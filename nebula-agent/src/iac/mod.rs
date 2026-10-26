#![allow(dead_code)]
// src/iac/mod.rs — Infrastructure-as-Code security scanner
//
// Scans: Terraform (.tf), Kubernetes YAML, Helm charts,
//        CloudFormation (.yaml/.json), Dockerfiles, Ansible playbooks
//
// Two approaches:
//   1. Native Rust checks — pattern/regex matching against known misconfigs.
//      Fast, no dependencies, covers the most common issues.
//   2. Tool delegation — if checkov, tfsec, kube-linter, or trivy config is
//      installed, delegate to them and parse their JSON output.
//      Richer coverage, slower, optional.
//
// All findings are structured as IaCFinding with MITRE mappings
// and actionable remediation steps.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────
// Finding types
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IaCFinding {
    pub file:        String,
    pub line:        Option<usize>,
    pub resource:    Option<String>,
    pub rule_id:     &'static str,
    pub title:       String,
    pub description: String,
    pub severity:    IaCSeverity,
    pub mitre_id:    Option<&'static str>,
    pub remediation: String,
    pub scanner:     String,  // "native" | "checkov" | "tfsec" | "trivy-config"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IaCSeverity { Critical, High, Medium, Low, Info }
impl IaCFinding {
    pub fn to_threat_event(&self) -> crate::types::ThreatEvent {
        let sev = match self.severity {
            IaCSeverity::Critical => crate::types::Severity::Critical,
            IaCSeverity::High     => crate::types::Severity::High,
            IaCSeverity::Medium   => crate::types::Severity::Medium,
            _                     => crate::types::Severity::Low,
        };
        crate::types::ThreatEvent {
            id:               uuid::Uuid::new_v4().to_string(),
            agent_id:         "".to_string(),
            hostname:         "".to_string(),
            timestamp:        chrono::Utc::now(),
            severity:         sev,
            confidence:       75.0,
            threat_name:      format!("IaC: {}", self.title),
            description:      format!("{}
File: {}
Line: {}
Remediation: {}",
                                self.description, self.file,
                                self.line.unwrap_or(0),
                                &self.remediation),
            mitre_tactics:    vec!["initial_access".to_string()],
            mitre_techniques: self.mitre_id.map(|t| vec![t.to_string()]).unwrap_or_else(|| vec!["T1190".to_string()]),
            matched_rules:    vec![format!("iac:{}", self.rule_id)],
            raw_event_ids:    vec![],
            chain:            None,
            iocs:             vec![],
            suggested_action: crate::types::ResponseAction::Alert,
            llm_analysis:     None,
            auto_generated_rule: None,
        }
    }
}


impl std::fmt::Display for IaCSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Self::Critical=>"CRITICAL", Self::High=>"HIGH",
            Self::Medium=>"MEDIUM", Self::Low=>"LOW", Self::Info=>"INFO" }
        .fmt(f)
    }
}

// ─────────────────────────────────────────────────────────────
// IaC scanner engine
// ─────────────────────────────────────────────────────────────

pub struct IaCScanner {
    /// Paths to scan (recursively walked)
    pub scan_paths: Vec<String>,
    /// Whether to invoke external tools (checkov, tfsec, etc.)
    pub use_external_tools: bool,
}

impl IaCScanner {
    pub fn new(paths: Vec<String>) -> Self {
        Self { scan_paths: paths, use_external_tools: true }
    }

    pub async fn scan_all(&self) -> Vec<IaCFinding> {
        let mut findings = vec![];

        for base in &self.scan_paths {
            let files = walk_iac_files(Path::new(base));
            for file in &files {
                let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
                let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let path_str = file.to_string_lossy().to_string();

                let Ok(content) = std::fs::read_to_string(file) else { continue };

                let file_findings = match (name, ext) {
                    ("Dockerfile" | "Containerfile", _) | (_, "") if name.starts_with("Dockerfile") => {
                        self.scan_dockerfile(&path_str, &content)
                    }
                    (_, "tf") => self.scan_terraform(&path_str, &content),
                    (_, "yaml" | "yml") => self.scan_yaml(&path_str, &content),
                    (_, "json") if content.contains("AWSTemplateFormatVersion") => {
                        self.scan_cloudformation(&path_str, &content)
                    }
                    _ => vec![],
                };

                findings.extend(file_findings);
            }
        }

        // External tools (richer coverage)
        if self.use_external_tools {
            for base in &self.scan_paths {
                if let Some(ext) = self.run_checkov(base).await { findings.extend(ext); }
                if let Some(ext) = self.run_tfsec(base).await   { findings.extend(ext); }
                if let Some(ext) = self.run_trivy_config(base).await { findings.extend(ext); }
                if let Some(ext) = self.run_kube_linter(base).await  { findings.extend(ext); }
            }
        }

        // Deduplicate by (file, rule_id, line)
        findings.sort_by(|a, b| a.file.cmp(&b.file).then(a.rule_id.cmp(b.rule_id)));
        findings.dedup_by(|a, b| a.file == b.file && a.rule_id == b.rule_id && a.line == b.line);

        if !findings.is_empty() {
            let critical = findings.iter().filter(|f| f.severity == IaCSeverity::Critical).count();
            let high     = findings.iter().filter(|f| f.severity == IaCSeverity::High).count();
            warn!("🏗️  IaC scan: {} findings ({} critical, {} high) across {} files",
                findings.len(), critical, high, self.scan_paths.len());
        }

        findings
    }

    // ── Dockerfile scanner ────────────────────────────────────
    fn scan_dockerfile(&self, path: &str, content: &str) -> Vec<IaCFinding> {
        let mut f = vec![];
        for (line_num, line) in content.lines().enumerate() {
            let line_n = line_num + 1;
            let l = line.trim().to_lowercase();

            // Running as root (no USER instruction → default root)
            // Check by looking for absence of USER at top level
            if l.starts_with("user ") {
                // good — they set a user
            }

            // Privilege escalation in RUN
            if l.starts_with("run ") {
                if l.contains("--privileged") || l.contains("sudo ") || l.contains("chmod 777") {
                    f.push(finding(path, line_n, "DF001", "Privileged operation in Dockerfile RUN",
                        "sudo or chmod 777 in RUN layer creates privilege escalation risks in container",
                        IaCSeverity::High, Some("T1610"),
                        "Remove sudo. Build with appropriate user. Avoid chmod 777."));
                }

                // Curl/wget piped to shell (supply chain risk)
                if (l.contains("curl ") || l.contains("wget ")) &&
                   (l.contains("| sh") || l.contains("| bash") || l.contains("| python"))
                {
                    f.push(finding(path, line_n, "DF002", "curl|bash pattern in Dockerfile",
                        "Downloading and executing scripts without verification — supply chain attack risk",
                        IaCSeverity::High, Some("T1195"),
                        "Download the script, verify its checksum, then execute."));
                }

                // Package manager leaving cache
                if (l.contains("apt-get install") || l.contains("yum install") || l.contains("apk add")) &&
                   !l.contains("--no-cache") && !l.contains("rm -rf /var/cache")
                {
                    f.push(finding(path, line_n, "DF003", "Package cache not cleaned in Dockerfile",
                        "Package manager cache left in image increases attack surface and image size",
                        IaCSeverity::Low, None,
                        "Use apt-get install --no-cache or add rm -rf /var/lib/apt/lists/* in the same RUN layer."));
                }
            }

            // ADD instead of COPY (ADD can fetch remote URLs, extract tarballs)
            if l.starts_with("add ") && (l.contains("http://") || l.contains("https://")) {
                f.push(finding(path, line_n, "DF004", "ADD with remote URL in Dockerfile",
                    "ADD with URL downloads at build time without integrity verification",
                    IaCSeverity::Medium, Some("T1195"),
                    "Use COPY + explicit curl with checksum verification."));
            }

            // Secrets in ENV
            let secret_re = Regex::new(r"(?i)env\s+(password|secret|token|api_key|private_key)\s*=").unwrap();
            if secret_re.is_match(line) {
                f.push(finding(path, line_n, "DF005", "Secret in Dockerfile ENV",
                    "Hardcoded secret in ENV is visible in docker inspect and image layers",
                    IaCSeverity::Critical, Some("T1552"),
                    "Use Docker secrets (--secret) or build-time ARG + runtime env injection."));
            }

            // Latest tag
            if l.starts_with("from ") && l.ends_with(":latest") {
                f.push(finding(path, line_n, "DF006", "FROM uses :latest tag",
                    "Unpinned image can introduce vulnerabilities on rebuild",
                    IaCSeverity::Low, None,
                    "Pin to a specific version digest: FROM ubuntu@sha256:..."));
            }

            // Running SSH daemon inside container
            if l.contains("openssh-server") || l.contains("sshd") {
                f.push(finding(path, line_n, "DF007", "SSH daemon in container image",
                    "Running sshd inside containers is an anti-pattern — use 'docker exec' or kubectl exec instead",
                    IaCSeverity::Medium, None,
                    "Remove OpenSSH server. Use docker exec / kubectl exec for debugging."));
            }
        }

        // Check for missing USER instruction
        if !content.to_lowercase().contains("\nuser ") && !content.to_lowercase().starts_with("user ") {
            f.push(finding(path, 0, "DF008", "No USER instruction — container runs as root",
                "Without USER, the container process runs as root (uid=0), which is a security risk",
                IaCSeverity::High, Some("T1610"),
                "Add 'USER nonroot' or 'USER 1000' before the last CMD/ENTRYPOINT."));
        }

        f
    }

    // ── Terraform scanner ─────────────────────────────────────
    fn scan_terraform(&self, path: &str, content: &str) -> Vec<IaCFinding> {
        let mut f = vec![];
        let lines: Vec<&str> = content.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let l = line.trim().to_lowercase();
            let n = i + 1;

            // AWS S3 bucket public access
            if l.contains("acl") && (l.contains("public-read") || l.contains("public-read-write")) {
                f.push(finding(path, n, "TF001", "S3 bucket with public ACL",
                    "Terraform resource configures S3 bucket with public read or write access",
                    IaCSeverity::Critical, Some("T1530"),
                    "Set acl = \"private\". Use bucket policies for controlled access."));
            }

            // Security group 0.0.0.0/0 ingress
            if (l.contains("cidr_blocks") || l.contains("ipv6_cidr_blocks")) &&
               (l.contains("0.0.0.0/0") || l.contains("::/0"))
            {
                // Check if this is ingress (port 22, 3389, 3306 are especially bad)
                let context = lines[i.saturating_sub(5)..i.min(lines.len())].join(" ").to_lowercase();
                let dangerous_port = context.contains("22") || context.contains("3389") ||
                    context.contains("3306") || context.contains("5432") || context.contains("6379");

                let sev = if dangerous_port { IaCSeverity::Critical } else { IaCSeverity::High };
                f.push(finding(path, n, "TF002",
                    "Security group allows unrestricted inbound access (0.0.0.0/0)",
                    "Terraform security group rule permits traffic from the entire internet",
                    sev, Some("T1190"),
                    "Restrict CIDR to specific IP ranges. Never expose databases or SSH to 0.0.0.0/0."));
            }

            // Unencrypted EBS/RDS
            if (l.contains("encrypted") || l.contains("storage_encrypted")) && l.contains("false") {
                f.push(finding(path, n, "TF003", "Unencrypted storage resource",
                    "Terraform resource has encryption disabled (encrypted = false)",
                    IaCSeverity::High, Some("T1530"),
                    "Set encrypted = true. For RDS: storage_encrypted = true. Use KMS CMK for key management."));
            }

            // IAM * policy
            if l.contains("\"*\"") && (content[..content.len().min(i*80)].to_lowercase().contains("iam") ||
               content[..content.len().min(i*80)].to_lowercase().contains("policy"))
            {
                if lines[i.saturating_sub(3)..i].iter().any(|l| l.contains("Action") || l.contains("Resource")) {
                    f.push(finding(path, n, "TF004", "IAM policy with wildcard (*) permissions",
                        "IAM policy grants all actions or all resources — violates least privilege",
                        IaCSeverity::Critical, Some("T1078"),
                        "Scope IAM policies to specific actions and resource ARNs."));
                }
            }

            // Hardcoded credentials
            let cred_re = Regex::new(
                r#"(?i)(password|secret|token|api_key|access_key)\s*=\s*"[^"${}]{8,}""#
            ).unwrap();
            if cred_re.is_match(line) && !line.contains("var.") && !line.contains("data.") {
                f.push(finding(path, n, "TF005", "Hardcoded credential in Terraform",
                    "Literal credential value found in Terraform resource — will be stored in state file",
                    IaCSeverity::Critical, Some("T1552"),
                    "Use var.* references or data sources (AWS SSM Parameter Store, HashiCorp Vault)."));
            }

            // CloudTrail disabled
            if l.contains("enable_log_file_validation") && l.contains("false") {
                f.push(finding(path, n, "TF006", "CloudTrail log validation disabled",
                    "CloudTrail log file validation disabled — logs can be tampered with undetected",
                    IaCSeverity::Medium, Some("T1070"),
                    "Set enable_log_file_validation = true."));
            }

            // VPC flow logs disabled
            if l.contains("aws_vpc") && !content.contains("aws_flow_log") {
                // Only flag once per file
                if i < 5 {
                    f.push(finding(path, n, "TF007", "VPC without flow logs",
                        "No aws_flow_log resource found for this VPC — network traffic not logged",
                        IaCSeverity::Medium, Some("T1071"),
                        "Add aws_flow_log resource to capture VPC traffic for security monitoring."));
                }
            }

            // Terraform state stored unencrypted (S3 backend without encryption)
            if l.contains("backend") && l.contains("s3") {
                let backend_block = lines[i..i.min(i+15)].join("\n").to_lowercase();
                if !backend_block.contains("encrypt") || backend_block.contains("encrypt = false") {
                    f.push(finding(path, n, "TF008", "Terraform S3 backend without encryption",
                        "Terraform state file in S3 without server-side encryption — state contains secrets",
                        IaCSeverity::High, Some("T1530"),
                        "Add encrypt = true to S3 backend configuration."));
                }
            }
        }

        f
    }

    // ── Kubernetes YAML scanner ───────────────────────────────
    fn scan_yaml(&self, path: &str, content: &str) -> Vec<IaCFinding> {
        let mut f = vec![];
        let lines: Vec<&str> = content.lines().collect();

        // Only scan Kubernetes-style YAML
        if !content.contains("apiVersion:") && !content.contains("kind:") {
            return f;
        }

        for (i, line) in lines.iter().enumerate() {
            let l = line.trim();
            let n = i + 1;
            let lower = l.to_lowercase();

            if lower.contains("privileged: true") {
                f.push(finding(path, n, "K8S001", "Privileged container in Kubernetes manifest",
                    "Pod spec sets privileged: true — container has full host access",
                    IaCSeverity::Critical, Some("T1610"),
                    "Set privileged: false. Use specific capabilities instead."));
            }

            if lower.contains("hostpid: true") {
                f.push(finding(path, n, "K8S002", "hostPID: true in Kubernetes manifest",
                    "Pod shares host PID namespace — can signal and inspect all host processes",
                    IaCSeverity::Critical, Some("T1611"),
                    "Remove hostPID: true."));
            }

            if lower.contains("hostnetwork: true") {
                f.push(finding(path, n, "K8S003", "hostNetwork: true in Kubernetes manifest",
                    "Pod uses host network namespace — bypasses NetworkPolicy controls",
                    IaCSeverity::High, Some("T1610"),
                    "Remove hostNetwork: true."));
            }

            if lower.contains("allowprivilegeescalation: true") {
                f.push(finding(path, n, "K8S004", "allowPrivilegeEscalation: true",
                    "Container allowed to gain more privileges via setuid binaries",
                    IaCSeverity::High, Some("T1548"),
                    "Set allowPrivilegeEscalation: false."));
            }

            if lower.contains("runasuser: 0") || lower.contains("runasroot: true") {
                f.push(finding(path, n, "K8S005", "Container configured to run as root (uid=0)",
                    "Container runs as root user — increases blast radius of compromise",
                    IaCSeverity::High, Some("T1610"),
                    "Set runAsUser: 1000 (or higher) and runAsNonRoot: true."));
            }

            // Secret exposed as env var
            if lower.contains("secretkeyref") && !lower.contains("#") {
                // This is actually OK! Using secretKeyRef is the correct pattern.
                // We only flag literal values.
            }
            if lower.starts_with("- name:") || lower.starts_with("name:") {
                let ctx = lines[i..i.min(i+3)].join("\n").to_lowercase();
                let secret_keys = ["password", "secret", "token", "api_key", "private_key"];
                if secret_keys.iter().any(|k| lower.contains(k)) {
                    if ctx.contains("value:") && !ctx.contains("valuefrom") {
                        f.push(finding(path, n, "K8S006", "Literal secret value in Kubernetes YAML",
                            "Hardcoded credential in env.value — should use secretKeyRef",
                            IaCSeverity::Critical, Some("T1552"),
                            "Use env.valueFrom.secretKeyRef to reference a Kubernetes Secret."));
                    }
                }
            }

            // ReadWriteMany PVC (can be multi-tenant data exposure)
            if lower.contains("readwritemany") {
                f.push(finding(path, n, "K8S007", "PVC with ReadWriteMany access mode",
                    "ReadWriteMany allows multiple pods to write — potential for cross-tenant data access",
                    IaCSeverity::Medium, None,
                    "Use ReadWriteOnce unless shared storage is explicitly required."));
            }

            // Default service account
            if lower.contains("serviceaccountname: default") {
                f.push(finding(path, n, "K8S008", "Pod uses default service account",
                    "Default service account often has broader permissions than needed — use a dedicated SA",
                    IaCSeverity::Medium, Some("T1552.007"),
                    "Create a dedicated ServiceAccount with minimal RBAC permissions."));
            }

            // Image pull policy Latest
            if lower.contains("imagepullpolicy: never") || lower.contains(":latest") {
                f.push(finding(path, n, "K8S009", "Container image uses :latest tag",
                    "Unpinned :latest tag means any image rebuild may introduce vulnerabilities",
                    IaCSeverity::Low, None,
                    "Pin to a specific image digest: image: nginx@sha256:..."));
            }

            // Missing resource limits
            if lower.contains("containers:") {
                let block = lines[i..i.min(i+30)].join("\n").to_lowercase();
                if !block.contains("resources:") || !block.contains("limits:") {
                    f.push(finding(path, n, "K8S010", "Container missing resource limits",
                        "No CPU/memory limits — container can exhaust node resources (DoS)",
                        IaCSeverity::Medium, None,
                        "Add resources.limits.cpu and resources.limits.memory to each container."));
                }
            }
        }

        f
    }

    // ── CloudFormation scanner ────────────────────────────────
    fn scan_cloudformation(&self, path: &str, content: &str) -> Vec<IaCFinding> {
        let mut f = vec![];
        let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else { return f };

        let Some(resources) = json["Resources"].as_object() else { return f };

        for (name, resource) in resources {
            let rtype = resource["Type"].as_str().unwrap_or("");
            let props = &resource["Properties"];

            // S3 public access
            if rtype == "AWS::S3::Bucket" {
                let pac = &props["PublicAccessBlockConfiguration"];
                if pac.is_null() || pac["BlockPublicAcls"].as_bool() == Some(false) {
                    f.push(finding(path, 0, "CFN001",
                        &format!("S3 bucket '{}' missing PublicAccessBlockConfiguration", name),
                        "S3 bucket may be publicly accessible without explicit block config",
                        IaCSeverity::High, Some("T1530"),
                        "Add PublicAccessBlockConfiguration with all four options set to true."));
                }
            }

            // RDS unencrypted
            if rtype == "AWS::RDS::DBInstance" {
                if props["StorageEncrypted"].as_bool() != Some(true) {
                    f.push(finding(path, 0, "CFN002",
                        &format!("RDS instance '{}' storage not encrypted", name),
                        "RDS database storage is unencrypted at rest",
                        IaCSeverity::High, Some("T1530"),
                        "Set StorageEncrypted: true and specify a KmsKeyId."));
                }
            }

            // EC2 unrestricted security group
            if rtype == "AWS::EC2::SecurityGroup" {
                if let Some(rules) = props["SecurityGroupIngress"].as_array() {
                    for rule in rules {
                        let cidr = rule["CidrIp"].as_str().unwrap_or("");
                        let port = rule["FromPort"].as_i64().unwrap_or(0);
                        if cidr == "0.0.0.0/0" && [22i64, 3389, 3306, 5432].contains(&port) {
                            f.push(finding(path, 0, "CFN003",
                                &format!("Security group '{}' opens port {} to 0.0.0.0/0", name, port),
                                "Unrestricted inbound access to sensitive port",
                                IaCSeverity::Critical, Some("T1190"),
                                "Restrict CidrIp to specific IP ranges. Never expose databases or SSH to the internet."));
                        }
                    }
                }
            }
        }
        f
    }

    // ── External tool: Checkov ────────────────────────────────
    async fn run_checkov(&self, path: &str) -> Option<Vec<IaCFinding>> {
        let out = tokio::process::Command::new("checkov")
            .args(["-d", path, "-o", "json", "--quiet"])
            .output().await.ok()?;

        if !out.status.success() && out.stdout.is_empty() { return None; }

        let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let mut findings = vec![];

        let failed = json["results"]["failed_checks"].as_array()?;
        for check in failed {
            let sev = match check["severity"].as_str().unwrap_or("MEDIUM") {
                "CRITICAL" => IaCSeverity::Critical,
                "HIGH"     => IaCSeverity::High,
                "LOW"      => IaCSeverity::Low,
                _          => IaCSeverity::Medium,
            };
            findings.push(IaCFinding {
                file:        check["repo_file_path"].as_str().unwrap_or(path).to_string(),
                line:        check["file_line_range"].as_array().and_then(|a| a.first()).and_then(|v| v.as_u64()).map(|n| n as usize),
                resource:    check["resource"].as_str().map(String::from),
                rule_id:     "CHECKOV",
                title:       check["check_id"].as_str().unwrap_or("").to_string(),
                description: check["check_result"]["result"].as_str().unwrap_or("").to_string(),
                severity:    sev,
                mitre_id:    None,
                remediation: check["guideline"].as_str().unwrap_or("See Checkov documentation.").to_string(),
                scanner:     "checkov".to_string(),
            });
        }

        if !findings.is_empty() {
            info!("🏗️  Checkov: {} findings in {}", findings.len(), path);
        }
        Some(findings)
    }

    // ── External tool: tfsec ──────────────────────────────────
    async fn run_tfsec(&self, path: &str) -> Option<Vec<IaCFinding>> {
        // Only run on directories containing .tf files
        if !has_tf_files(path) { return None; }

        let out = tokio::process::Command::new("tfsec")
            .args([path, "--format", "json", "--no-color"])
            .output().await.ok()?;

        let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let mut findings = vec![];

        for result in json["results"].as_array()? {
            let sev = match result["severity"].as_str().unwrap_or("MEDIUM") {
                "CRITICAL" => IaCSeverity::Critical,
                "HIGH"     => IaCSeverity::High,
                "LOW"      => IaCSeverity::Low,
                _          => IaCSeverity::Medium,
            };
            findings.push(IaCFinding {
                file:        result["location"]["filename"].as_str().unwrap_or(path).to_string(),
                line:        result["location"]["start_line"].as_u64().map(|n| n as usize),
                resource:    result["resource"].as_str().map(String::from),
                rule_id:     "TFSEC",
                title:       result["rule"]["summary"].as_str().unwrap_or("").to_string(),
                description: result["description"].as_str().unwrap_or("").to_string(),
                severity:    sev,
                mitre_id:    None,
                remediation: result["rule"]["resolution"].as_str().unwrap_or("").to_string(),
                scanner:     "tfsec".to_string(),
            });
        }

        Some(findings)
    }

    // ── External tool: trivy config ───────────────────────────
    async fn run_trivy_config(&self, path: &str) -> Option<Vec<IaCFinding>> {
        let out = tokio::process::Command::new("trivy")
            .args(["config", "--format", "json", "--quiet", path])
            .output().await.ok()?;

        let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let mut findings = vec![];

        if let Some(results) = json["Results"].as_array() {
            for result in results {
                if let Some(misconfigs) = result["Misconfigurations"].as_array() {
                    for m in misconfigs {
                        let sev = match m["Severity"].as_str().unwrap_or("MEDIUM") {
                            "CRITICAL" => IaCSeverity::Critical,
                            "HIGH"     => IaCSeverity::High,
                            "LOW"      => IaCSeverity::Low,
                            _          => IaCSeverity::Medium,
                        };
                        findings.push(IaCFinding {
                            file:        result["Target"].as_str().unwrap_or(path).to_string(),
                            line:        None,
                            resource:    None,
                            rule_id:     "TRIVY-CONFIG",
                            title:       m["Title"].as_str().unwrap_or("").to_string(),
                            description: m["Description"].as_str().unwrap_or("").to_string(),
                            severity:    sev,
                            mitre_id:    None,
                            remediation: m["Resolution"].as_str().unwrap_or("").to_string(),
                            scanner:     "trivy-config".to_string(),
                        });
                    }
                }
            }
        }

        Some(findings)
    }

    // ── External tool: kube-linter ────────────────────────────
    async fn run_kube_linter(&self, path: &str) -> Option<Vec<IaCFinding>> {
        let out = tokio::process::Command::new("kube-linter")
            .args(["lint", path, "--format", "json"])
            .output().await.ok()?;

        let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let mut findings = vec![];

        for report in json["Reports"].as_array().unwrap_or(&vec![]) {
            findings.push(IaCFinding {
                file:        path.to_string(),
                line:        None,
                resource:    report["Object"]["K8sObject"]["Name"].as_str().map(String::from),
                rule_id:     "KUBELINTER",
                title:       report["Check"].as_str().unwrap_or("").to_string(),
                description: report["Diagnostic"]["Message"].as_str().unwrap_or("").to_string(),
                severity:    IaCSeverity::Medium,
                mitre_id:    None,
                remediation: "See kube-linter documentation for this check.".to_string(),
                scanner:     "kube-linter".to_string(),
            });
        }

        Some(findings)
    }
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

fn finding(
    path: &str, line: usize, rule_id: &'static str,
    title: &str, description: &str, severity: IaCSeverity,
    mitre_id: Option<&'static str>, remediation: &str,
) -> IaCFinding {
    IaCFinding {
        file:        path.to_string(),
        line:        if line == 0 { None } else { Some(line) },
        resource:    None,
        rule_id,
        title:       title.to_string(),
        description: description.to_string(),
        severity,
        mitre_id,
        remediation: remediation.to_string(),
        scanner:     "native".to_string(),
    }
}

fn walk_iac_files(base: &Path) -> Vec<PathBuf> {
    let mut files = vec![];
    let Ok(entries) = std::fs::read_dir(base) else { return files };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip dependency dirs
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !matches!(name, ".git" | "node_modules" | ".terraform" | "vendor" | "__pycache__") {
                files.extend(walk_iac_files(&path));
            }
        } else {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let ext  = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let is_iac = matches!(ext, "tf" | "yaml" | "yml" | "json") ||
                name.starts_with("Dockerfile") ||
                name == "Containerfile";
            if is_iac { files.push(path); }
        }
    }
    files
}

fn has_tf_files(path: &str) -> bool {
    std::fs::read_dir(path)
        .map(|entries| entries.flatten().any(|e| {
            e.path().extension().and_then(|x| x.to_str()) == Some("tf")
        }))
        .unwrap_or(false)
}
