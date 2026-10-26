#![allow(dead_code)]
// src/container/mod.rs — Container & Kubernetes security engine
//
// How container protection works in NebulaSentinel:
//
// Layer 1 — Image scanning (before runtime)
//   Scans Docker/OCI images for known CVEs using Trivy or Grype.
//   Checks base image, installed packages, and application libraries.
//   Runs on: docker pull, docker build, kubernetes pod scheduling.
//
// Layer 2 — Runtime behavioral monitoring
//   Watches the Docker/containerd/CRI-O API for container lifecycle events.
//   Detects: privileged containers, dangerous capabilities, host path mounts,
//   hostPID/hostNetwork mode, unexpected process spawns inside containers.
//
// Layer 3 — Namespace isolation verification
//   Checks that container namespaces (pid, net, mnt, user) are properly
//   isolated. Detects shared-namespace containers (T1611 escape vectors).
//
// Layer 4 — Kubernetes admission posture
//   If kubectl/k8s API is reachable: checks pod security standards,
//   RBAC misconfigurations, privileged service accounts, exposed dashboards.
//
// Layer 5 — Drift detection
//   Compares running container against its image manifest. Any binary,
//   library, or config file written at runtime is flagged (T1525).
//   Legitimate containers are immutable; writes = compromise.
//
// MITRE coverage:
//   T1610 — Deploy Container (malicious privileged container)
//   T1611 — Escape to Host (nsenter, /proc/1, chroot /host)
//   T1525 — Implant Internal Image (modified container image)
//   T1543 — Container as persistence mechanism
//   T1552.007 — Container API secrets exposure
//   T1613 — Container and Resource Discovery

use crate::types::{ThreatEvent, Severity, IOC, IOCType, ResponseAction};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn, debug};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────
// Container runtime info
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRuntime {
    pub id:           String,
    pub name:         String,
    pub image:        String,
    pub image_id:     String,
    pub status:       String,
    pub pid:          Option<u32>,
    pub privileged:   bool,
    pub capabilities: Vec<String>,
    pub mounts:       Vec<MountInfo>,
    pub network_mode: String,
    pub pid_mode:     String,
    pub user:         String,
    pub env_vars:     Vec<String>,  // sanitized — no values, just key names
    pub labels:       HashMap<String, String>,
    pub created_at:   String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    pub source:      String,
    pub destination: String,
    pub mode:        String,
    pub dangerous:   bool,  // true if host-sensitive path
}

// ─────────────────────────────────────────────────────────────
// Image vulnerability finding
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageVulnerability {
    pub image:        String,
    pub cve:          String,
    pub package:      String,
    pub version:      String,
    pub fixed_version: Option<String>,
    pub severity:     String,
    pub cvss:         f32,
    pub layer:        Option<String>,  // which Dockerfile layer introduced it
    pub scanner:      String,          // "trivy" | "grype"
}

// ─────────────────────────────────────────────────────────────
// Container security finding
// ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerFinding {
    pub container_id:  String,
    pub container_name: String,
    pub image:         String,
    pub finding_type:  ContainerFindingType,
    pub severity:      Severity,
    pub description:   String,
    pub mitre_id:      &'static str,
    pub remediation:   String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerFindingType {
    PrivilegedContainer,
    DangerousCapability,
    HostPathMount,
    HostNetworkMode,
    HostPidMode,
    RootUser,
    WritableRootFs,
    SecretInEnv,
    EscapeAttempt,
    DriftDetected,
    VulnerableImage,
    ExposedDockerSocket,
    PrivilegedServiceAccount,
    RbacMisconfiguration,
}

// ─────────────────────────────────────────────────────────────
// Container engine
// ─────────────────────────────────────────────────────────────

pub struct ContainerEngine {
    // Docker socket path
    docker_socket:    String,
    // containerd socket path
    containerd_socket: String,
    // Whether to scan images with Trivy/Grype
    image_scan:        bool,
    // Track container state for drift detection
    // key: container_id, value: map of path → sha256
    baseline:          std::sync::Arc<tokio::sync::Mutex<HashMap<String, HashMap<String, String>>>>,
}

impl ContainerEngine {
    pub fn new() -> Self {
        Self {
            docker_socket:     "/var/run/docker.sock".to_string(),
            containerd_socket: "/run/containerd/containerd.sock".to_string(),
            image_scan:        true,
            baseline:          std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub fn is_available(&self) -> bool {
        Path::new(&self.docker_socket).exists()
            || Path::new(&self.containerd_socket).exists()
            || Path::new("/run/crio/crio.sock").exists()
    }

    // ── Full container security assessment ────────────────────
    pub async fn assess(&self) -> Vec<ContainerFinding> {
        let mut findings = vec![];

        // 1. List running containers and inspect each
        let containers = self.list_containers().await;
        for c in &containers {
            findings.extend(self.inspect_runtime_config(c));
        }

        // 1b. Runtime filesystem drift — files written since the image was built
        // (possible implant / tampering, T1525). Uses `docker diff`. This wires
        // up `detect_drift`, which was previously implemented but never called.
        for c in &containers {
            let drifted = self.detect_drift(&c.id).await;
            if !drifted.is_empty() {
                let sample: Vec<String> = drifted.iter().take(10).cloned().collect();
                findings.push(ContainerFinding {
                    container_id:   c.id.clone(),
                    container_name: c.name.clone(),
                    image:          c.image.clone(),
                    finding_type:   ContainerFindingType::DriftDetected,
                    severity:       Severity::Medium,
                    description:    format!(
                        "{} runtime-written file(s) not present in the image (possible \
                         implant or tampering). Sample: {}",
                        drifted.len(), sample.join(", ")),
                    mitre_id:       "T1525",
                    remediation:    "Investigate the runtime-written files; redeploy from a \
                                     trusted image; consider a read-only root filesystem.".to_string(),
                });
            }
        }

        // 2. Check exposed Docker socket
        #[cfg(unix)]
        if Path::new(&self.docker_socket).exists() {
            if let Ok(meta) = std::fs::metadata(&self.docker_socket) {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode();
                if mode & 0o007 != 0 {
                    findings.push(ContainerFinding {
                        container_id: "host".to_string(),
                        container_name: "host".to_string(),
                        image: "N/A".to_string(),
                        finding_type: ContainerFindingType::ExposedDockerSocket,
                        severity: Severity::Critical,
                        description: format!(
                            "Docker socket {} is world-readable/writable (mode {:o}). \
                             Any process can control Docker → full host compromise.",
                            self.docker_socket, mode & 0o777
                        ),
                        mitre_id: "T1552.007",
                        remediation: "chmod 660 /var/run/docker.sock && chown root:docker /var/run/docker.sock".to_string(),
                    });
                }
            }
        }

        // 3. Check for docker.sock mounted inside containers (container-in-container escape)
        for c in &containers {
            if c.mounts.iter().any(|m| m.source.contains("docker.sock")) {
                findings.push(ContainerFinding {
                    container_id:   c.id.clone(),
                    container_name: c.name.clone(),
                    image:          c.image.clone(),
                    finding_type:   ContainerFindingType::ExposedDockerSocket,
                    severity:       Severity::Critical,
                    description:    format!(
                        "Container {} has Docker socket mounted inside. \
                         This allows full host takeover via the Docker API (T1611).",
                        c.name
                    ),
                    mitre_id:    "T1611",
                    remediation: "Remove the docker.sock volume mount. Use a sidecar proxy if Docker API access is needed.".to_string(),
                });
            }
        }

        // 4. Kubernetes posture check
        if self.kubectl_available().await {
            findings.extend(self.check_kubernetes_posture().await);
        }

        if !findings.is_empty() {
            warn!("🐳 Container assessment: {} findings", findings.len());
        }
        findings
    }

    // ── Inspect container runtime configuration ───────────────
    fn inspect_runtime_config(&self, c: &ContainerRuntime) -> Vec<ContainerFinding> {
        let mut f = vec![];

        // Privileged mode — full host capabilities, all devices accessible
        if c.privileged {
            f.push(ContainerFinding {
                container_id:   c.id.clone(),
                container_name: c.name.clone(),
                image:          c.image.clone(),
                finding_type:   ContainerFindingType::PrivilegedContainer,
                severity:       Severity::Critical,
                description:    format!(
                    "Container '{}' is running in privileged mode. \
                     Has full access to all host devices and capabilities — trivial escape to host.",
                    c.name
                ),
                mitre_id:    "T1610",
                remediation: "Remove --privileged flag. Use specific capabilities with --cap-add instead.".to_string(),
            });
        }

        // Dangerous capabilities
        let dangerous_caps = ["SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN",
            "SYS_RAWIO", "SYS_BOOT", "SYS_TIME", "SYS_NICE", "AUDIT_CONTROL",
            "SETUID", "SETGID", "DAC_OVERRIDE", "SYS_CHROOT"];
        for cap in &c.capabilities {
            if dangerous_caps.contains(&cap.as_str()) {
                let severity = match cap.as_str() {
                    "SYS_ADMIN" | "SYS_PTRACE" | "SYS_MODULE" => Severity::Critical,
                    "NET_ADMIN" | "SYS_RAWIO"                  => Severity::High,
                    _                                           => Severity::Medium,
                };
                f.push(ContainerFinding {
                    container_id:   c.id.clone(),
                    container_name: c.name.clone(),
                    image:          c.image.clone(),
                    finding_type:   ContainerFindingType::DangerousCapability,
                    severity,
                    description:    format!(
                        "Container '{}' has dangerous capability: {}. \
                         This can be used for privilege escalation or host escape.",
                        c.name, cap
                    ),
                    mitre_id:    "T1611",
                    remediation: format!("Remove --cap-add {} unless strictly required. Apply principle of least privilege.", cap),
                });
            }
        }

        // Sensitive host path mounts
        let sensitive_paths = [
            ("/", "Root filesystem"),
            ("/etc", "System configuration"),
            ("/var/run", "Runtime sockets"),
            ("/proc", "Process filesystem"),
            ("/sys", "Kernel interfaces"),
            ("/boot", "Boot loader"),
            ("/lib/modules", "Kernel modules"),
            ("/usr", "System binaries"),
            ("/home", "User home directories"),
            ("/root", "Root home directory"),
            ("/var/lib/kubelet", "Kubernetes node agent data"),
            ("/etc/kubernetes", "Kubernetes configuration"),
            ("/run/secrets/kubernetes.io", "Kubernetes service account"),
        ];

        for mount in &c.mounts {
            for (sensitive, desc) in &sensitive_paths {
                if mount.source.starts_with(sensitive) {
                    let severity = match *sensitive {
                        "/" | "/proc" | "/sys" | "/etc/kubernetes" => Severity::Critical,
                        "/etc" | "/var/run" | "/lib/modules"       => Severity::High,
                        _                                           => Severity::Medium,
                    };
                    f.push(ContainerFinding {
                        container_id:   c.id.clone(),
                        container_name: c.name.clone(),
                        image:          c.image.clone(),
                        finding_type:   ContainerFindingType::HostPathMount,
                        severity,
                        description:    format!(
                            "Container '{}' mounts host path {} ({}) → container path {}. \
                             Host filesystem access enables escape/persistence.",
                            c.name, mount.source, desc, mount.destination
                        ),
                        mitre_id:    "T1611",
                        remediation: format!("Remove hostPath mount of {}. Use ConfigMaps/Secrets for configuration.", mount.source),
                    });
                    break;
                }
            }
        }

        // Host network mode — bypasses network namespace isolation
        if c.network_mode == "host" {
            f.push(ContainerFinding {
                container_id:   c.id.clone(),
                container_name: c.name.clone(),
                image:          c.image.clone(),
                finding_type:   ContainerFindingType::HostNetworkMode,
                severity:       Severity::High,
                description:    format!(
                    "Container '{}' uses host network mode. \
                     Container can see and interact with all host network interfaces and ports.",
                    c.name
                ),
                mitre_id:    "T1610",
                remediation: "Remove --network=host. Expose specific ports with -p instead.".to_string(),
            });
        }

        // Host PID namespace — can see and signal all host processes
        if c.pid_mode == "host" {
            f.push(ContainerFinding {
                container_id:   c.id.clone(),
                container_name: c.name.clone(),
                image:          c.image.clone(),
                finding_type:   ContainerFindingType::HostPidMode,
                severity:       Severity::Critical,
                description:    format!(
                    "Container '{}' shares the host PID namespace. \
                     Can see all host processes and send signals to them (T1611 trivial escape).",
                    c.name
                ),
                mitre_id:    "T1611",
                remediation: "Remove --pid=host unless required for specific monitoring use cases.".to_string(),
            });
        }

        // Running as root
        if c.user.is_empty() || c.user == "0" || c.user == "root" {
            f.push(ContainerFinding {
                container_id:   c.id.clone(),
                container_name: c.name.clone(),
                image:          c.image.clone(),
                finding_type:   ContainerFindingType::RootUser,
                severity:       Severity::Medium,
                description:    format!(
                    "Container '{}' runs as root (uid=0). \
                     If compromised, attacker has root inside container — easier to escalate.",
                    c.name
                ),
                mitre_id:    "T1610",
                remediation: "Add USER nonroot in Dockerfile. Set runAsNonRoot: true in Kubernetes securityContext.".to_string(),
            });
        }

        // Secrets in environment variables
        let secret_patterns = ["password", "secret", "token", "key", "credential",
            "api_key", "private_key", "auth", "passwd", "pwd"];
        for env_key in &c.env_vars {
            let lower = env_key.to_lowercase();
            if secret_patterns.iter().any(|p| lower.contains(p)) {
                f.push(ContainerFinding {
                    container_id:   c.id.clone(),
                    container_name: c.name.clone(),
                    image:          c.image.clone(),
                    finding_type:   ContainerFindingType::SecretInEnv,
                    severity:       Severity::High,
                    description:    format!(
                        "Container '{}' has potential secret in environment variable: {}. \
                         Environment variables are visible via 'docker inspect' and /proc/{}/environ.",
                        c.name, env_key, c.pid.unwrap_or(0)
                    ),
                    mitre_id:    "T1552.007",
                    remediation: "Use Docker secrets or Kubernetes Secrets mounted as files instead of env vars.".to_string(),
                });
            }
        }

        f
    }

    // ── List containers via Docker CLI ────────────────────────
    // Real production impl: use bollard crate (Docker API over Unix socket)
    async fn list_containers(&self) -> Vec<ContainerRuntime> {
        let mut containers = vec![];

        if let Ok(out) = tokio::process::Command::new("docker")
            .args(["ps", "--no-trunc", "--format",
                "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}"])
            .output().await
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let parts: Vec<&str> = line.splitn(4, '\t').collect();
                if parts.len() < 4 { continue; }

                let id   = parts[0].to_string();
                let name = parts[1].to_string();

                // Inspect this container for security-relevant config
                let runtime = self.inspect_container(&id, &name, parts[2], parts[3]).await;
                containers.push(runtime);
            }
        }

        // Also check containerd via crictl if available
        if Path::new("/run/containerd/containerd.sock").exists() {
            if let Ok(out) = tokio::process::Command::new("crictl")
                .args(["ps", "--output", "json"])
                .output().await
            {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                    if let Some(items) = json["containers"].as_array() {
                        for item in items {
                            let id = item["id"].as_str().unwrap_or("").to_string();
                            let name = item["metadata"]["name"].as_str().unwrap_or("").to_string();
                            let image = item["image"]["image"].as_str().unwrap_or("").to_string();
                            // crictl inspect for full details
                            containers.push(self.inspect_container(&id, &name, &image, "running").await);
                        }
                    }
                }
            }
        }

        containers
    }

    async fn inspect_container(&self, id: &str, name: &str, image: &str, status: &str) -> ContainerRuntime {
        let mut runtime = ContainerRuntime {
            id: id.to_string(),
            name: name.to_string(),
            image: image.to_string(),
            image_id: String::new(),
            status: status.to_string(),
            pid: None,
            privileged: false,
            capabilities: vec![],
            mounts: vec![],
            network_mode: "bridge".to_string(),
            pid_mode: String::new(),
            user: String::new(),
            env_vars: vec![],
            labels: HashMap::new(),
            created_at: String::new(),
        };

        // Docker inspect for full config
        if let Ok(out) = tokio::process::Command::new("docker")
            .args(["inspect", "--format", "{{json .}}", id])
            .output().await
        {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                let first = if json.is_array() { &json[0] } else { &json };

                runtime.pid          = first["State"]["Pid"].as_u64().map(|p| p as u32);
                runtime.privileged   = first["HostConfig"]["Privileged"].as_bool().unwrap_or(false);
                runtime.network_mode = first["HostConfig"]["NetworkMode"].as_str().unwrap_or("bridge").to_string();
                runtime.pid_mode     = first["HostConfig"]["PidMode"].as_str().unwrap_or("").to_string();
                runtime.user         = first["Config"]["User"].as_str().unwrap_or("").to_string();

                // Capabilities
                if let Some(caps) = first["HostConfig"]["CapAdd"].as_array() {
                    runtime.capabilities = caps.iter()
                        .filter_map(|c| c.as_str().map(String::from))
                        .collect();
                }

                // Mounts — check for dangerous host paths
                if let Some(mounts) = first["Mounts"].as_array() {
                    for m in mounts {
                        let source = m["Source"].as_str().unwrap_or("").to_string();
                        let dest   = m["Destination"].as_str().unwrap_or("").to_string();
                        let mode   = m["Mode"].as_str().unwrap_or("").to_string();
                        let dangerous = source.starts_with('/') &&
                            !source.starts_with("/var/lib/docker") &&
                            !source.starts_with("/home") &&
                            !source.starts_with("/opt/app") &&
                            !source.starts_with("/data");
                        runtime.mounts.push(MountInfo { source, destination: dest, mode, dangerous });
                    }
                }

                // Env var keys only (not values — too sensitive to log)
                if let Some(env) = first["Config"]["Env"].as_array() {
                    runtime.env_vars = env.iter()
                        .filter_map(|e| e.as_str())
                        .filter_map(|e| e.split('=').next().map(String::from))
                        .collect();
                }
            }
        }

        runtime
    }

    // ── Image vulnerability scanning ──────────────────────────
    pub async fn scan_image(&self, image: &str) -> Vec<ImageVulnerability> {
        let mut vulns = vec![];

        // Try Trivy first (most comprehensive)
        if let Some(v) = self.scan_with_trivy(image).await {
            vulns.extend(v);
            return vulns;
        }

        // Fall back to Grype
        if let Some(v) = self.scan_with_grype(image).await {
            vulns.extend(v);
        }

        vulns
    }

    async fn scan_with_trivy(&self, image: &str) -> Option<Vec<ImageVulnerability>> {
        let out = tokio::process::Command::new("trivy")
            .args(["image", "--format", "json", "--quiet", image])
            .output().await.ok()?;

        let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let mut vulns = vec![];

        if let Some(results) = json["Results"].as_array() {
            for result in results {
                if let Some(vulnerabilities) = result["Vulnerabilities"].as_array() {
                    for v in vulnerabilities {
                        let cvss = v["CVSS"]["nvd"]["V3Score"]
                            .as_f64()
                            .or_else(|| v["CVSS"]["redhat"]["V3Score"].as_f64())
                            .unwrap_or(5.0) as f32;

                        vulns.push(ImageVulnerability {
                            image:         image.to_string(),
                            cve:           v["VulnerabilityID"].as_str().unwrap_or("").to_string(),
                            package:       v["PkgName"].as_str().unwrap_or("").to_string(),
                            version:       v["InstalledVersion"].as_str().unwrap_or("").to_string(),
                            fixed_version: v["FixedVersion"].as_str().map(String::from),
                            severity:      v["Severity"].as_str().unwrap_or("UNKNOWN").to_string(),
                            cvss,
                            layer:         v["Layer"]["DiffID"].as_str().map(String::from),
                            scanner:       "trivy".to_string(),
                        });
                    }
                }
            }
        }

        info!("🐳 Trivy: {} vulnerabilities in image {}", vulns.len(), image);
        Some(vulns)
    }

    async fn scan_with_grype(&self, image: &str) -> Option<Vec<ImageVulnerability>> {
        let out = tokio::process::Command::new("grype")
            .args([image, "-o", "json", "--quiet"])
            .output().await.ok()?;

        let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
        let mut vulns = vec![];

        if let Some(matches) = json["matches"].as_array() {
            for m in matches {
                let vuln = &m["vulnerability"];
                let cvss = vuln["cvss"].as_array()
                    .and_then(|a| a.iter().find(|c| c["version"].as_str() == Some("3.1")))
                    .and_then(|c| c["metrics"]["baseScore"].as_f64())
                    .unwrap_or(5.0) as f32;

                vulns.push(ImageVulnerability {
                    image:         image.to_string(),
                    cve:           vuln["id"].as_str().unwrap_or("").to_string(),
                    package:       m["artifact"]["name"].as_str().unwrap_or("").to_string(),
                    version:       m["artifact"]["version"].as_str().unwrap_or("").to_string(),
                    fixed_version: vuln["fix"]["versions"].as_array()
                        .and_then(|a| a.first())
                        .and_then(|s| s.as_str())
                        .map(String::from),
                    severity:      vuln["severity"].as_str().unwrap_or("Unknown").to_string(),
                    cvss,
                    layer:         None,
                    scanner:       "grype".to_string(),
                });
            }
        }

        info!("🐳 Grype: {} vulnerabilities in image {}", vulns.len(), image);
        Some(vulns)
    }

    // ── Container drift detection ─────────────────────────────
    /// Baseline a container's filesystem — called when container starts.
    pub async fn baseline_container(&self, container_id: &str) {
        let out = tokio::process::Command::new("docker")
            .args(["exec", container_id, "find", "/", "-type", "f",
                "-not", "-path", "*/proc/*", "-not", "-path", "*/sys/*",
                "-exec", "sha256sum", "{}", "+"])
            .output().await;

        if let Ok(out) = out {
            let mut file_hashes = HashMap::new();
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let parts: Vec<&str> = line.splitn(2, "  ").collect();
                if parts.len() == 2 {
                    file_hashes.insert(parts[1].trim().to_string(), parts[0].to_string());
                }
            }
            let count = file_hashes.len();
            self.baseline.lock().await.insert(container_id.to_string(), file_hashes);
            debug!("🐳 Baselined container {}: {} files", container_id, count);
        }
    }

    /// Detect drift — files written at runtime (T1525 implant detection).
    pub async fn detect_drift(&self, container_id: &str) -> Vec<String> {
        let out = tokio::process::Command::new("docker")
            .args(["diff", container_id])
            .output().await;

        let Ok(out) = out else { return vec![] };
        let mut drifted = vec![];

        for line in String::from_utf8_lossy(&out.stdout).lines() {
            // A = added, C = changed, D = deleted
            let line = line.trim();
            if line.starts_with('A') || line.starts_with('C') {
                let path = line[2..].trim();
                // Ignore expected runtime writes
                let is_normal = path.starts_with("/tmp/") ||
                    path.starts_with("/var/log/") ||
                    path.starts_with("/var/run/") ||
                    path.starts_with("/run/") ||
                    path.ends_with(".pid") ||
                    path.ends_with(".log");
                if !is_normal {
                    drifted.push(path.to_string());
                }
            }
        }

        if !drifted.is_empty() {
            warn!("🐳 Container drift detected in {}: {} modified files", container_id, drifted.len());
        }
        drifted
    }

    // ── Kubernetes posture ────────────────────────────────────
    async fn kubectl_available(&self) -> bool {
        tokio::process::Command::new("kubectl")
            .args(["version", "--client", "--output", "json"])
            .output().await
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    async fn check_kubernetes_posture(&self) -> Vec<ContainerFinding> {
        let mut findings = vec![];

        // Check for pods with privileged containers
        if let Ok(out) = tokio::process::Command::new("kubectl")
            .args(["get", "pods", "--all-namespaces", "-o", "json"])
            .output().await
        {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                if let Some(items) = json["items"].as_array() {
                    for pod in items {
                        let ns   = pod["metadata"]["namespace"].as_str().unwrap_or("default");
                        let name = pod["metadata"]["name"].as_str().unwrap_or("unknown");

                        // Check all containers in the pod
                        let containers_json = pod["spec"]["containers"].as_array()
                            .into_iter().chain(pod["spec"]["initContainers"].as_array())
                            .flatten();

                        for c in containers_json {
                            let cname = c["name"].as_str().unwrap_or("unknown");
                            let sc    = &c["securityContext"];

                            if sc["privileged"].as_bool().unwrap_or(false) {
                                findings.push(ContainerFinding {
                                    container_id:   format!("{}/{}", ns, name),
                                    container_name: cname.to_string(),
                                    image:          c["image"].as_str().unwrap_or("").to_string(),
                                    finding_type:   ContainerFindingType::PrivilegedContainer,
                                    severity:       Severity::Critical,
                                    description:    format!(
                                        "Kubernetes pod {}/{} container '{}' is privileged.",
                                        ns, name, cname
                                    ),
                                    mitre_id:    "T1610",
                                    remediation: "Set privileged: false in pod security context. Use PodSecurityAdmission with 'restricted' profile.".to_string(),
                                });
                            }

                            // runAsRoot check
                            let run_as_user = sc["runAsUser"].as_u64().unwrap_or(0);
                            if run_as_user == 0 && !sc["runAsNonRoot"].as_bool().unwrap_or(false) {
                                findings.push(ContainerFinding {
                                    container_id:   format!("{}/{}", ns, name),
                                    container_name: cname.to_string(),
                                    image:          c["image"].as_str().unwrap_or("").to_string(),
                                    finding_type:   ContainerFindingType::RootUser,
                                    severity:       Severity::Medium,
                                    description:    format!(
                                        "Pod {}/{} container '{}' runs as root. Set runAsNonRoot: true.",
                                        ns, name, cname
                                    ),
                                    mitre_id:    "T1610",
                                    remediation: "Add securityContext.runAsNonRoot: true and runAsUser: 1000+".to_string(),
                                });
                            }
                        }

                        // Check pod-level host namespace sharing
                        if pod["spec"]["hostNetwork"].as_bool().unwrap_or(false) {
                            findings.push(ContainerFinding {
                                container_id:   format!("{}/{}", ns, name),
                                container_name: name.to_string(),
                                image:          "N/A".to_string(),
                                finding_type:   ContainerFindingType::HostNetworkMode,
                                severity:       Severity::High,
                                description:    format!("Pod {}/{} uses hostNetwork: true.", ns, name),
                                mitre_id:    "T1610",
                                remediation: "Remove hostNetwork: true unless strictly required (e.g., network monitoring daemonsets).".to_string(),
                            });
                        }

                        if pod["spec"]["hostPID"].as_bool().unwrap_or(false) {
                            findings.push(ContainerFinding {
                                container_id:   format!("{}/{}", ns, name),
                                container_name: name.to_string(),
                                image:          "N/A".to_string(),
                                finding_type:   ContainerFindingType::HostPidMode,
                                severity:       Severity::Critical,
                                description:    format!("Pod {}/{} uses hostPID: true.", ns, name),
                                mitre_id:    "T1611",
                                remediation: "Remove hostPID: true. Apply PodSecurityAdmission 'baseline' or 'restricted'.".to_string(),
                            });
                        }
                    }
                }
            }
        }

        // Check for overly permissive RBAC (ClusterRoleBindings with cluster-admin)
        if let Ok(out) = tokio::process::Command::new("kubectl")
            .args(["get", "clusterrolebindings", "-o", "json"])
            .output().await
        {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                if let Some(items) = json["items"].as_array() {
                    for binding in items {
                        let role = binding["roleRef"]["name"].as_str().unwrap_or("");
                        if role == "cluster-admin" {
                            if let Some(subjects) = binding["subjects"].as_array() {
                                for s in subjects {
                                    if s["kind"].as_str() == Some("ServiceAccount") {
                                        let sa   = s["name"].as_str().unwrap_or("");
                                        let ns   = s["namespace"].as_str().unwrap_or("");
                                        let bname = binding["metadata"]["name"].as_str().unwrap_or("");
                                        // Skip known-good system accounts
                                        if !sa.starts_with("system:") {
                                            findings.push(ContainerFinding {
                                                container_id:   format!("{}/{}", ns, sa),
                                                container_name: sa.to_string(),
                                                image:          "N/A".to_string(),
                                                finding_type:   ContainerFindingType::PrivilegedServiceAccount,
                                                severity:       Severity::Critical,
                                                description:    format!(
                                                    "ServiceAccount {}/{} has cluster-admin via ClusterRoleBinding '{}'. \
                                                     Full cluster access — if this pod is compromised, the entire cluster is.",
                                                    ns, sa, bname
                                                ),
                                                mitre_id:    "T1552.007",
                                                remediation: "Revoke cluster-admin. Use namespace-scoped Roles with minimal required permissions.".to_string(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    // ── Convert findings to threat events ─────────────────────
    pub fn findings_to_threats(findings: &[ContainerFinding], agent_id: &str, hostname: &str) -> Vec<ThreatEvent> {
        findings.iter()
            .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
            .map(|f| ThreatEvent {
                id:               Uuid::new_v4().to_string(),
                agent_id:         agent_id.to_string(),
                hostname:         hostname.to_string(),
                timestamp:        Utc::now(),
                severity:         f.severity.clone(),
                confidence:       match f.severity {
                    Severity::Critical => 95.0,
                    Severity::High     => 85.0,
                    _                  => 70.0,
                },
                threat_name:      format!("{} — {}", f.mitre_id, format!("{:?}", f.finding_type)),
                description:      f.description.clone(),
                mitre_tactics:    vec!["execution".to_string()],
                mitre_techniques: vec![f.mitre_id.to_string()],
                matched_rules:    vec!["container_security".to_string()],
                raw_event_ids:    vec![],
                chain:            None,
                iocs:             vec![
                    IOC { ioc_type: IOCType::ProcessName, value: f.container_name.clone(),
                          source: "container_engine".to_string(), confidence: 90.0 },
                ],
                suggested_action: match f.severity {
                    Severity::Critical => ResponseAction::KillProcess(0),
                    _                  => ResponseAction::Alert,
                },
                llm_analysis:          None,
                auto_generated_rule:   None,
            })
            .collect()
    }
}
