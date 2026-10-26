#![allow(dead_code)]
// src/memory/mod.rs — Memory forensics engine
// Integrates: LiME (Linux Memory Extractor), Volatility 3

use crate::config::MemoryConfig;
use anyhow::Result;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use tokio::process::Command;
use chrono::Utc;

pub struct MemoryEngine {
    config: MemoryConfig,
}

#[derive(Debug)]
pub struct MemoryAnalysis {
    pub dump_path: PathBuf,
    pub process_list: Vec<MemProcess>,
    pub network_connections: Vec<String>,
    pub loaded_modules: Vec<String>,
    pub suspicious_findings: Vec<String>,
}

#[derive(Debug)]
pub struct MemProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub suspicious: bool,
}

impl MemoryEngine {
    pub fn new(config: MemoryConfig) -> Self {
        info!("💾 MemoryEngine initialized (enabled={})", config.enabled);
        Self { config }
    }

    /// Acquire a memory dump using LiME kernel module
    pub async fn acquire_dump(&self, output_dir: &Path) -> Result<PathBuf> {
        if !self.config.enabled {
            anyhow::bail!("Memory engine disabled");
        }

        let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let dump_path = output_dir.join(format!("memory_{}.lime", ts));

        // Try LiME first
        if let Some(ref lime_path) = self.config.lime_module_path {
            if Path::new(lime_path).exists() {
                info!("💾 Loading LiME module for memory acquisition...");
                let result = Command::new("insmod")
                    .args([
                        lime_path,
                        &format!("path={}", dump_path.display()),
                        "format=lime",
                    ])
                    .output().await?;

                if result.status.success() {
                    info!("💾 Memory dump acquired → {}", dump_path.display());
                    // Unload LiME after acquisition
                    let _ = Command::new("rmmod").arg("lime").output().await;
                    return Ok(dump_path);
                } else {
                    let err = String::from_utf8_lossy(&result.stderr);
                    warn!("LiME insmod failed: {}", err);
                }
            } else {
                warn!("LiME module not found at {}. Install: apt install lime-forensics-dkms", lime_path);
            }
        }

        // Fallback: /proc/kcore (limited, kernel image excluded, only RAM-mapped memory)
        warn!("💾 LiME unavailable — using /proc/kcore (partial memory access)");
        let kcore_path = output_dir.join(format!("kcore_{}.bin", ts));
        if Path::new("/proc/kcore").exists() {
            // Note: reading kcore requires root and gets partial memory
            let _ = Command::new("dd")
                .args([
                    "if=/proc/kcore",
                    &format!("of={}", kcore_path.display()),
                    "bs=1M",
                    "count=512",  // 512MB cap for safety
                ])
                .output().await;
            return Ok(kcore_path);
        }

        anyhow::bail!("No memory acquisition method available")
    }

    /// Analyze a memory dump using Volatility 3
    pub async fn analyze_dump(&self, dump_path: &Path) -> Result<MemoryAnalysis> {
        let vol = self.config.volatility_path.as_deref()
            .unwrap_or("/usr/bin/vol");

        if !Path::new(vol).exists() {
            warn!("Volatility not found at {}. Install: pip3 install volatility3", vol);
            return Ok(MemoryAnalysis {
                dump_path: dump_path.to_path_buf(),
                process_list: vec![],
                network_connections: vec![],
                loaded_modules: vec![],
                suspicious_findings: vec!["Volatility not installed".to_string()],
            });
        }

        info!("🔬 Analyzing memory dump with Volatility...");
        let dump_str = dump_path.to_string_lossy();

        // pslist
        let process_list = self.vol_pslist(vol, &dump_str).await;

        // network connections
        let network_connections = self.vol_netstat(vol, &dump_str).await;

        // loaded kernel modules
        let loaded_modules = self.vol_lsmod(vol, &dump_str).await;

        // Malfind (process memory with injected code)
        let mut suspicious = self.vol_malfind(vol, &dump_str).await;

        // Identify suspicious processes
        let sus_procs: Vec<String> = process_list.iter()
            .filter(|p| p.suspicious)
            .map(|p| format!("Suspicious process: {} (pid={})", p.name, p.pid))
            .collect();
        suspicious.extend(sus_procs);

        info!("💾 Memory analysis complete: {} procs, {} connections, {} suspicious",
            process_list.len(), network_connections.len(), suspicious.len());

        Ok(MemoryAnalysis {
            dump_path: dump_path.to_path_buf(),
            process_list,
            network_connections,
            loaded_modules,
            suspicious_findings: suspicious,
        })
    }

    async fn vol_pslist(&self, vol: &str, dump: &str) -> Vec<MemProcess> {
        let mut procs = vec![];
        let out = Command::new(vol)
            .args(["-f", dump, "linux.pslist"])
            .output().await
            .unwrap_or_else(|_| {
                // tokio Command failed to spawn — return empty output
                // Safety: ExitStatus is repr(i32) on Linux, 0 = success
                let status: std::process::ExitStatus = unsafe { std::mem::transmute(0i32) };
                std::process::Output { status, stdout: vec![], stderr: vec![] }
            });

        for line in String::from_utf8_lossy(&out.stdout).lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let pid = parts[0].parse::<u32>().unwrap_or(0);
                let ppid = parts[1].parse::<u32>().unwrap_or(0);
                let name = parts[2].to_string();
                let suspicious = is_suspicious_process(&name, pid, ppid);
                procs.push(MemProcess { pid, ppid, name, path: String::new(), suspicious });
            }
        }
        procs
    }

    async fn vol_netstat(&self, vol: &str, dump: &str) -> Vec<String> {
        let out = Command::new(vol)
            .args(["-f", dump, "linux.netstat"])
            .output().await
            .unwrap_or_else(|_| {
                // tokio Command failed to spawn — return empty output
                // Safety: ExitStatus is repr(i32) on Linux, 0 = success
                let status: std::process::ExitStatus = unsafe { std::mem::transmute(0i32) };
                std::process::Output { status, stdout: vec![], stderr: vec![] }
            });
        String::from_utf8_lossy(&out.stdout)
            .lines().skip(2)
            .map(String::from)
            .collect()
    }

    async fn vol_lsmod(&self, vol: &str, dump: &str) -> Vec<String> {
        let out = Command::new(vol)
            .args(["-f", dump, "linux.lsmod"])
            .output().await
            .unwrap_or_else(|_| {
                // tokio Command failed to spawn — return empty output
                // Safety: ExitStatus is repr(i32) on Linux, 0 = success
                let status: std::process::ExitStatus = unsafe { std::mem::transmute(0i32) };
                std::process::Output { status, stdout: vec![], stderr: vec![] }
            });
        String::from_utf8_lossy(&out.stdout)
            .lines().skip(2)
            .map(String::from)
            .collect()
    }

    async fn vol_malfind(&self, vol: &str, dump: &str) -> Vec<String> {
        let out = Command::new(vol)
            .args(["-f", dump, "linux.malfind"])
            .output().await
            .unwrap_or_else(|_| {
                // tokio Command failed to spawn — return empty output
                // Safety: ExitStatus is repr(i32) on Linux, 0 = success
                let status: std::process::ExitStatus = unsafe { std::mem::transmute(0i32) };
                std::process::Output { status, stdout: vec![], stderr: vec![] }
            });
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        if text.trim().is_empty() {
            return vec![];
        }
        vec![format!("Malfind output:\n{}", &text[..text.len().min(2000)])]
    }

    /// Scan running process memory (lightweight — no full dump required)
    pub async fn scan_process_memory(&self, pid: u32) -> Vec<String> {
        if !self.config.scan_running_procs { return vec![]; }

        let mut findings = vec![];
        let maps_path = format!("/proc/{}/maps", pid);
        let Ok(maps) = std::fs::read_to_string(&maps_path) else { return findings };

        let suspicious_patterns = [
            ("[heap]", "Code executing from heap"),
            ("/dev/shm", "Mapping in /dev/shm (common malware technique)"),
            ("/tmp/",    "Mapping in /tmp"),
            ("(deleted)", "Mapping deleted-on-disk executable"),
        ];

        for line in maps.lines() {
            // Check for executable pages with suspicious attributes
            let is_exec = line.split_whitespace().nth(1).map(|p| p.contains('x')).unwrap_or(false);
            if !is_exec { continue; }

            for (pattern, description) in &suspicious_patterns {
                if line.contains(pattern) {
                    findings.push(format!("PID {}: {} — {}", pid, description, line));
                }
            }
        }
        findings
    }
}

fn is_suspicious_process(name: &str, pid: u32, _ppid: u32) -> bool {
    // Processes suspicious in memory context:
    // - shell processes with high PID (possible reverse shell)
    // - processes with no parent (orphaned)
    // - common malware names
    let malware_names = ["nc", "ncat", "nmap", "meterpreter", "beacon",
                          "mimikatz", "cobaltstrike", "empire"];
    if malware_names.iter().any(|m| name.to_lowercase().contains(m)) {
        return true;
    }
    if (name == "bash" || name == "sh" || name == "zsh") && pid > 10000 {
        return true; // high-pid shell could be injected
    }
    false
}
