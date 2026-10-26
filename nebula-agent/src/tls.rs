// ══════════════════════════════════════════════════════════════
// Shared TLS client construction for all agent → Nexus HTTP(S) calls.
//
// Historically several auxiliary clients (gossip, llm model download, posture
// imported-checks) hardcoded `danger_accept_invalid_certs(true)`, silently
// disabling TLS verification regardless of config — a MITM risk. They now all
// route through `nexus_http_builder` so the same policy applies everywhere:
//
//   * ca_cert_path set  → CERTIFICATE PINNING: trust ONLY that certificate as
//     the root and drop the built-in root store. This is the recommended,
//     secure configuration and works with the Nexus's default self-signed cert
//     (point ca_cert_path at the Nexus's cert PEM). An attacker's cert — even
//     one signed by a public CA — will not validate.
//   * ca_cert_path unset, tls_verify = false → verification disabled (explicit,
//     logged opt-out for lab/dev only).
//   * ca_cert_path unset, tls_verify = true (default) → standard system-trust
//     verification (the self-signed Nexus will be REJECTED until a pin or an
//     explicit tls_verify=false is configured — this is intentional).
// ══════════════════════════════════════════════════════════════

use reqwest::ClientBuilder;
use tracing::{info, warn};

/// Build a reqwest ClientBuilder pre-configured with the shared Nexus TLS
/// policy. Callers add their own timeout / headers on top.
pub fn nexus_http_builder(ca_cert_path: Option<&str>, tls_verify: bool) -> ClientBuilder {
    let mut builder = ClientBuilder::new();

    if let Some(path) = ca_cert_path.filter(|p| !p.trim().is_empty()) {
        match std::fs::read(path) {
            Ok(data) => match reqwest::Certificate::from_pem(&data) {
                Ok(cert) => {
                    // Pin: this cert is the only trust anchor.
                    builder = builder
                        .add_root_certificate(cert)
                        .tls_built_in_root_certs(false);
                    info!("🔒 TLS: pinned to Nexus certificate {}", path);
                    return builder;
                }
                Err(e) => warn!("🔒 TLS: invalid PEM in ca_cert_path {} ({}) — falling back to tls_verify={}", path, e, tls_verify),
            },
            Err(e) => warn!("🔒 TLS: cannot read ca_cert_path {} ({}) — falling back to tls_verify={}", path, e, tls_verify),
        }
    }

    if !tls_verify {
        warn!("⚠️ TLS verification disabled (tls_verify=false, no cert pin)");
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder
}
