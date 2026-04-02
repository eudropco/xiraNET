use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

/// TLS/mTLS konfigürasyonu oluştur
pub fn create_tls_config(
    cert_path: &str,
    key_path: &str,
    mtls_enabled: bool,
    client_ca_path: Option<&str>,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // Sunucu sertifikası yükle
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<rustls::pki_types::CertificateDer> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;

    if cert_chain.is_empty() {
        return Err("No certificates found in cert file".into());
    }

    // Private key yükle
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let keys: Vec<rustls::pki_types::PrivateKeyDer> = pkcs8_private_keys(&mut key_reader)
        .map(|k| k.map(rustls::pki_types::PrivateKeyDer::from))
        .collect::<Result<Vec<_>, _>>()?;

    let key = keys.into_iter().next()
        .ok_or("No private key found in key file")?;

    let config = if mtls_enabled {
        // mTLS: Client sertifika doğrulama
        if let Some(ca_path) = client_ca_path {
            let ca_file = File::open(ca_path)?;
            let mut ca_reader = BufReader::new(ca_file);
            let ca_certs: Vec<rustls::pki_types::CertificateDer> = certs(&mut ca_reader)
                .collect::<Result<Vec<_>, _>>()?;

            let mut root_store = rustls::RootCertStore::empty();
            for cert in ca_certs {
                root_store.add(cert)?;
            }

            let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| format!("Failed to create client verifier: {}", e))?;

            ServerConfig::builder()
                .with_client_cert_verifier(client_auth)
                .with_single_cert(cert_chain, key)
                .map_err(|e| format!("TLS config error: {}", e))?
        } else {
            return Err("mTLS enabled but no client CA path provided".into());
        }
    } else {
        // Standard TLS
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| format!("TLS config error: {}", e))?
    };

    tracing::info!(
        "TLS configured: cert={}, mtls={}",
        cert_path,
        mtls_enabled
    );

    Ok(config)
}

/// TLS sertifikası oluşturma komutu (self-signed test için)
pub fn print_cert_generation_help() {
    println!("Generate self-signed TLS certificates for testing:");
    println!();
    println!("  # Generate CA key and cert");
    println!("  openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem -days 365 -nodes -subj '/CN=XIRA CA'");
    println!();
    println!("  # Generate server key and CSR");
    println!("  openssl req -newkey rsa:4096 -keyout server-key.pem -out server.csr -nodes -subj '/CN=localhost'");
    println!();
    println!("  # Sign server cert with CA");
    println!("  openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365");
    println!();
    println!("  # For mTLS — generate client cert");
    println!("  openssl req -newkey rsa:4096 -keyout client-key.pem -out client.csr -nodes -subj '/CN=client'");
    println!("  openssl x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 365");
}
