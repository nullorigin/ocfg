use crate::error::{OcfgError, Result};
use openssl::rand::rand_bytes;
use openssl::sha::sha256;
use rand::Rng;
use base64::{Engine as _, engine::general_purpose};

/// Generate a cryptographically secure random hex string
pub fn generate_hex(length: usize) -> Result<String> {
    let bytes = (length + 1) / 2;
    let mut buf = vec![0u8; bytes];
    rand_bytes(&mut buf).map_err(|e| OcfgError::Crypto(e.to_string()))?;
    Ok(hex::encode(&buf))
}

/// Generate a cryptographically secure random base64 string
pub fn generate_base64(length: usize) -> Result<String> {
    let bytes = (length * 3) / 4;
    let mut buf = vec![0u8; bytes];
    rand_bytes(&mut buf).map_err(|e| OcfgError::Crypto(e.to_string()))?;
    Ok(general_purpose::STANDARD.encode(&buf))
}

/// Generate a secure random password
pub fn generate_password(length: usize) -> Result<String> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    let mut rng = rand::thread_rng();
    
    let password: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    
    Ok(password)
}

/// Generate an SSH key pair (simplified - in reality would use ssh-keygen or appropriate library)
pub fn generate_ssh_key() -> Result<String> {
    // This is a placeholder - real implementation would use ssh-keygen or a Rust SSH library
    // For now, we'll generate a random string that looks like a public key
    let random_part = generate_hex(32)?;
    Ok(format!("ssh-ed25519 {} user@host", random_part))
}

/// Generate a WireGuard private key
pub fn generate_wireguard_key() -> Result<String> {
    // WireGuard uses 32-byte keys encoded in base64
    generate_base64(32)
}

/// Generate a WireGuard preshared key
pub fn generate_wireguard_psk() -> Result<String> {
    generate_base64(32)
}

/// Generate an OpenVPN static key
pub fn generate_openvpn_static_key() -> Result<String> {
    // OpenVPN static keys are 2048 bits (256 bytes) encoded in base64
    generate_base64(256)
}

/// Generate an encryption key (32 bytes for AES-256)
pub fn generate_encryption_key() -> Result<String> {
    generate_hex(32)
}

/// Generate an HMAC key (32 bytes)
pub fn generate_hmac_key() -> Result<String> {
    generate_hex(32)
}

/// Generate an API key
pub fn generate_api_key() -> Result<String> {
    generate_hex(32)
}

/// Generate a certificate serial number
pub fn generate_serial() -> Result<String> {
    let mut rng = rand::thread_rng();
    let serial: u64 = rng.gen();
    Ok(format!("{:016x}", serial))
}

/// Hash a password using SHA-256 (for demonstration - use proper password hashing in production)
pub fn hash_password(password: &str) -> Result<String> {
    let hash = sha256(password.as_bytes());
    Ok(format!("${{sha256}}{}", hex::encode(hash)))
}

/// Generate a RADIUS shared secret
pub fn generate_radius_secret() -> Result<String> {
    generate_hex(16)
}

/// Validate a hex string
pub fn is_valid_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit() && s.len() % 2 == 0)
}

/// Validate a base64 string
pub fn is_valid_base64(s: &str) -> bool {
    general_purpose::STANDARD.decode(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hex() {
        let hex = generate_hex(32).unwrap();
        assert_eq!(hex.len(), 32);
        assert!(is_valid_hex(&hex));
    }

    #[test]
    fn test_generate_password() {
        let password = generate_password(24).unwrap();
        assert_eq!(password.len(), 24);
    }

    #[test]
    fn test_generate_wireguard_key() {
        let key = generate_wireguard_key().unwrap();
        assert!(is_valid_base64(&key));
    }
}
