use crate::error::{OcfgError, Result};
use rand::RngExt;

pub fn rand_bytes(length: usize) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    rand::fill(&mut buf);
    buf
}
/// Generate a cryptographically secure random hex string
pub fn generate_hex(length: usize) -> String {
    let bytes = (length + 1) / 2;
    let mut buf = vec![0u8; bytes];
    rand::fill(&mut buf);
    encode_hex(&buf)
}
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}
/// Generate a cryptographically secure random base64 string
pub fn generate_base64(length: usize) -> String {
    let bytes = (length * 3) / 4;
    let mut buf = vec![0u8; bytes];
    rand::fill(&mut buf);
    encode_base64(&buf)
}
pub fn encode_base64(bytes: &[u8]) -> String {
    const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let mut i = 0;

    // Process 3 bytes at a time
    while i + 2 < bytes.len() {
        let b1 = bytes[i];
        let b2 = bytes[i + 1];
        let b3 = bytes[i + 2];

        result.push(BASE64_CHARS[(b1 >> 2) as usize] as char);
        result.push(BASE64_CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
        result.push(BASE64_CHARS[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize] as char);
        result.push(BASE64_CHARS[(b3 & 0x3f) as usize] as char);

        i += 3;
    }

    // Handle remaining bytes
    if i < bytes.len() {
        let b1 = bytes[i];
        result.push(BASE64_CHARS[(b1 >> 2) as usize] as char);

        if i + 1 < bytes.len() {
            let b2 = bytes[i + 1];
            result.push(BASE64_CHARS[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
            result.push(BASE64_CHARS[((b2 & 0x0f) << 2) as usize] as char);
            result.push('=');
        } else {
            result.push(BASE64_CHARS[((b1 & 0x03) << 4) as usize] as char);
            result.push('=');
            result.push('=');
        }
    }

    result
}
pub fn decode_base64(s: &str) -> Result<Vec<u8>> {
    const BASE64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Create a reverse lookup table
    let mut decode_table = [255u8; 256];
    for (i, &ch) in BASE64_CHARS.iter().enumerate() {
        decode_table[ch as usize] = i as u8;
    }

    // Remove whitespace and validate input
    let input: String = s.chars().filter(|c| !c.is_whitespace()).collect();

    if input.is_empty() {
        return Ok(Vec::new());
    }

    // Count padding characters
    let padding = input.chars().rev().take_while(|&c| c == '=').count();

    if padding > 2 {
        return Err(OcfgError::InvalidValue("Invalid base64 padding".to_string()));
    }

    let input_len = input.len();
    if input_len % 4 != 0 {
        return Err(OcfgError::InvalidValue("Invalid base64 length".to_string()));
    }

    let mut result = Vec::with_capacity((input_len * 3) / 4);
    let input_bytes = input.as_bytes();

    // Process 4 characters at a time
    let mut i = 0;
    while i < input_len {
        let c1 = input_bytes[i];
        let c2 = input_bytes[i + 1];
        let c3 = input_bytes[i + 2];
        let c4 = input_bytes[i + 3];

        // Check for valid base64 characters
        let b1 = decode_table[c1 as usize];
        let b2 = decode_table[c2 as usize];

        if b1 == 255 || b2 == 255 {
            return Err(OcfgError::InvalidValue("Invalid base64 character".to_string()));
        }

        // First byte
        result.push((b1 << 2) | (b2 >> 4));

        // Check if we have more data (not padding)
        if c3 != b'=' {
            let b3 = decode_table[c3 as usize];
            if b3 == 255 {
                return Err(OcfgError::InvalidValue("Invalid base64 character".to_string()));
            }

            // Second byte
            result.push(((b2 & 0x0f) << 4) | (b3 >> 2));

            if c4 != b'=' {
                let b4 = decode_table[c4 as usize];
                if b4 == 255 {
                    return Err(OcfgError::InvalidValue("Invalid base64 character".to_string()));
                }

                // Third byte
                result.push(((b3 & 0x03) << 6) | b4);
            }
        }

        i += 4;
    }

    Ok(result)
}

/// Generate a secure random password
pub fn generate_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    let mut rng = rand::rng();
    
    let password: String = (0..length)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    
    password
}

/// Generate a WireGuard private key
pub fn generate_wireguard_key() -> String {
    // WireGuard uses 32-byte keys encoded in base64
    generate_base64(32)
}

/// Generate a WireGuard preshared key
pub fn generate_wireguard_psk() -> String {
    generate_base64(32)
}

/// Generate an OpenVPN static key
pub fn generate_openvpn_static_key() -> String {
    // OpenVPN static keys are 2048 bits (256 bytes) encoded in base64
    generate_base64(256)
}

/// Generate an encryption key (32 bytes for AES-256)
pub fn generate_encryption_key() -> String {
    generate_hex(32)
}

/// Generate an HMAC key (32 bytes)
pub fn generate_hmac_key() -> String {
    generate_hex(32)
}

/// Generate an API key
pub fn generate_api_key() -> String {
    generate_hex(32)
}

/// Generate a certificate serial number
pub fn generate_serial() -> String {
    let mut rng = rand::rng();
    let serial: u64 = rng.random();
    format!("{:016x}", serial)
}

/// Hash a password using SHA-256 (for demonstration - use proper password hashing in production)
pub fn hash_password(password: &str) -> String {
    let hash = sha256(password.as_bytes());
    format!("${{sha256}}{}", encode_hex(&hash))
}

/// Generate a RADIUS shared secret
pub fn generate_radius_secret() -> String {
    generate_hex(16)
}

/// Generate an Ed25519 SSH key pair using the built-in Ed25519 implementation
/// Returns (secret_key, public_key, ssh_public_key_string)
/// The secret_key is 64 bytes (32-byte seed + 32-byte public key)
/// The public_key is 32 bytes
/// The ssh_public_key_string is formatted for SSH authorized_keys files
pub fn generate_ed25519_keypair() -> (Vec<u8>, Vec<u8>, String) {
    // Generate a new Ed25519 key pair using the built-in implementation
    let keypair = KeyPair::generate();
    
    // Extract the secret key (64 bytes)
    let secret_key = keypair.sk.to_vec();
    
    // Extract the public key (32 bytes)
    let public_key = keypair.pk.to_vec();
    
    // Encode the public key in SSH format
    let ssh_public_key = encode_ssh_ed25519_public_key(&public_key);
    
    (secret_key, public_key, ssh_public_key)
}

/// Encode an Ed25519 public key in SSH authorized_keys format
/// Format: ssh-ed25519 AAAA... comment
fn encode_ssh_ed25519_public_key(public_key: &[u8]) -> String {
    // SSH key format: type length (4 bytes) + type string + public key length (4 bytes) + public key
    let key_type = b"ssh-ed25519";
    
    let mut buffer = Vec::new();
    
    // Add key type length (4 bytes big-endian)
    buffer.extend_from_slice(&(key_type.len() as u32).to_be_bytes().as_ref());
    
    // Add key type
    buffer.extend_from_slice(key_type);
    
    // Add public key length (4 bytes big-endian)
    buffer.extend_from_slice(&(public_key.len() as u32).to_be_bytes().as_ref());
    
    // Add public key
    buffer.extend_from_slice(public_key);
    
    // Base64 encode the buffer
    let encoded = encode_base64(&buffer);
    
    format!("ssh-ed25519 {} ocfg-generated", encoded)
}

/// Generate an SSH Ed25519 public key string for use in authorized_keys files
/// Returns just the SSH public key string
pub fn generate_ssh_ed25519_key() -> String {
    let (_, _, ssh_public_key) = generate_ed25519_keypair();
    ssh_public_key
}

/// Validate a hex string
pub fn is_valid_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit() && s.len() % 2 == 0)
}

/// Validate a base64 string
pub fn is_valid_base64(s: &str) -> bool {
    decode_base64(s).is_ok()
}

#[inline(always)]
fn load_be(base: &[u8], offset: usize) -> u64 {
    let addr = &base[offset..];
    (addr[7] as u64)
        | (addr[6] as u64) << 8
        | (addr[5] as u64) << 16
        | (addr[4] as u64) << 24
        | (addr[3] as u64) << 32
        | (addr[2] as u64) << 40
        | (addr[1] as u64) << 48
        | (addr[0] as u64) << 56
}

#[inline(always)]
fn store_be(base: &mut [u8], offset: usize, x: u64) {
    let addr = &mut base[offset..];
    addr[7] = x as u8;
    addr[6] = (x >> 8) as u8;
    addr[5] = (x >> 16) as u8;
    addr[4] = (x >> 24) as u8;
    addr[3] = (x >> 32) as u8;
    addr[2] = (x >> 40) as u8;
    addr[1] = (x >> 48) as u8;
    addr[0] = (x >> 56) as u8;
}

/// Compute SHA-256 hash of input
pub fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::hash(input)
}

/// Compute SHA-512 hash of input
pub fn sha512(input: &[u8]) -> [u8; 64] {
    Hash::hash(input)
}

// SHA-256 implementation (32-bit words)
struct W256([u32; 16]);

#[derive(Copy, Clone)]
struct State256([u32; 8]);

impl W256 {
    fn new(input: &[u8]) -> Self {
        let mut w = [0u32; 16];
        for (i, e) in w.iter_mut().enumerate() {
            *e = ((input[i * 4] as u32) << 24)
                | ((input[i * 4 + 1] as u32) << 16)
                | ((input[i * 4 + 2] as u32) << 8)
                | (input[i * 4 + 3] as u32);
        }
        W256(w)
    }

    #[inline(always)]
    fn Ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn Maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn Sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn Sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    #[inline(always)]
    fn M(&mut self, a: usize, b: usize, c: usize, d: usize) {
        let w = &mut self.0;
        w[a] = w[a]
            .wrapping_add(Self::sigma1(w[b]))
            .wrapping_add(w[c])
            .wrapping_add(Self::sigma0(w[d]));
    }

    #[inline(always)]
    fn expand(&mut self) {
        self.M(0, (0 + 14) & 15, (0 + 9) & 15, (0 + 1) & 15);
        self.M(1, (1 + 14) & 15, (1 + 9) & 15, (1 + 1) & 15);
        self.M(2, (2 + 14) & 15, (2 + 9) & 15, (2 + 1) & 15);
        self.M(3, (3 + 14) & 15, (3 + 9) & 15, (3 + 1) & 15);
        self.M(4, (4 + 14) & 15, (4 + 9) & 15, (4 + 1) & 15);
        self.M(5, (5 + 14) & 15, (5 + 9) & 15, (5 + 1) & 15);
        self.M(6, (6 + 14) & 15, (6 + 9) & 15, (6 + 1) & 15);
        self.M(7, (7 + 14) & 15, (7 + 9) & 15, (7 + 1) & 15);
        self.M(8, (8 + 14) & 15, (8 + 9) & 15, (8 + 1) & 15);
        self.M(9, (9 + 14) & 15, (9 + 9) & 15, (9 + 1) & 15);
        self.M(10, (10 + 14) & 15, (10 + 9) & 15, (10 + 1) & 15);
        self.M(11, (11 + 14) & 15, (11 + 9) & 15, (11 + 1) & 15);
        self.M(12, (12 + 14) & 15, (12 + 9) & 15, (12 + 1) & 15);
        self.M(13, (13 + 14) & 15, (13 + 9) & 15, (13 + 1) & 15);
        self.M(14, (14 + 14) & 15, (14 + 9) & 15, (14 + 1) & 15);
        self.M(15, (15 + 14) & 15, (15 + 9) & 15, (15 + 1) & 15);
    }

    #[inline(always)]
    fn F(&mut self, state: &mut State256, i: usize, k: u32) {
        let t = &mut state.0;
        t[(16 - i + 7) & 7] = t[(16 - i + 7) & 7]
            .wrapping_add(Self::Sigma1(t[(16 - i + 4) & 7]))
            .wrapping_add(Self::Ch(
                t[(16 - i + 4) & 7],
                t[(16 - i + 5) & 7],
                t[(16 - i + 6) & 7],
            ))
            .wrapping_add(k)
            .wrapping_add(self.0[i]);
        t[(16 - i + 3) & 7] = t[(16 - i + 3) & 7].wrapping_add(t[(16 - i + 7) & 7]);
        t[(16 - i + 7) & 7] = t[(16 - i + 7) & 7]
            .wrapping_add(Self::Sigma0(t[(16 - i + 0) & 7]))
            .wrapping_add(Self::Maj(
                t[(16 - i + 0) & 7],
                t[(16 - i + 1) & 7],
                t[(16 - i + 2) & 7],
            ));
    }

    #[inline(always)]
    fn G(&mut self, state: &mut State256, s: usize) {
        const ROUND_CONSTANTS: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let rc = &ROUND_CONSTANTS[s * 16..];
        self.F(state, 0, rc[0]);
        self.F(state, 1, rc[1]);
        self.F(state, 2, rc[2]);
        self.F(state, 3, rc[3]);
        self.F(state, 4, rc[4]);
        self.F(state, 5, rc[5]);
        self.F(state, 6, rc[6]);
        self.F(state, 7, rc[7]);
        self.F(state, 8, rc[8]);
        self.F(state, 9, rc[9]);
        self.F(state, 10, rc[10]);
        self.F(state, 11, rc[11]);
        self.F(state, 12, rc[12]);
        self.F(state, 13, rc[13]);
        self.F(state, 14, rc[14]);
        self.F(state, 15, rc[15]);
    }
}

impl State256 {
    fn new() -> Self {
        const IV: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        State256(IV)
    }

    #[inline(always)]
    fn add(&mut self, x: &State256) {
        let sx = &mut self.0;
        let ex = &x.0;
        sx[0] = sx[0].wrapping_add(ex[0]);
        sx[1] = sx[1].wrapping_add(ex[1]);
        sx[2] = sx[2].wrapping_add(ex[2]);
        sx[3] = sx[3].wrapping_add(ex[3]);
        sx[4] = sx[4].wrapping_add(ex[4]);
        sx[5] = sx[5].wrapping_add(ex[5]);
        sx[6] = sx[6].wrapping_add(ex[6]);
        sx[7] = sx[7].wrapping_add(ex[7]);
    }

    fn store(&self, out: &mut [u8]) {
        for (i, &e) in self.0.iter().enumerate() {
            out[i * 4] = (e >> 24) as u8;
            out[i * 4 + 1] = (e >> 16) as u8;
            out[i * 4 + 2] = (e >> 8) as u8;
            out[i * 4 + 3] = e as u8;
        }
    }

    fn blocks(&mut self, mut input: &[u8]) -> usize {
        let mut t = *self;
        let mut inlen = input.len();
        while inlen >= 64 {
            let mut w = W256::new(input);
            w.G(&mut t, 0);
            w.expand();
            w.G(&mut t, 1);
            w.expand();
            w.G(&mut t, 2);
            w.expand();
            w.G(&mut t, 3);
            t.add(self);
            self.0 = t.0;
            input = &input[64..];
            inlen -= 64;
        }
        inlen
    }
}

#[derive(Copy, Clone)]
pub struct Sha256 {
    state: State256,
    w: [u8; 64],
    r: usize,
    len: usize,
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 {
            state: State256::new(),
            r: 0,
            w: [0u8; 64],
            len: 0,
        }
    }

    /// Absorb content
    pub fn update<T: AsRef<[u8]>>(&mut self, input: T) {
        let input = input.as_ref();
        let mut n = input.len();
        self.len += n;
        let av = 64 - self.r;
        let tc = ::core::cmp::min(n, av);
        self.w[self.r..self.r + tc].copy_from_slice(&input[0..tc]);
        self.r += tc;
        n -= tc;
        let pos = tc;
        if self.r == 64 {
            self.state.blocks(&self.w);
            self.r = 0;
        }
        if self.r == 0 && n > 0 {
            let rb = self.state.blocks(&input[pos..]);
            if rb > 0 {
                self.w[..rb].copy_from_slice(&input[pos + n - rb..]);
                self.r = rb;
            }
        }
    }

    /// Compute SHA-256(absorbed content)
    pub fn finalize(mut self) -> [u8; 32] {
        let mut padded = [0u8; 128];
        padded[..self.r].copy_from_slice(&self.w[..self.r]);
        padded[self.r] = 0x80;
        let r = if self.r < 56 { 64 } else { 128 };
        let bits = self.len * 8;
        for i in 0..8 {
            padded[r - 8 + i] = (bits as u64 >> (56 - i * 8)) as u8;
        }
        self.state.blocks(&padded[..r]);
        let mut out = [0u8; 32];
        self.state.store(&mut out);
        out
    }

    /// Compute SHA-256(`input`)
    pub fn hash<T: AsRef<[u8]>>(input: T) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(input);
        h.finalize()
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

// SHA-512 implementation (64-bit words)
struct W512([u64; 16]);

#[derive(Copy, Clone)]
struct State512([u64; 8]);

impl W512 {
    fn new(input: &[u8]) -> Self {
        let mut w = [0u64; 16];
        for (i, e) in w.iter_mut().enumerate() {
            *e = load_be(input, i * 8)
        }
        W512(w)
    }

    #[inline(always)]
    fn Ch(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (!x & z)
    }
    #[inline(always)]
    fn Maj(x: u64, y: u64, z: u64) -> u64 {
        (x & y) ^ (x & z) ^ (y & z)
    }
    #[inline(always)]
    fn Sigma0(x: u64) -> u64 {
        x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
    }

    #[inline(always)]
    fn Sigma1(x: u64) -> u64 {
        x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
    }

    #[inline(always)]
    fn sigma0(x: u64) -> u64 {
        x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
    }
    #[inline(always)]
    fn sigma1(x: u64) -> u64 {
        x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
    }
    #[inline(always)]
    fn M(&mut self, a: usize, b: usize, c: usize, d: usize) {
        let w = &mut self.0;
        w[a] = w[a]
            .wrapping_add(Self::sigma1(w[b]))
            .wrapping_add(w[c])
            .wrapping_add(Self::sigma0(w[d]));
    }
    #[inline(always)]
    fn expand(&mut self) {
        self.M(0, (0 + 14) & 15, (0 + 9) & 15, (0 + 1) & 15);
        self.M(1, (1 + 14) & 15, (1 + 9) & 15, (1 + 1) & 15);
        self.M(2, (2 + 14) & 15, (2 + 9) & 15, (2 + 1) & 15);
        self.M(3, (3 + 14) & 15, (3 + 9) & 15, (3 + 1) & 15);
        self.M(4, (4 + 14) & 15, (4 + 9) & 15, (4 + 1) & 15);
        self.M(5, (5 + 14) & 15, (5 + 9) & 15, (5 + 1) & 15);
        self.M(6, (6 + 14) & 15, (6 + 9) & 15, (6 + 1) & 15);
        self.M(7, (7 + 14) & 15, (7 + 9) & 15, (7 + 1) & 15);
        self.M(8, (8 + 14) & 15, (8 + 9) & 15, (8 + 1) & 15);
        self.M(9, (9 + 14) & 15, (9 + 9) & 15, (9 + 1) & 15);
        self.M(10, (10 + 14) & 15, (10 + 9) & 15, (10 + 1) & 15);
        self.M(11, (11 + 14) & 15, (11 + 9) & 15, (11 + 1) & 15);
        self.M(12, (12 + 14) & 15, (12 + 9) & 15, (12 + 1) & 15);
        self.M(13, (13 + 14) & 15, (13 + 9) & 15, (13 + 1) & 15);
        self.M(14, (14 + 14) & 15, (14 + 9) & 15, (14 + 1) & 15);
        self.M(15, (15 + 14) & 15, (15 + 9) & 15, (15 + 1) & 15);
    }

    #[inline(always)]
    fn F(&mut self, state: &mut State512, i: usize, k: u64) {
        let t = &mut state.0;
        t[(16 - i + 7) & 7] = t[(16 - i + 7) & 7]
            .wrapping_add(Self::Sigma1(t[(16 - i + 4) & 7]))
            .wrapping_add(Self::Ch(
                t[(16 - i + 4) & 7],
                t[(16 - i + 5) & 7],
                t[(16 - i + 6) & 7],
            ))
            .wrapping_add(k)
            .wrapping_add(self.0[i]);
        t[(16 - i + 3) & 7] = t[(16 - i + 3) & 7].wrapping_add(t[(16 - i + 7) & 7]);
        t[(16 - i + 7) & 7] = t[(16 - i + 7) & 7]
            .wrapping_add(Self::Sigma0(t[(16 - i + 0) & 7]))
            .wrapping_add(Self::Maj(
                t[(16 - i + 0) & 7],
                t[(16 - i + 1) & 7],
                t[(16 - i + 2) & 7],
            ));
    }

    #[inline(always)]
    fn G(&mut self, state: &mut State512, s: usize) {
        const ROUND_CONSTANTS: [u64; 80] = [
            0x428a2f98d728ae22,
            0x7137449123ef65cd,
            0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc,
            0x3956c25bf348b538,
            0x59f111f1b605d019,
            0x923f82a4af194f9b,
            0xab1c5ed5da6d8118,
            0xd807aa98a3030242,
            0x12835b0145706fbe,
            0x243185be4ee4b28c,
            0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f,
            0x80deb1fe3b1696b1,
            0x9bdc06a725c71235,
            0xc19bf174cf692694,
            0xe49b69c19ef14ad2,
            0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5,
            0x240ca1cc77ac9c65,
            0x2de92c6f592b0275,
            0x4a7484aa6ea6e483,
            0x5cb0a9dcbd41fbd4,
            0x76f988da831153b5,
            0x983e5152ee66dfab,
            0xa831c66d2db43210,
            0xb00327c898fb213f,
            0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2,
            0xd5a79147930aa725,
            0x06ca6351e003826f,
            0x142929670a0e6e70,
            0x27b70a8546d22ffc,
            0x2e1b21385c26c926,
            0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df,
            0x650a73548baf63de,
            0x766a0abb3c77b2a8,
            0x81c2c92e47edaee6,
            0x92722c851482353b,
            0xa2bfe8a14cf10364,
            0xa81a664bbc423001,
            0xc24b8b70d0f89791,
            0xc76c51a30654be30,
            0xd192e819d6ef5218,
            0xd69906245565a910,
            0xf40e35855771202a,
            0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8,
            0x1e376c085141ab53,
            0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63,
            0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc,
            0x78a5636f43172f60,
            0x84c87814a1f0ab72,
            0x8cc702081a6439ec,
            0x90befffa23631e28,
            0xa4506cebde82bde9,
            0xbef9a3f7b2c67915,
            0xc67178f2e372532b,
            0xca273eceea26619c,
            0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e,
            0xf57d4f7fee6ed178,
            0x06f067aa72176fba,
            0x0a637dc5a2c898a6,
            0x113f9804bef90dae,
            0x1b710b35131c471b,
            0x28db77f523047d84,
            0x32caab7b40c72493,
            0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6,
            0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec,
            0x6c44198c4a475817,
        ];
        let rc = &ROUND_CONSTANTS[s * 16..];
        self.F(state, 0, rc[0]);
        self.F(state, 1, rc[1]);
        self.F(state, 2, rc[2]);
        self.F(state, 3, rc[3]);
        self.F(state, 4, rc[4]);
        self.F(state, 5, rc[5]);
        self.F(state, 6, rc[6]);
        self.F(state, 7, rc[7]);
        self.F(state, 8, rc[8]);
        self.F(state, 9, rc[9]);
        self.F(state, 10, rc[10]);
        self.F(state, 11, rc[11]);
        self.F(state, 12, rc[12]);
        self.F(state, 13, rc[13]);
        self.F(state, 14, rc[14]);
        self.F(state, 15, rc[15]);
    }
}

impl State512 {
    fn new() -> Self {
        const IV: [u8; 64] = [
            0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85, 0x84, 0xca,
            0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a,
            0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05,
            0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b,
            0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79,
        ];
        let mut t = [0u64; 8];
        for (i, e) in t.iter_mut().enumerate() {
            *e = load_be(&IV, i * 8)
        }
        State512(t)
    }
    #[inline(always)]
    fn add(&mut self, x: &State512) {
        let sx = &mut self.0;
        let ex = &x.0;
        sx[0] = sx[0].wrapping_add(ex[0]);
        sx[1] = sx[1].wrapping_add(ex[1]);
        sx[2] = sx[2].wrapping_add(ex[2]);
        sx[3] = sx[3].wrapping_add(ex[3]);
        sx[4] = sx[4].wrapping_add(ex[4]);
        sx[5] = sx[5].wrapping_add(ex[5]);
        sx[6] = sx[6].wrapping_add(ex[6]);
        sx[7] = sx[7].wrapping_add(ex[7]);
    }

    fn store(&self, out: &mut [u8]) {
        for (i, &e) in self.0.iter().enumerate() {
            store_be(out, i * 8, e);
        }
    }

    fn blocks(&mut self, mut input: &[u8]) -> usize {
        let mut t = *self;
        let mut inlen = input.len();
        while inlen >= 128 {
            let mut w = W512::new(input);
            w.G(&mut t, 0);
            w.expand();
            w.G(&mut t, 1);
            w.expand();
            w.G(&mut t, 2);
            w.expand();
            w.G(&mut t, 3);
            w.expand();
            w.G(&mut t, 4);
            t.add(self);
            self.0 = t.0;
            input = &input[128..];
            inlen -= 128;
        }
        inlen
    }
}

#[derive(Copy, Clone)]
pub struct Hash {
    state: State512,
    w: [u8; 128],
    r: usize,
    len: usize,
}

impl Hash {
    pub fn new() -> Hash {
        Hash {
            state: State512::new(),
            r: 0,
            w: [0u8; 128],
            len: 0,
        }
    }

    /// Absorb content
    pub fn update<T: AsRef<[u8]>>(&mut self, input: T) {
        let input = input.as_ref();
        let mut n = input.len();
        self.len += n;
        let av = 128 - self.r;
        let tc = ::core::cmp::min(n, av);
        self.w[self.r..self.r + tc].copy_from_slice(&input[0..tc]);
        self.r += tc;
        n -= tc;
        let pos = tc;
        if self.r == 128 {
            self.state.blocks(&self.w);
            self.r = 0;
        }
        if self.r == 0 && n > 0 {
            let rb = self.state.blocks(&input[pos..]);
            if rb > 0 {
                self.w[..rb].copy_from_slice(&input[pos + n - rb..]);
                self.r = rb;
            }
        }
    }

    /// Compute SHA512(absorbed content)
    pub fn finalize(mut self) -> [u8; 64] {
        let mut padded = [0u8; 256];
        padded[..self.r].copy_from_slice(&self.w[..self.r]);
        padded[self.r] = 0x80;
        let r = if self.r < 112 { 128 } else { 256 };
        let bits = self.len * 8;
        for i in 0..8 {
            padded[r - 8 + i] = (bits as u64 >> (56 - i * 8)) as u8;
        }
        self.state.blocks(&padded[..r]);
        let mut out = [0u8; 64];
        self.state.store(&mut out);
        out
    }

    /// Compute SHA512(`input`)
    pub fn hash<T: AsRef<[u8]>>(input: T) -> [u8; 64] {
        let mut h = Hash::new();
        h.update(input);
        h.finalize()
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::new()
    }
}

use core::cmp::{Eq, PartialEq};
use core::ops::{Add, Mul, Sub};
use std::cmp::min;
use std::{fmt, ptr};
use std::ops::{Deref, DerefMut};
use std::sync::atomic;
use crate::err;
use crate::error::*;
/// A seed, which a key pair can be derived from.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Seed([u8; Seed::BYTES]);

impl From<[u8; 32]> for Seed {
    fn from(seed: [u8; 32]) -> Self {
        Seed(seed)
    }
}

impl Seed {
    /// Number of raw bytes in a seed.
    pub const BYTES: usize = 32;

    /// Creates a seed from raw bytes.
    pub fn new(seed: [u8; Seed::BYTES]) -> Self {
        Seed(seed)
    }

    /// Creates a seed from a slice.
    pub fn from_slice(seed: &[u8]) -> Result<Self> {
        let mut seed_ = [0u8; Seed::BYTES];
        if seed.len() != seed_.len() {
            return Err(err!(Crypto,"Invalid Seed"));
        }
        seed_.copy_from_slice(seed);
        Ok(Seed::new(seed_))
    }

    /// Tentatively overwrite the content of the seed with zeros.
    pub fn wipe(self) {
        let mut seed = self;
        Mem::wipe(&mut seed.0)
    }

    /// Overwrite the content of the seed with zeros in-place.
    pub fn wipe_mut(&mut self) {
        Mem::wipe(&mut self.0)
    }
}

impl Default for Seed {
    /// Generates a random seed.
    fn default() -> Self {
        let mut seed = [0u8; Seed::BYTES];
        rand::fill(&mut seed);
        Seed(seed)
    }
}

impl Seed {
    /// Generates a random seed.
    pub fn generate() -> Self {
        Seed::default()
    }
}

impl Deref for Seed {
    type Target = [u8; Seed::BYTES];

    /// Returns a seed as raw bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Seed {
    /// Returns a seed as mutable raw bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub(crate) struct Mem;

impl Mem {
    #[inline]
    pub fn wipe<T: Default>(x: &mut [T]) {
        for i in 0..x.len() {
            unsafe {
                ptr::write_volatile(x.as_mut_ptr().add(i), T::default());
            }
        }
        atomic::compiler_fence(atomic::Ordering::SeqCst);
        atomic::fence(atomic::Ordering::SeqCst);
    }
}
/// A public key.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct PublicKey([u8; PublicKey::BYTES]);

impl PublicKey {
    /// Number of raw bytes in a public key.
    pub const BYTES: usize = 32;

    /// Creates a public key from raw bytes.
    pub fn new(pk: [u8; PublicKey::BYTES]) -> Self {
        PublicKey(pk)
    }

    /// Creates a public key from a slice.
    pub fn from_slice(pk: &[u8]) -> Result<Self> {
        let mut pk_ = [0u8; PublicKey::BYTES];
        if pk.len() != pk_.len() {
            return Err(err!(Crypto,"Invalid Public Key"));
        }
        pk_.copy_from_slice(pk);
        Ok(PublicKey::new(pk_))
    }
}

impl Deref for PublicKey {
    type Target = [u8; PublicKey::BYTES];

    /// Returns a public key as bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PublicKey {
    /// Returns a public key as mutable bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A secret key.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SecretKey([u8; SecretKey::BYTES]);

impl SecretKey {
    /// Number of bytes in a secret key.
    pub const BYTES: usize = 32 + PublicKey::BYTES;

    /// Creates a secret key from raw bytes.
    pub fn new(sk: [u8; SecretKey::BYTES]) -> Self {
        SecretKey(sk)
    }

    /// Creates a secret key from a slice.
    pub fn from_slice(sk: &[u8]) -> Result<Self> {
        let mut sk_ = [0u8; SecretKey::BYTES];
        if sk.len() != sk_.len() {
            return Err(err!(Crypto,"Invalid Secret Key"));
        }
        sk_.copy_from_slice(sk);
        Ok(SecretKey::new(sk_))
    }

    /// Returns the public counterpart of a secret key.
    pub fn public_key(&self) -> PublicKey {
        let mut pk = [0u8; PublicKey::BYTES];
        pk.copy_from_slice(&self[Seed::BYTES..]);
        PublicKey(pk)
    }

    /// Returns the seed of a secret key.
    pub fn seed(&self) -> Seed {
        Seed::from_slice(&self[0..Seed::BYTES]).unwrap()
    }

    /// Returns `Ok(())` if the given public key is the public counterpart of
    /// this secret key.
    /// Returns `Err(Error::InvalidPublicKey)` otherwise.
    /// The public key is recomputed (not just copied) from the secret key,
    /// so this will detect corruption of the secret key.
    pub fn validate_public_key(&self, pk: &PublicKey) -> Result<()> {
        let kp = KeyPair::from_seed(self.seed());
        if kp.pk != *pk {
            return Err(err!(Crypto,"Invalid Public Key"));
        }
        Ok(())
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        Mem::wipe(&mut self.0)
    }
}

impl Deref for SecretKey {
    type Target = [u8; SecretKey::BYTES];

    /// Returns a secret key as bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SecretKey {
    /// Returns a secret key as mutable bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// A key pair.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct KeyPair {
    /// Public key part of the key pair.
    pub pk: PublicKey,
    /// Secret key part of the key pair.
    pub sk: SecretKey,
}

/// An Ed25519 signature.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct Signature([u8; Signature::BYTES]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{:x?}", &self.0))
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = OcfgError;

    fn try_from(slice: &[u8]) -> std::result::Result<Self, Self::Error> {
        Signature::from_slice(slice)
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Signature {
    /// Number of raw bytes in a signature.
    pub const BYTES: usize = 64;

    /// Creates a signature from raw bytes.
    pub fn new(bytes: [u8; Signature::BYTES]) -> Self {
        Signature(bytes)
    }

    /// Creates a signature key from a slice.
    pub fn from_slice(signature: &[u8]) -> Result<Self> {
        let mut signature_ = [0u8; Signature::BYTES];
        if signature.len() != signature_.len() {
            return Err(err!(Crypto,"Invalid Signature"));
        }
        signature_.copy_from_slice(signature);
        Ok(Signature::new(signature_))
    }
}

impl Deref for Signature {
    type Target = [u8; Signature::BYTES];

    /// Returns a signture as bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Signature {
    /// Returns a signature as mutable bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// The state of a streaming verification operation.
#[derive(Clone)]
pub struct VerifyingState {
    hasher: Hash,
    signature: Signature,
    a: GeP3,
}

impl Drop for VerifyingState {
    fn drop(&mut self) {
        Mem::wipe(&mut self.signature.0);
    }
}

impl VerifyingState {
    fn new(pk: &PublicKey, signature: &Signature) -> Result<Self> {
        let r = &signature[0..32];
        let s = &signature[32..64];
        sc_reject_noncanonical(s)?;
        if is_identity(pk) || pk.iter().fold(0, |acc, x| acc | x) == 0 {
            return Err(err!(Crypto,"Weak Public Key"));
        }
        let a = match GeP3::from_bytes_negate_vartime(pk) {
            Some(g) => g,
            None => {
                return Err(err!(Crypto,"Invalid Public Key"));
            }
        };
        let mut hasher = Hash::new();
        hasher.update(r);
        hasher.update(&pk[..]);
        Ok(VerifyingState {
            hasher,
            signature: *signature,
            a,
        })
    }

    /// Appends data to the message being verified.
    pub fn absorb(&mut self, chunk: impl AsRef<[u8]>) {
        self.hasher.update(chunk)
    }

    /// Verifies the signature and return it.
    pub fn verify(&self) -> Result<()> {
        let mut expected_r_bytes = [0u8; 32];
        expected_r_bytes.copy_from_slice(&self.signature[0..32]);
        let expected_r =
            GeP3::from_bytes_vartime(&expected_r_bytes).ok_or(err!(Crypto, "Invalid Signature"))?;
        let s = &self.signature[32..64];

        let mut hash = self.hasher.finalize();
        sc_reduce(&mut hash);

        let r = GeP2::double_scalarmult_vartime(hash.as_ref(), self.a, s);
        if (expected_r - GeP3::from(r)).has_small_order() {
            Ok(())
        } else {
            Err(err!(Crypto, "Signature Mismatch"))
        }
    }
}

impl PublicKey {
    /// Verify the signature of a multi-part message (streaming).
    pub fn verify_incremental(&self, signature: &Signature) -> Result<VerifyingState> {
        VerifyingState::new(self, signature)
    }

    /// Verifies that the signature `signature` is valid for the message
    /// `message`.
    pub fn verify(&self, message: impl AsRef<[u8]>, signature: &Signature) -> Result<()> {
        let mut st = VerifyingState::new(self, signature)?;
        st.absorb(message);
        st.verify()
    }
}

/// The state of a streaming signature operation.
#[derive(Clone)]
pub struct SigningState {
    hasher: Hash,
    az: [u8; 64],
    nonce: [u8; 64],
}

impl Drop for SigningState {
    fn drop(&mut self) {
        Mem::wipe(&mut self.az);
        Mem::wipe(&mut self.nonce);
    }
}

impl SigningState {
    fn new(nonce: [u8; 64], az: [u8; 64], pk_: &[u8]) -> Self {
        let mut prefix: [u8; 64] = [0; 64];
        let r = ge_scalarmult_base(&nonce[0..32]);
        prefix[0..32].copy_from_slice(&r.to_bytes()[..]);
        prefix[32..64].copy_from_slice(pk_);

        let mut st = Hash::new();
        st.update(prefix);

        SigningState {
            hasher: st,
            nonce,
            az,
        }
    }

    /// Appends data to the message being signed.
    pub fn absorb(&mut self, chunk: impl AsRef<[u8]>) {
        self.hasher.update(chunk)
    }

    /// Computes the signature and return it.
    pub fn sign(&self) -> Signature {
        let mut signature: [u8; 64] = [0; 64];
        let r = ge_scalarmult_base(&self.nonce[0..32]);
        signature[0..32].copy_from_slice(&r.to_bytes()[..]);
        let mut hram = self.hasher.finalize();
        sc_reduce(&mut hram);
        sc_muladd(
            &mut signature[32..64],
            &hram[0..32],
            &self.az[0..32],
            &self.nonce[0..32],
        );
        Signature(signature)
    }
}

impl SecretKey {
    /// Sign a multi-part message (streaming API).
    /// It is critical for `noise` to never repeat.
    pub fn sign_incremental(&self, noise: Noise) -> SigningState {
        let seed = &self[0..32];
        let pk = &self[32..64];
        let az: [u8; 64] = {
            let mut hash_output = Hash::hash(seed);
            hash_output[0] &= 248;
            hash_output[31] &= 63;
            hash_output[31] |= 64;
            hash_output
        };
        let mut st = Hash::new();
        {
            let additional_noise = Noise::generate();
            st.update(additional_noise.as_ref());
        }
        st.update(noise.as_ref());
        st.update(seed);
        let nonce = st.finalize();
        SigningState::new(nonce, az, pk)
    }

    /// Computes a signature for the message `message` using the secret key.
    /// The noise parameter is optional, but recommended in order to mitigate
    /// fault attacks.
    pub fn sign(&self, message: impl AsRef<[u8]>, noise: Option<Noise>) -> Signature {
        let seed = &self[0..32];
        let pk = &self[32..64];
        let az: [u8; 64] = {
            let mut hash_output = Hash::hash(seed);
            hash_output[0] &= 248;
            hash_output[31] &= 63;
            hash_output[31] |= 64;
            hash_output
        };
        let nonce = {
            let mut hasher = Hash::new();
            if let Some(noise) = noise {
                hasher.update(&noise[..]);
                hasher.update(&az[..]);
            } else {
                hasher.update(&az[32..64]);
            }
            hasher.update(&message);
            let mut hash_output = hasher.finalize();
            sc_reduce(&mut hash_output[0..64]);
            hash_output
        };
        let mut st = SigningState::new(nonce, az, pk);
        st.absorb(&message);
        let signature = st.sign();

        signature
    }
}

impl KeyPair {
    /// Number of bytes in a key pair.
    pub const BYTES: usize = SecretKey::BYTES;

    /// Generates a new key pair.
    pub fn generate() -> KeyPair {
        KeyPair::from_seed(Seed::default())
    }

    /// Generates a new key pair using a secret seed.
    pub fn from_seed(seed: Seed) -> KeyPair {
        if seed.iter().fold(0, |acc, x| acc | x) == 0 {
            panic!("All-zero seed");
        }
        let (scalar, _) = {
            let hash_output = Hash::hash(&seed[..]);
            KeyPair::split(&hash_output, false, true)
        };
        let pk = ge_scalarmult_base(&scalar).to_bytes();
        let mut sk = [0u8; 64];
        sk[0..32].copy_from_slice(&*seed);
        sk[32..64].copy_from_slice(&pk);
        KeyPair {
            pk: PublicKey(pk),
            sk: SecretKey(sk),
        }
    }

    /// Creates a key pair from a slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let sk = SecretKey::from_slice(bytes)?;
        let pk = sk.public_key();
        Ok(KeyPair { pk, sk })
    }

    /// Clamp a scalar.
    pub fn clamp(scalar: &mut [u8]) {
        scalar[0] &= 248;
        scalar[31] &= 63;
        scalar[31] |= 64;
    }

    /// Split a serialized representation of a key pair into a secret scalar and
    /// a prefix.
    pub fn split(bytes: &[u8; 64], reduce: bool, clamp: bool) -> ([u8; 32], [u8; 32]) {
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&bytes[0..32]);
        if clamp {
            Self::clamp(&mut scalar);
        }
        if reduce {
            sc_reduce32(&mut scalar);
        }
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&bytes[32..64]);
        (scalar, prefix)
    }

    /// Check that the public key is valid for the secret key.
    pub fn validate(&self) -> Result<()> {
        self.sk.validate_public_key(&self.pk)
    }
}

impl Deref for KeyPair {
    type Target = [u8; KeyPair::BYTES];

    /// Returns a key pair as bytes.
    fn deref(&self) -> &Self::Target {
        &self.sk
    }
}

impl DerefMut for KeyPair {
    /// Returns a key pair as mutable bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sk
    }
}

/// Noise, for non-deterministic signatures.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Noise([u8; Noise::BYTES]);

impl Noise {
    /// Number of raw bytes for a noise component.
    pub const BYTES: usize = 16;

    /// Creates a new noise component from raw bytes.
    pub fn new(noise: [u8; Noise::BYTES]) -> Self {
        Noise(noise)
    }

    /// Creates noise from a slice.
    pub fn from_slice(noise: &[u8]) -> Result<Self> {
        let mut noise_ = [0u8; Noise::BYTES];
        if noise.len() != noise_.len() {
            return Err(err!(Crypto,"Invalid Noise"));
        }
        noise_.copy_from_slice(noise);
        Ok(Noise::new(noise_))
    }
}

impl Deref for Noise {
    type Target = [u8; Noise::BYTES];

    /// Returns the noise as bytes.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Noise {
    /// Returns the noise as mutable bytes.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Default for Noise {
    /// Generates random noise.
    fn default() -> Self {
        let mut noise = [0u8; Noise::BYTES];
        rand::fill(&mut noise);
        Noise(noise)
    }
}

impl Noise {
    /// Generates random noise.
    pub fn generate() -> Self {
        Noise::default()
    }
}
#[inline(always)]
pub fn fiat_25519_addcarryx_u51(
    out1: &mut u64,
    out2: &mut u8,
    arg1: u8,
    arg2: u64,
    arg3: u64,
) {
    let x1: u64 = (((arg1 as u64).wrapping_add(arg2)).wrapping_add(arg3));
    let x2: u64 = (x1 & 0x7ffffffffffff);
    let x3: u8 = ((x1 >> 51) as u8);
    *out1 = x2;
    *out2 = x3;
}

#[inline(always)]
pub fn fiat_25519_subborrowx_u51(
    out1: &mut u64,
    out2: &mut u8,
    arg1: u8,
    arg2: u64,
    arg3: u64,
) {
    let x1: i64 = ((((((arg2 as i128).wrapping_sub(arg1 as i128)) as i64) as i128)
        .wrapping_sub(arg3 as i128)) as i64);
    let x2: i8 = ((x1 >> 51) as i8);
    let x3: u64 = (((x1 as i128) & 0x7ffffffffffff_i128) as u64);
    *out1 = x3;
    *out2 = ((0x0_i8.wrapping_sub(x2 as i8)) as u8);
}

#[inline(always)]
pub fn fiat_25519_cmovznz_u64(out1: &mut u64, arg1: u8, arg2: u64, arg3: u64) {
    let x1: u8 = (!(!arg1));
    let x2: u64 = (((((0x0_i8.wrapping_sub(x1 as i8)) as i8) as i128)
        & 0xffffffffffffffff_i128) as u64);
    let x3: u64 = ((x2 & arg3) | ((!x2) & arg2));
    *out1 = x3;
}

#[inline(always)]
pub fn fiat_25519_carry_mul(out1: &mut [u64; 5], arg1: &[u64; 5], arg2: &[u64; 5]) {
    let x1: u128 = (((arg1[4]) as u128).wrapping_mul(((arg2[4]).wrapping_mul(0x13)) as u128));
    let x2: u128 = (((arg1[4]) as u128).wrapping_mul(((arg2[3]).wrapping_mul(0x13)) as u128));
    let x3: u128 = (((arg1[4]) as u128).wrapping_mul(((arg2[2]).wrapping_mul(0x13)) as u128));
    let x4: u128 = (((arg1[4]) as u128).wrapping_mul(((arg2[1]).wrapping_mul(0x13)) as u128));
    let x5: u128 = (((arg1[3]) as u128).wrapping_mul(((arg2[4]).wrapping_mul(0x13)) as u128));
    let x6: u128 = (((arg1[3]) as u128).wrapping_mul(((arg2[3]).wrapping_mul(0x13)) as u128));
    let x7: u128 = (((arg1[3]) as u128).wrapping_mul(((arg2[2]).wrapping_mul(0x13)) as u128));
    let x8: u128 = (((arg1[2]) as u128).wrapping_mul(((arg2[4]).wrapping_mul(0x13)) as u128));
    let x9: u128 = (((arg1[2]) as u128).wrapping_mul(((arg2[3]).wrapping_mul(0x13)) as u128));
    let x10: u128 = (((arg1[1]) as u128).wrapping_mul(((arg2[4]).wrapping_mul(0x13)) as u128));
    let x11: u128 = (((arg1[4]) as u128).wrapping_mul((arg2[0]) as u128));
    let x12: u128 = (((arg1[3]) as u128).wrapping_mul((arg2[1]) as u128));
    let x13: u128 = (((arg1[3]) as u128).wrapping_mul((arg2[0]) as u128));
    let x14: u128 = (((arg1[2]) as u128).wrapping_mul((arg2[2]) as u128));
    let x15: u128 = (((arg1[2]) as u128).wrapping_mul((arg2[1]) as u128));
    let x16: u128 = (((arg1[2]) as u128).wrapping_mul((arg2[0]) as u128));
    let x17: u128 = (((arg1[1]) as u128).wrapping_mul((arg2[3]) as u128));
    let x18: u128 = (((arg1[1]) as u128).wrapping_mul((arg2[2]) as u128));
    let x19: u128 = (((arg1[1]) as u128).wrapping_mul((arg2[1]) as u128));
    let x20: u128 = (((arg1[1]) as u128).wrapping_mul((arg2[0]) as u128));
    let x21: u128 = (((arg1[0]) as u128).wrapping_mul((arg2[4]) as u128));
    let x22: u128 = (((arg1[0]) as u128).wrapping_mul((arg2[3]) as u128));
    let x23: u128 = (((arg1[0]) as u128).wrapping_mul((arg2[2]) as u128));
    let x24: u128 = (((arg1[0]) as u128).wrapping_mul((arg2[1]) as u128));
    let x25: u128 = (((arg1[0]) as u128).wrapping_mul((arg2[0]) as u128));
    let x26: u128 =
        (x25.wrapping_add(x10.wrapping_add(x9.wrapping_add(x7.wrapping_add(x4)))));
    let x27: u64 = ((x26 >> 51) as u64);
    let x28: u64 = ((x26 & 0x7ffffffffffff_u128) as u64);
    let x29: u128 =
        (x21.wrapping_add(x17.wrapping_add(x14.wrapping_add(x12.wrapping_add(x11)))));
    let x30: u128 =
        (x22.wrapping_add(x18.wrapping_add(x15.wrapping_add(x13.wrapping_add(x1)))));
    let x31: u128 =
        (x23.wrapping_add(x19.wrapping_add(x16.wrapping_add(x5.wrapping_add(x2)))));
    let x32: u128 =
        (x24.wrapping_add(x20.wrapping_add(x8.wrapping_add(x6.wrapping_add(x3)))));
    let x33: u128 = ((x27 as u128).wrapping_add(x32));
    let x34: u64 = ((x33 >> 51) as u64);
    let x35: u64 = ((x33 & 0x7ffffffffffff_u128) as u64);
    let x36: u128 = ((x34 as u128).wrapping_add(x31));
    let x37: u64 = ((x36 >> 51) as u64);
    let x38: u64 = ((x36 & 0x7ffffffffffff_u128) as u64);
    let x39: u128 = ((x37 as u128).wrapping_add(x30));
    let x40: u64 = ((x39 >> 51) as u64);
    let x41: u64 = ((x39 & 0x7ffffffffffff_u128) as u64);
    let x42: u128 = ((x40 as u128).wrapping_add(x29));
    let x43: u64 = ((x42 >> 51) as u64);
    let x44: u64 = ((x42 & 0x7ffffffffffff_u128) as u64);
    let x45: u64 = (x43.wrapping_mul(0x13));
    let x46: u64 = (x28.wrapping_add(x45));
    let x47: u64 = (x46 >> 51);
    let x48: u64 = (x46 & 0x7ffffffffffff);
    let x49: u64 = (x47.wrapping_add(x35));
    let x50: u8 = ((x49 >> 51) as u8);
    let x51: u64 = (x49 & 0x7ffffffffffff);
    let x52: u64 = ((x50 as u64).wrapping_add(x38));
    out1[0] = x48;
    out1[1] = x51;
    out1[2] = x52;
    out1[3] = x41;
    out1[4] = x44;
}

#[inline(always)]
pub fn fiat_25519_carry_square(out1: &mut [u64; 5], arg1: &[u64; 5]) {
    let x1: u64 = ((arg1[4]).wrapping_mul(0x13));
    let x2: u64 = (x1.wrapping_mul(0x2));
    let x3: u64 = ((arg1[4]).wrapping_mul(0x2));
    let x4: u64 = ((arg1[3]).wrapping_mul(0x13));
    let x5: u64 = (x4.wrapping_mul(0x2));
    let x6: u64 = ((arg1[3]).wrapping_mul(0x2));
    let x7: u64 = ((arg1[2]).wrapping_mul(0x2));
    let x8: u64 = ((arg1[1]).wrapping_mul(0x2));
    let x9: u128 = (((arg1[4]) as u128).wrapping_mul(x1 as u128));
    let x10: u128 = (((arg1[3]) as u128).wrapping_mul(x2 as u128));
    let x11: u128 = (((arg1[3]) as u128).wrapping_mul(x4 as u128));
    let x12: u128 = (((arg1[2]) as u128).wrapping_mul(x2 as u128));
    let x13: u128 = (((arg1[2]) as u128).wrapping_mul(x5 as u128));
    let x14: u128 = (((arg1[2]) as u128).wrapping_mul((arg1[2]) as u128));
    let x15: u128 = (((arg1[1]) as u128).wrapping_mul(x2 as u128));
    let x16: u128 = (((arg1[1]) as u128).wrapping_mul(x6 as u128));
    let x17: u128 = (((arg1[1]) as u128).wrapping_mul(x7 as u128));
    let x18: u128 = (((arg1[1]) as u128).wrapping_mul((arg1[1]) as u128));
    let x19: u128 = (((arg1[0]) as u128).wrapping_mul(x3 as u128));
    let x20: u128 = (((arg1[0]) as u128).wrapping_mul(x6 as u128));
    let x21: u128 = (((arg1[0]) as u128).wrapping_mul(x7 as u128));
    let x22: u128 = (((arg1[0]) as u128).wrapping_mul(x8 as u128));
    let x23: u128 = (((arg1[0]) as u128).wrapping_mul((arg1[0]) as u128));
    let x24: u128 = (x23.wrapping_add(x15.wrapping_add(x13)));
    let x25: u64 = ((x24 >> 51) as u64);
    let x26: u64 = ((x24 & 0x7ffffffffffff_u128) as u64);
    let x27: u128 = (x19.wrapping_add(x16.wrapping_add(x14)));
    let x28: u128 = (x20.wrapping_add(x17.wrapping_add(x9)));
    let x29: u128 = (x21.wrapping_add(x18.wrapping_add(x10)));
    let x30: u128 = (x22.wrapping_add(x12.wrapping_add(x11)));
    let x31: u128 = ((x25 as u128).wrapping_add(x30));
    let x32: u64 = ((x31 >> 51) as u64);
    let x33: u64 = ((x31 & 0x7ffffffffffff_u128) as u64);
    let x34: u128 = ((x32 as u128).wrapping_add(x29));
    let x35: u64 = ((x34 >> 51) as u64);
    let x36: u64 = ((x34 & 0x7ffffffffffff_u128) as u64);
    let x37: u128 = ((x35 as u128).wrapping_add(x28));
    let x38: u64 = ((x37 >> 51) as u64);
    let x39: u64 = ((x37 & 0x7ffffffffffff_u128) as u64);
    let x40: u128 = ((x38 as u128).wrapping_add(x27));
    let x41: u64 = ((x40 >> 51) as u64);
    let x42: u64 = ((x40 & 0x7ffffffffffff_u128) as u64);
    let x43: u64 = (x41.wrapping_mul(0x13));
    let x44: u64 = (x26.wrapping_add(x43));
    let x45: u64 = (x44 >> 51);
    let x46: u64 = (x44 & 0x7ffffffffffff);
    let x47: u64 = (x45.wrapping_add(x33));
    let x48: u8 = ((x47 >> 51) as u8);
    let x49: u64 = (x47 & 0x7ffffffffffff);
    let x50: u64 = ((x48 as u64).wrapping_add(x36));
    out1[0] = x46;
    out1[1] = x49;
    out1[2] = x50;
    out1[3] = x39;
    out1[4] = x42;
}

#[inline(always)]
pub fn fiat_25519_carry(out1: &mut [u64; 5], arg1: &[u64; 5]) {
    let x1: u64 = (arg1[0]);
    let x2: u64 = ((x1 >> 51).wrapping_add(arg1[1]));
    let x3: u64 = ((x2 >> 51).wrapping_add(arg1[2]));
    let x4: u64 = ((x3 >> 51).wrapping_add(arg1[3]));
    let x5: u64 = ((x4 >> 51).wrapping_add(arg1[4]));
    let x6: u64 = ((x1 & 0x7ffffffffffff).wrapping_add((x5 >> 51).wrapping_mul(0x13)));
    let x7: u64 = ((((x6 >> 51) as u8) as u64).wrapping_add(x2 & 0x7ffffffffffff));
    let x8: u64 = (x6 & 0x7ffffffffffff);
    let x9: u64 = (x7 & 0x7ffffffffffff);
    let x10: u64 = ((((x7 >> 51) as u8) as u64).wrapping_add(x3 & 0x7ffffffffffff));
    let x11: u64 = (x4 & 0x7ffffffffffff);
    let x12: u64 = (x5 & 0x7ffffffffffff);
    out1[0] = x8;
    out1[1] = x9;
    out1[2] = x10;
    out1[3] = x11;
    out1[4] = x12;
}
#[inline(always)]
pub fn fiat_25519_add(out1: &mut [u64; 5], arg1: &[u64; 5], arg2: &[u64; 5]) {
    let x1: u64 = ((arg1[0]).wrapping_add(arg2[0]));
    let x2: u64 = ((arg1[1]).wrapping_add(arg2[1]));
    let x3: u64 = ((arg1[2]).wrapping_add(arg2[2]));
    let x4: u64 = ((arg1[3]).wrapping_add(arg2[3]));
    let x5: u64 = ((arg1[4]).wrapping_add(arg2[4]));
    out1[0] = x1;
    out1[1] = x2;
    out1[2] = x3;
    out1[3] = x4;
    out1[4] = x5;
}

#[inline(always)]
pub fn fiat_25519_sub(out1: &mut [u64; 5], arg1: &[u64; 5], arg2: &[u64; 5]) {
    let x1: u64 = ((0xfffffffffffdau64.wrapping_add(arg1[0])).wrapping_sub(arg2[0]));
    let x2: u64 = ((0xffffffffffffeu64.wrapping_add(arg1[1])).wrapping_sub(arg2[1]));
    let x3: u64 = ((0xffffffffffffeu64.wrapping_add(arg1[2])).wrapping_sub(arg2[2]));
    let x4: u64 = ((0xffffffffffffeu64.wrapping_add(arg1[3])).wrapping_sub(arg2[3]));
    let x5: u64 = ((0xffffffffffffeu64.wrapping_add(arg1[4])).wrapping_sub(arg2[4]));
    out1[0] = x1;
    out1[1] = x2;
    out1[2] = x3;
    out1[3] = x4;
    out1[4] = x5;
}

#[inline(always)]
pub fn fiat_25519_opp(out1: &mut [u64; 5], arg1: &[u64; 5]) {
    let x1: u64 = (0xfffffffffffdau64.wrapping_sub(arg1[0]));
    let x2: u64 = (0xffffffffffffeu64.wrapping_sub(arg1[1]));
    let x3: u64 = (0xffffffffffffeu64.wrapping_sub(arg1[2]));
    let x4: u64 = (0xffffffffffffeu64.wrapping_sub(arg1[3]));
    let x5: u64 = (0xffffffffffffeu64.wrapping_sub(arg1[4]));
    out1[0] = x1;
    out1[1] = x2;
    out1[2] = x3;
    out1[3] = x4;
    out1[4] = x5;
}

#[inline(always)]
pub fn fiat_25519_selectznz(
    out1: &mut [u64; 5],
    arg1: u8,
    arg2: &[u64; 5],
    arg3: &[u64; 5],
) {
    let mut x1: u64 = 0;
    fiat_25519_cmovznz_u64(&mut x1, arg1, (arg2[0]), (arg3[0]));
    let mut x2: u64 = 0;
    fiat_25519_cmovznz_u64(&mut x2, arg1, (arg2[1]), (arg3[1]));
    let mut x3: u64 = 0;
    fiat_25519_cmovznz_u64(&mut x3, arg1, (arg2[2]), (arg3[2]));
    let mut x4: u64 = 0;
    fiat_25519_cmovznz_u64(&mut x4, arg1, (arg2[3]), (arg3[3]));
    let mut x5: u64 = 0;
    fiat_25519_cmovznz_u64(&mut x5, arg1, (arg2[4]), (arg3[4]));
    out1[0] = x1;
    out1[1] = x2;
    out1[2] = x3;
    out1[3] = x4;
    out1[4] = x5;
}

pub fn fiat_25519_to_bytes(out1: &mut [u8; 32], arg1: &[u64; 5]) {
    let mut x1: u64 = 0;
    let mut x2: u8 = 0;
    fiat_25519_subborrowx_u51(&mut x1, &mut x2, 0x0, (arg1[0]), 0x7ffffffffffed);
    let mut x3: u64 = 0;
    let mut x4: u8 = 0;
    fiat_25519_subborrowx_u51(&mut x3, &mut x4, x2, (arg1[1]), 0x7ffffffffffff);
    let mut x5: u64 = 0;
    let mut x6: u8 = 0;
    fiat_25519_subborrowx_u51(&mut x5, &mut x6, x4, (arg1[2]), 0x7ffffffffffff);
    let mut x7: u64 = 0;
    let mut x8: u8 = 0;
    fiat_25519_subborrowx_u51(&mut x7, &mut x8, x6, (arg1[3]), 0x7ffffffffffff);
    let mut x9: u64 = 0;
    let mut x10: u8 = 0;
    fiat_25519_subborrowx_u51(&mut x9, &mut x10, x8, (arg1[4]), 0x7ffffffffffff);
    let mut x11: u64 = 0;
    fiat_25519_cmovznz_u64(&mut x11, x10, 0x0_u64, 0xffffffffffffffff);
    let mut x12: u64 = 0;
    let mut x13: u8 = 0;
    fiat_25519_addcarryx_u51(&mut x12, &mut x13, 0x0, x1, (x11 & 0x7ffffffffffed));
    let mut x14: u64 = 0;
    let mut x15: u8 = 0;
    fiat_25519_addcarryx_u51(&mut x14, &mut x15, x13, x3, (x11 & 0x7ffffffffffff));
    let mut x16: u64 = 0;
    let mut x17: u8 = 0;
    fiat_25519_addcarryx_u51(&mut x16, &mut x17, x15, x5, (x11 & 0x7ffffffffffff));
    let mut x18: u64 = 0;
    let mut x19: u8 = 0;
    fiat_25519_addcarryx_u51(&mut x18, &mut x19, x17, x7, (x11 & 0x7ffffffffffff));
    let mut x20: u64 = 0;
    let mut x21: u8 = 0;
    fiat_25519_addcarryx_u51(&mut x20, &mut x21, x19, x9, (x11 & 0x7ffffffffffff));
    let x22: u64 = (x20 << 4);
    let x23: u64 = (x18.wrapping_mul(0x2_u64));
    let x24: u64 = (x16 << 6);
    let x25: u64 = (x14 << 3);
    let x26: u8 = ((x12 & 0xff_u64) as u8);
    let x27: u64 = (x12 >> 8);
    let x28: u8 = ((x27 & 0xff_u64) as u8);
    let x29: u64 = (x27 >> 8);
    let x30: u8 = ((x29 & 0xff_u64) as u8);
    let x31: u64 = (x29 >> 8);
    let x32: u8 = ((x31 & 0xff_u64) as u8);
    let x33: u64 = (x31 >> 8);
    let x34: u8 = ((x33 & 0xff_u64) as u8);
    let x35: u64 = (x33 >> 8);
    let x36: u8 = ((x35 & 0xff_u64) as u8);
    let x37: u8 = ((x35 >> 8) as u8);
    let x38: u64 = (x25.wrapping_add(x37 as u64));
    let x39: u8 = ((x38 & 0xff_u64) as u8);
    let x40: u64 = (x38 >> 8);
    let x41: u8 = ((x40 & 0xff_u64) as u8);
    let x42: u64 = (x40 >> 8);
    let x43: u8 = ((x42 & 0xff_u64) as u8);
    let x44: u64 = (x42 >> 8);
    let x45: u8 = ((x44 & 0xff_u64) as u8);
    let x46: u64 = (x44 >> 8);
    let x47: u8 = ((x46 & 0xff_u64) as u8);
    let x48: u64 = (x46 >> 8);
    let x49: u8 = ((x48 & 0xff_u64) as u8);
    let x50: u8 = ((x48 >> 8) as u8);
    let x51: u64 = (x24.wrapping_add(x50 as u64));
    let x52: u8 = ((x51 & 0xff_u64) as u8);
    let x53: u64 = (x51 >> 8);
    let x54: u8 = ((x53 & 0xff_u64) as u8);
    let x55: u64 = (x53 >> 8);
    let x56: u8 = ((x55 & 0xff_u64) as u8);
    let x57: u64 = (x55 >> 8);
    let x58: u8 = ((x57 & 0xff_u64) as u8);
    let x59: u64 = (x57 >> 8);
    let x60: u8 = ((x59 & 0xff_u64) as u8);
    let x61: u64 = (x59 >> 8);
    let x62: u8 = ((x61 & 0xff_u64) as u8);
    let x63: u64 = (x61 >> 8);
    let x64: u8 = ((x63 & 0xff_u64) as u8);
    let x65: u8 = ((x63 >> 8) as u8);
    let x66: u64 = (x23.wrapping_add(x65 as u64));
    let x67: u8 = ((x66 & 0xff_u64) as u8);
    let x68: u64 = (x66 >> 8);
    let x69: u8 = ((x68 & 0xff_u64) as u8);
    let x70: u64 = (x68 >> 8);
    let x71: u8 = ((x70 & 0xff_u64) as u8);
    let x72: u64 = (x70 >> 8);
    let x73: u8 = ((x72 & 0xff_u64) as u8);
    let x74: u64 = (x72 >> 8);
    let x75: u8 = ((x74 & 0xff_u64) as u8);
    let x76: u64 = (x74 >> 8);
    let x77: u8 = ((x76 & 0xff_u64) as u8);
    let x78: u8 = ((x76 >> 8) as u8);
    let x79: u64 = (x22.wrapping_add(x78 as u64));
    let x80: u8 = ((x79 & 0xff_u64) as u8);
    let x81: u64 = (x79 >> 8);
    let x82: u8 = ((x81 & 0xff_u64) as u8);
    let x83: u64 = (x81 >> 8);
    let x84: u8 = ((x83 & 0xff_u64) as u8);
    let x85: u64 = (x83 >> 8);
    let x86: u8 = ((x85 & 0xff_u64) as u8);
    let x87: u64 = (x85 >> 8);
    let x88: u8 = ((x87 & 0xff_u64) as u8);
    let x89: u64 = (x87 >> 8);
    let x90: u8 = ((x89 & 0xff_u64) as u8);
    let x91: u8 = ((x89 >> 8) as u8);
    out1[0] = x26;
    out1[1] = x28;
    out1[2] = x30;
    out1[3] = x32;
    out1[4] = x34;
    out1[5] = x36;
    out1[6] = x39;
    out1[7] = x41;
    out1[8] = x43;
    out1[9] = x45;
    out1[10] = x47;
    out1[11] = x49;
    out1[12] = x52;
    out1[13] = x54;
    out1[14] = x56;
    out1[15] = x58;
    out1[16] = x60;
    out1[17] = x62;
    out1[18] = x64;
    out1[19] = x67;
    out1[20] = x69;
    out1[21] = x71;
    out1[22] = x73;
    out1[23] = x75;
    out1[24] = x77;
    out1[25] = x80;
    out1[26] = x82;
    out1[27] = x84;
    out1[28] = x86;
    out1[29] = x88;
    out1[30] = x90;
    out1[31] = x91;
}

#[derive(Clone, Default, Copy)]
pub struct Fe(pub [u64; 5]);

impl PartialEq for Fe {
    fn eq(&self, other: &Fe) -> bool {
        let &Fe(self_elems) = self;
        let &Fe(other_elems) = other;
        self_elems == other_elems
    }
}
impl Eq for Fe {}

pub static FE_ZERO: Fe = Fe([0, 0, 0, 0, 0]);
pub static FE_ONE: Fe = Fe([1, 0, 0, 0, 0]);
pub static FE_SQRTM1: Fe = Fe([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);
pub(crate) static FE_D: Fe = Fe([
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
]);
pub(crate) static FE_D2: Fe = Fe([
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
]);
#[inline(always)]
fn load_8u(s: &[u8]) -> u64 {
    (s[0] as u64)
        | ((s[1] as u64) << 8)
        | ((s[2] as u64) << 16)
        | ((s[3] as u64) << 24)
        | ((s[4] as u64) << 32)
        | ((s[5] as u64) << 40)
        | ((s[6] as u64) << 48)
        | ((s[7] as u64) << 56)
}

#[inline(always)]
pub fn load_4u(s: &[u8]) -> u64 {
    (s[0] as u64) | ((s[1] as u64) << 8) | ((s[2] as u64) << 16) | ((s[3] as u64) << 24)
}

#[inline(always)]
pub fn load_4i(s: &[u8]) -> i64 {
    load_4u(s) as i64
}

#[inline(always)]
pub fn load_3u(s: &[u8]) -> u64 {
    (s[0] as u64) | ((s[1] as u64) << 8) | ((s[2] as u64) << 16)
}

#[inline(always)]
pub fn load_3i(s: &[u8]) -> i64 {
    load_3u(s) as i64
}

impl Add for Fe {
    type Output = Fe;

    fn add(self, _rhs: Fe) -> Fe {
        let Fe(f) = self;
        let Fe(g) = _rhs;
        let mut h = Fe::default();
        fiat_25519_add(&mut h.0, &f, &g);
        h
    }
}

impl Sub for Fe {
    type Output = Fe;

    fn sub(self, _rhs: Fe) -> Fe {
        let Fe(f) = self;
        let Fe(g) = _rhs;
        let mut h = Fe::default();
        fiat_25519_sub(&mut h.0, &f, &g);
        h.carry()
    }
}

impl Mul for Fe {
    type Output = Fe;

    fn mul(self, _rhs: Fe) -> Fe {
        let Fe(f) = self;
        let Fe(g) = _rhs;
        let mut h = Fe::default();
        fiat_25519_carry_mul(&mut h.0, &f, &g);
        h
    }
}

impl Fe {
    pub fn from_bytes(s: &[u8]) -> Fe {
        if s.len() != 32 {
            panic!("Invalid compressed length")
        }
        let mut h = Fe::default();
        let mask = 0x7ffffffffffff;
        h.0[0] = load_8u(&s[0..]) & mask;
        h.0[1] = (load_8u(&s[6..]) >> 3) & mask;
        h.0[2] = (load_8u(&s[12..]) >> 6) & mask;
        h.0[3] = (load_8u(&s[19..]) >> 1) & mask;
        h.0[4] = (load_8u(&s[24..]) >> 12) & mask;
        h
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let &Fe(es) = &self.carry();
        let mut s_ = [0u8; 32];
        fiat_25519_to_bytes(&mut s_, &es);
        s_
    }

    pub fn carry(&self) -> Fe {
        let mut h = Fe::default();
        fiat_25519_carry(&mut h.0, &self.0);
        h
    }

    pub fn maybe_set(&mut self, other: &Fe, do_swap: u8) {
        let &mut Fe(f) = self;
        let &Fe(g) = other;
        let mut t = [0u64; 5];
        fiat_25519_selectznz(&mut t, do_swap, &f, &g);
        self.0 = t
    }

    pub fn square(&self) -> Fe {
        let &Fe(f) = &self;
        let mut h = Fe::default();
        fiat_25519_carry_square(&mut h.0, f);
        h
    }

    pub fn square_and_double(&self) -> Fe {
        let h = self.square();
        (h + h)
    }

    pub fn invert(&self) -> Fe {
        let z1 = *self;
        let z2 = z1.square();
        let z8 = z2.square().square();
        let z9 = z1 * z8;
        let z11 = z2 * z9;
        let z22 = z11.square();
        let z_5_0 = z9 * z22;
        let z_10_5 = (0..5).fold(z_5_0, |z_5_n, _| z_5_n.square());
        let z_10_0 = z_10_5 * z_5_0;
        let z_20_10 = (0..10).fold(z_10_0, |x, _| x.square());
        let z_20_0 = z_20_10 * z_10_0;
        let z_40_20 = (0..20).fold(z_20_0, |x, _| x.square());
        let z_40_0 = z_40_20 * z_20_0;
        let z_50_10 = (0..10).fold(z_40_0, |x, _| x.square());
        let z_50_0 = z_50_10 * z_10_0;
        let z_100_50 = (0..50).fold(z_50_0, |x, _| x.square());
        let z_100_0 = z_100_50 * z_50_0;
        let z_200_100 = (0..100).fold(z_100_0, |x, _| x.square());
        let z_200_0 = z_200_100 * z_100_0;
        let z_250_50 = (0..50).fold(z_200_0, |x, _| x.square());
        let z_250_0 = z_250_50 * z_50_0;
        let z_255_5 = (0..5).fold(z_250_0, |x, _| x.square());
        let z_255_21 = z_255_5 * z11;
        z_255_21
    }

    pub fn is_zero(&self) -> bool {
        self.to_bytes().iter().fold(0, |acc, x| acc | x) == 0
    }

    pub fn is_negative(&self) -> bool {
        (self.to_bytes()[0] & 1) != 0
    }

    pub fn neg(&self) -> Fe {
        let &Fe(f) = &self;
        let mut h = Fe::default();
        fiat_25519_opp(&mut h.0, f);
        h
    }

    pub fn pow25523(&self) -> Fe {
        let z2 = self.square();
        let z8 = (0..2).fold(z2, |x, _| x.square());
        let z9 = *self * z8;
        let z11 = z2 * z9;
        let z22 = z11.square();
        let z_5_0 = z9 * z22;
        let z_10_5 = (0..5).fold(z_5_0, |x, _| x.square());
        let z_10_0 = z_10_5 * z_5_0;
        let z_20_10 = (0..10).fold(z_10_0, |x, _| x.square());
        let z_20_0 = z_20_10 * z_10_0;
        let z_40_20 = (0..20).fold(z_20_0, |x, _| x.square());
        let z_40_0 = z_40_20 * z_20_0;
        let z_50_10 = (0..10).fold(z_40_0, |x, _| x.square());
        let z_50_0 = z_50_10 * z_10_0;
        let z_100_50 = (0..50).fold(z_50_0, |x, _| x.square());
        let z_100_0 = z_100_50 * z_50_0;
        let z_200_100 = (0..100).fold(z_100_0, |x, _| x.square());
        let z_200_0 = z_200_100 * z_100_0;
        let z_250_50 = (0..50).fold(z_200_0, |x, _| x.square());
        let z_250_0 = z_250_50 * z_50_0;
        let z_252_2 = (0..2).fold(z_250_0, |x, _| x.square());
        let z_252_3 = z_252_2 * *self;

        z_252_3
    }

    pub fn reject_noncanonical(s: &[u8]) -> Result<()> {
        if s.len() != 32 {
            panic!("Invalid compressed length")
        }
        let mut c = s[31];
        c ^= 0x7f;
        let mut i: usize = 30;
        while i > 0 {
            c |= s[i] ^ 0xff;
            i -= 1;
        }
        c = ((c as u16).wrapping_sub(1) >> 8) as u8;
        let d = (((0xed - 1) as u16).wrapping_sub(s[0] as u16) >> 8) as u8;
        if c & d & 1 == 0 {
            Ok(())
        } else {
            Err(err!(Crypto,"Non canonical"))
        }
    }
}
#[derive(Clone, Copy)]
pub struct GeP2 {
    x: Fe,
    y: Fe,
    z: Fe,
}

#[derive(Clone, Copy)]
pub struct GeP3 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

#[derive(Clone, Copy, Default)]
pub struct GeP1P1 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

#[derive(Clone, Copy)]
pub struct GePrecomp {
    y_plus_x: Fe,
    y_minus_x: Fe,
    xy2d: Fe,
}

#[derive(Clone, Copy, Default)]
pub struct GeCached {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,
}

impl GeCached {
    pub fn maybe_set(&mut self, other: &GeCached, do_swap: u8) {
        self.y_plus_x.maybe_set(&other.y_plus_x, do_swap);
        self.y_minus_x.maybe_set(&other.y_minus_x, do_swap);
        self.z.maybe_set(&other.z, do_swap);
        self.t2d.maybe_set(&other.t2d, do_swap);
    }
}

impl GeP1P1 {
    fn to_p2(&self) -> GeP2 {
        GeP2 {
            x: self.x * self.t,
            y: self.y * self.z,
            z: self.z * self.t,
        }
    }

    fn to_p3(&self) -> GeP3 {
        GeP3 {
            x: self.x * self.t,
            y: self.y * self.z,
            z: self.z * self.t,
            t: self.x * self.y,
        }
    }
}

impl From<GeP2> for GeP3 {
    fn from(p: GeP2) -> GeP3 {
        GeP3 {
            x: p.x,
            y: p.y,
            z: p.z,
            t: p.x * p.y,
        }
    }
}

impl GeP2 {
    fn zero() -> GeP2 {
        GeP2 {
            x: FE_ZERO,
            y: FE_ONE,
            z: FE_ONE,
        }
    }

    fn dbl(&self) -> GeP1P1 {
        let xx = self.x.square();
        let yy = self.y.square();
        let b = self.z.square_and_double();
        let a = self.x + self.y;
        let aa = a.square();
        let y3 = yy + xx;
        let z3 = yy - xx;
        let x3 = aa - y3;
        let t3 = b - z3;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }

    fn slide(a: &[u8]) -> [i8; 256] {
        let mut r = [0i8; 256];
        for i in 0..256 {
            r[i] = (1 & (a[i >> 3] >> (i & 7))) as i8;
        }
        for i in 0..256 {
            if r[i] != 0 {
                for b in 1..min(7, 256 - i) {
                    if r[i + b] != 0 {
                        if r[i] + (r[i + b] << b) <= 15 {
                            r[i] += r[i + b] << b;
                            r[i + b] = 0;
                        } else if r[i] - (r[i + b] << b) >= -15 {
                            r[i] -= r[i + b] << b;
                            for k in i + b..256 {
                                if r[k] == 0 {
                                    r[k] = 1;
                                    break;
                                }
                                r[k] = 0;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        r
    }

    #[allow(clippy::comparison_chain)]
    pub fn double_scalarmult_vartime(a_scalar: &[u8], a_point: GeP3, b_scalar: &[u8]) -> GeP2 {
        let aslide = GeP2::slide(a_scalar);
        let bslide = GeP2::slide(b_scalar);

        let mut ai = [GeCached {
            y_plus_x: FE_ZERO,
            y_minus_x: FE_ZERO,
            z: FE_ZERO,
            t2d: FE_ZERO,
        }; 8]; // A,3A,5A,7A,9A,11A,13A,15A
        ai[0] = a_point.to_cached();
        let a2 = a_point.dbl().to_p3();
        ai[1] = (a2 + ai[0]).to_p3().to_cached();
        ai[2] = (a2 + ai[1]).to_p3().to_cached();
        ai[3] = (a2 + ai[2]).to_p3().to_cached();
        ai[4] = (a2 + ai[3]).to_p3().to_cached();
        ai[5] = (a2 + ai[4]).to_p3().to_cached();
        ai[6] = (a2 + ai[5]).to_p3().to_cached();
        ai[7] = (a2 + ai[6]).to_p3().to_cached();

        let mut r = GeP2::zero();

        let mut i: usize = 255;
        loop {
            if aslide[i] != 0 || bslide[i] != 0 {
                break;
            }
            if i == 0 {
                return r;
            }
            i -= 1;
        }

        loop {
            let mut t = r.dbl();
            if aslide[i] > 0 {
                t = t.to_p3() + ai[(aslide[i] / 2) as usize];
            } else if aslide[i] < 0 {
                t = t.to_p3() - ai[(-aslide[i] / 2) as usize];
            }

            if bslide[i] > 0 {
                t = t.to_p3() + BI[(bslide[i] / 2) as usize];
            } else if bslide[i] < 0 {
                t = t.to_p3() - BI[(-bslide[i] / 2) as usize];
            }

            r = t.to_p2();

            if i == 0 {
                return r;
            }
            i -= 1;
        }
    }
}

impl GeP3 {
    pub fn from_bytes_negate_vartime(s: &[u8; 32]) -> Option<GeP3> {
        let y = Fe::from_bytes(s);
        let z = FE_ONE;
        let y_squared = y.square();
        let u = y_squared - FE_ONE;
        let v = (y_squared * FE_D) + FE_ONE;
        let mut x = (u * v).pow25523() * u;

        let vxx = x.square() * v;
        let check = vxx - u;
        if !check.is_zero() {
            let check2 = vxx + u;
            if !check2.is_zero() {
                return None;
            }
            x = x * FE_SQRTM1;
        }

        if x.is_negative() == ((s[31] >> 7) != 0) {
            x = x.neg();
        }

        let t = x * y;

        Some(GeP3 { x, y, z, t })
    }

    pub fn from_bytes_vartime(s: &[u8; 32]) -> Option<GeP3> {
        Self::from_bytes_negate_vartime(s).map(|p| GeP3 {
            x: p.x.neg(),
            y: p.y,
            z: p.z,
            t: p.t.neg(),
        })
    }

    fn to_p2(&self) -> GeP2 {
        GeP2 {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    fn to_cached(&self) -> GeCached {
        GeCached {
            y_plus_x: self.y + self.x,
            y_minus_x: self.y - self.x,
            z: self.z,
            t2d: self.t * FE_D2,
        }
    }

    fn zero() -> GeP3 {
        GeP3 {
            x: FE_ZERO,
            y: FE_ONE,
            z: FE_ONE,
            t: FE_ZERO,
        }
    }

    fn dbl(&self) -> GeP1P1 {
        self.to_p2().dbl()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = self.x * recip;
        let y = self.y * recip;
        let mut bs = y.to_bytes();
        bs[31] ^= (if x.is_negative() { 1 } else { 0 }) << 7;
        bs
    }

    pub fn has_small_order(&self) -> bool {
        let recip = self.z.invert();
        let x = self.x * recip;
        let y = self.y * recip;
        let x_neg = x.neg();
        let y_sqrtm1 = y * FE_SQRTM1;
        x.is_zero() | y.is_zero() | (y_sqrtm1 == x) | (y_sqrtm1 == x_neg)
    }
}

impl Add<GeP3> for GeP3 {
    type Output = GeP3;

    fn add(self, other: GeP3) -> GeP3 {
        (self + other.to_cached()).to_p3()
    }
}

impl Sub<GeP3> for GeP3 {
    type Output = GeP3;

    fn sub(self, other: GeP3) -> GeP3 {
        (self - other.to_cached()).to_p3()
    }
}

impl Add<GeCached> for GeP3 {
    type Output = GeP1P1;

    fn add(self, _rhs: GeCached) -> GeP1P1 {
        let y1_plus_x1 = self.y + self.x;
        let y1_minus_x1 = self.y - self.x;
        let a = y1_plus_x1 * _rhs.y_plus_x;
        let b = y1_minus_x1 * _rhs.y_minus_x;
        let c = _rhs.t2d * self.t;
        let zz = self.z * _rhs.z;
        let d = zz + zz;
        let x3 = a - b;
        let y3 = a + b;
        let z3 = d + c;
        let t3 = d - c;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }
}

impl Add<GePrecomp> for GeP3 {
    type Output = GeP1P1;

    fn add(self, _rhs: GePrecomp) -> GeP1P1 {
        let y1_plus_x1 = self.y + self.x;
        let y1_minus_x1 = self.y - self.x;
        let a = y1_plus_x1 * _rhs.y_plus_x;
        let b = y1_minus_x1 * _rhs.y_minus_x;
        let c = _rhs.xy2d * self.t;
        let d = self.z + self.z;
        let x3 = a - b;
        let y3 = a + b;
        let z3 = d + c;
        let t3 = d - c;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }
}

impl Sub<GeCached> for GeP3 {
    type Output = GeP1P1;

    fn sub(self, _rhs: GeCached) -> GeP1P1 {
        let y1_plus_x1 = self.y + self.x;
        let y1_minus_x1 = self.y - self.x;
        let a = y1_plus_x1 * _rhs.y_minus_x;
        let b = y1_minus_x1 * _rhs.y_plus_x;
        let c = _rhs.t2d * self.t;
        let zz = self.z * _rhs.z;
        let d = zz + zz;
        let x3 = a - b;
        let y3 = a + b;
        let z3 = d - c;
        let t3 = d + c;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }
}

impl Sub<GePrecomp> for GeP3 {
    type Output = GeP1P1;

    fn sub(self, _rhs: GePrecomp) -> GeP1P1 {
        let y1_plus_x1 = self.y + self.x;
        let y1_minus_x1 = self.y - self.x;
        let a = y1_plus_x1 * _rhs.y_minus_x;
        let b = y1_minus_x1 * _rhs.y_plus_x;
        let c = _rhs.xy2d * self.t;
        let d = self.z + self.z;
        let x3 = a - b;
        let y3 = a + b;
        let z3 = d - c;
        let t3 = d + c;

        GeP1P1 {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }
}

fn ge_precompute(base: &GeP3) -> [GeCached; 16] {
    let base_cached = base.to_cached();
    let mut pc = [GeP3::zero(); 16];
    pc[1] = *base;
    for i in 2..16 {
        pc[i] = if i % 2 == 0 {
            pc[i / 2].dbl().to_p3()
        } else {
            pc[i - 1].add(base_cached).to_p3()
        }
    }
    let mut pc_cached: [GeCached; 16] = Default::default();
    for i in 0..16 {
        pc_cached[i] = pc[i].to_cached();
    }
    pc_cached
}

pub fn ge_scalarmult(scalar: &[u8], base: &GeP3) -> GeP3 {
    let pc = ge_precompute(base);
    let mut q = GeP3::zero();
    let mut pos = 252;
    loop {
        let slot = ((scalar[pos >> 3] >> (pos & 7)) & 15) as usize;
        let mut t = pc[0];
        for i in 1..16 {
            t.maybe_set(&pc[i], (((slot ^ i).wrapping_sub(1)) >> 8) as u8 & 1);
        }
        q = q.add(t).to_p3();
        if pos == 0 {
            break;
        }
        q = q.dbl().to_p3().dbl().to_p3().dbl().to_p3().dbl().to_p3();
        pos -= 4;
    }
    q
}

pub fn ge_scalarmult_base(scalar: &[u8]) -> GeP3 {
    const BXP: [u8; 32] = [
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c,
        0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36,
        0x69, 0x21,
    ];
    const BYP: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];
    let bx = Fe::from_bytes(&BXP);
    let by = Fe::from_bytes(&BYP);
    let base = GeP3 {
        x: bx,
        y: by,
        z: FE_ONE,
        t: bx * by,
    };
    ge_scalarmult(scalar, &base)
}

pub fn sc_reduce32(s: &mut [u8; 32]) {
    let mut t = [0u8; 64];
    t[0..32].copy_from_slice(s);
    sc_reduce(&mut t);
    s.copy_from_slice(&t[0..32]);
}

pub fn sc_reduce(s: &mut [u8]) {
    let mut s0: i64 = 2097151 & load_3i(s);
    let mut s1: i64 = 2097151 & (load_4i(&s[2..6]) >> 5);
    let mut s2: i64 = 2097151 & (load_3i(&s[5..8]) >> 2);
    let mut s3: i64 = 2097151 & (load_4i(&s[7..11]) >> 7);
    let mut s4: i64 = 2097151 & (load_4i(&s[10..14]) >> 4);
    let mut s5: i64 = 2097151 & (load_3i(&s[13..16]) >> 1);
    let mut s6: i64 = 2097151 & (load_4i(&s[15..19]) >> 6);
    let mut s7: i64 = 2097151 & (load_3i(&s[18..21]) >> 3);
    let mut s8: i64 = 2097151 & load_3i(&s[21..24]);
    let mut s9: i64 = 2097151 & (load_4i(&s[23..27]) >> 5);
    let mut s10: i64 = 2097151 & (load_3i(&s[26..29]) >> 2);
    let mut s11: i64 = 2097151 & (load_4i(&s[28..32]) >> 7);
    let mut s12: i64 = 2097151 & (load_4i(&s[31..35]) >> 4);
    let mut s13: i64 = 2097151 & (load_3i(&s[34..37]) >> 1);
    let mut s14: i64 = 2097151 & (load_4i(&s[36..40]) >> 6);
    let mut s15: i64 = 2097151 & (load_3i(&s[39..42]) >> 3);
    let mut s16: i64 = 2097151 & load_3i(&s[42..45]);
    let mut s17: i64 = 2097151 & (load_4i(&s[44..48]) >> 5);
    let s18: i64 = 2097151 & (load_3i(&s[47..50]) >> 2);
    let s19: i64 = 2097151 & (load_4i(&s[49..53]) >> 7);
    let s20: i64 = 2097151 & (load_4i(&s[52..56]) >> 4);
    let s21: i64 = 2097151 & (load_3i(&s[55..58]) >> 1);
    let s22: i64 = 2097151 & (load_4i(&s[57..61]) >> 6);
    let s23: i64 = load_4i(&s[60..64]) >> 3;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;

    let mut carry6: i64 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    let mut carry8: i64 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    let mut carry10: i64 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    let carry12: i64 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 << 21;
    let carry14: i64 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 << 21;
    let carry16: i64 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 << 21;

    let mut carry7: i64 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    let mut carry9: i64 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    let mut carry11: i64 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    let carry13: i64 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 << 21;
    let carry15: i64 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 << 21;

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    let mut carry0: i64 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    let mut carry2: i64 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    let mut carry4: i64 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    let mut carry1: i64 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    let mut carry3: i64 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    let mut carry5: i64 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    s[0] = (s0 >> 0) as u8;
    s[1] = (s0 >> 8) as u8;
    s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
    s[3] = (s1 >> 3) as u8;
    s[4] = (s1 >> 11) as u8;
    s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
    s[6] = (s2 >> 6) as u8;
    s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
    s[8] = (s3 >> 1) as u8;
    s[9] = (s3 >> 9) as u8;
    s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
    s[11] = (s4 >> 4) as u8;
    s[12] = (s4 >> 12) as u8;
    s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
    s[14] = (s5 >> 7) as u8;
    s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
    s[16] = (s6 >> 2) as u8;
    s[17] = (s6 >> 10) as u8;
    s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
    s[19] = (s7 >> 5) as u8;
    s[20] = (s7 >> 13) as u8;
    s[21] = (s8 >> 0) as u8;
    s[22] = (s8 >> 8) as u8;
    s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
    s[24] = (s9 >> 3) as u8;
    s[25] = (s9 >> 11) as u8;
    s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
    s[27] = (s10 >> 6) as u8;
    s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
    s[29] = (s11 >> 1) as u8;
    s[30] = (s11 >> 9) as u8;
    s[31] = (s11 >> 17) as u8;
}

pub fn sc_muladd(s: &mut [u8], a: &[u8], b: &[u8], c: &[u8]) {
    let a0 = 2097151 & load_3i(&a[0..3]);
    let a1 = 2097151 & (load_4i(&a[2..6]) >> 5);
    let a2 = 2097151 & (load_3i(&a[5..8]) >> 2);
    let a3 = 2097151 & (load_4i(&a[7..11]) >> 7);
    let a4 = 2097151 & (load_4i(&a[10..14]) >> 4);
    let a5 = 2097151 & (load_3i(&a[13..16]) >> 1);
    let a6 = 2097151 & (load_4i(&a[15..19]) >> 6);
    let a7 = 2097151 & (load_3i(&a[18..21]) >> 3);
    let a8 = 2097151 & load_3i(&a[21..24]);
    let a9 = 2097151 & (load_4i(&a[23..27]) >> 5);
    let a10 = 2097151 & (load_3i(&a[26..29]) >> 2);
    let a11 = load_4i(&a[28..32]) >> 7;
    let b0 = 2097151 & load_3i(&b[0..3]);
    let b1 = 2097151 & (load_4i(&b[2..6]) >> 5);
    let b2 = 2097151 & (load_3i(&b[5..8]) >> 2);
    let b3 = 2097151 & (load_4i(&b[7..11]) >> 7);
    let b4 = 2097151 & (load_4i(&b[10..14]) >> 4);
    let b5 = 2097151 & (load_3i(&b[13..16]) >> 1);
    let b6 = 2097151 & (load_4i(&b[15..19]) >> 6);
    let b7 = 2097151 & (load_3i(&b[18..21]) >> 3);
    let b8 = 2097151 & load_3i(&b[21..24]);
    let b9 = 2097151 & (load_4i(&b[23..27]) >> 5);
    let b10 = 2097151 & (load_3i(&b[26..29]) >> 2);
    let b11 = load_4i(&b[28..32]) >> 7;
    let c0 = 2097151 & load_3i(&c[0..3]);
    let c1 = 2097151 & (load_4i(&c[2..6]) >> 5);
    let c2 = 2097151 & (load_3i(&c[5..8]) >> 2);
    let c3 = 2097151 & (load_4i(&c[7..11]) >> 7);
    let c4 = 2097151 & (load_4i(&c[10..14]) >> 4);
    let c5 = 2097151 & (load_3i(&c[13..16]) >> 1);
    let c6 = 2097151 & (load_4i(&c[15..19]) >> 6);
    let c7 = 2097151 & (load_3i(&c[18..21]) >> 3);
    let c8 = 2097151 & load_3i(&c[21..24]);
    let c9 = 2097151 & (load_4i(&c[23..27]) >> 5);
    let c10 = 2097151 & (load_3i(&c[26..29]) >> 2);
    let c11 = load_4i(&c[28..32]) >> 7;

    let mut s0: i64 = c0 + a0 * b0;
    let mut s1: i64 = c1 + a0 * b1 + a1 * b0;
    let mut s2: i64 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
    let mut s3: i64 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    let mut s4: i64 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
    let mut s5: i64 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
    let mut s6: i64 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
    let mut s7: i64 =
        c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1 + a7 * b0;
    let mut s8: i64 = c8
        + a0 * b8
        + a1 * b7
        + a2 * b6
        + a3 * b5
        + a4 * b4
        + a5 * b3
        + a6 * b2
        + a7 * b1
        + a8 * b0;
    let mut s9: i64 = c9
        + a0 * b9
        + a1 * b8
        + a2 * b7
        + a3 * b6
        + a4 * b5
        + a5 * b4
        + a6 * b3
        + a7 * b2
        + a8 * b1
        + a9 * b0;
    let mut s10: i64 = c10
        + a0 * b10
        + a1 * b9
        + a2 * b8
        + a3 * b7
        + a4 * b6
        + a5 * b5
        + a6 * b4
        + a7 * b3
        + a8 * b2
        + a9 * b1
        + a10 * b0;
    let mut s11: i64 = c11
        + a0 * b11
        + a1 * b10
        + a2 * b9
        + a3 * b8
        + a4 * b7
        + a5 * b6
        + a6 * b5
        + a7 * b4
        + a8 * b3
        + a9 * b2
        + a10 * b1
        + a11 * b0;
    let mut s12: i64 = a1 * b11
        + a2 * b10
        + a3 * b9
        + a4 * b8
        + a5 * b7
        + a6 * b6
        + a7 * b5
        + a8 * b4
        + a9 * b3
        + a10 * b2
        + a11 * b1;
    let mut s13: i64 = a2 * b11
        + a3 * b10
        + a4 * b9
        + a5 * b8
        + a6 * b7
        + a7 * b6
        + a8 * b5
        + a9 * b4
        + a10 * b3
        + a11 * b2;
    let mut s14: i64 =
        a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3;
    let mut s15: i64 =
        a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 + a11 * b4;
    let mut s16: i64 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
    let mut s17: i64 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
    let mut s18: i64 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
    let mut s19: i64 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
    let mut s20: i64 = a9 * b11 + a10 * b10 + a11 * b9;
    let mut s21: i64 = a10 * b11 + a11 * b10;
    let mut s22: i64 = a11 * b11;
    let mut s23: i64 = 0;

    let mut carry0: i64 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    let mut carry2: i64 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    let mut carry4: i64 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    let mut carry6: i64 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    let mut carry8: i64 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    let mut carry10: i64 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    let mut carry12: i64 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 << 21;
    let mut carry14: i64 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 << 21;
    let mut carry16: i64 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 << 21;
    let carry18: i64 = (s18 + (1 << 20)) >> 21;
    s19 += carry18;
    s18 -= carry18 << 21;
    let carry20: i64 = (s20 + (1 << 20)) >> 21;
    s21 += carry20;
    s20 -= carry20 << 21;
    let carry22: i64 = (s22 + (1 << 20)) >> 21;
    s23 += carry22;
    s22 -= carry22 << 21;

    let mut carry1: i64 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    let mut carry3: i64 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    let mut carry5: i64 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    let mut carry7: i64 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    let mut carry9: i64 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    let mut carry11: i64 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    let mut carry13: i64 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 << 21;
    let mut carry15: i64 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 << 21;
    let carry17: i64 = (s17 + (1 << 20)) >> 21;
    s18 += carry17;
    s17 -= carry17 << 21;
    let carry19: i64 = (s19 + (1 << 20)) >> 21;
    s20 += carry19;
    s19 -= carry19 << 21;
    let carry21: i64 = (s21 + (1 << 20)) >> 21;
    s22 += carry21;
    s21 -= carry21 << 21;

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;

    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry12 = (s12 + (1 << 20)) >> 21;
    s13 += carry12;
    s12 -= carry12 << 21;
    carry14 = (s14 + (1 << 20)) >> 21;
    s15 += carry14;
    s14 -= carry14 << 21;
    carry16 = (s16 + (1 << 20)) >> 21;
    s17 += carry16;
    s16 -= carry16 << 21;

    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;
    carry13 = (s13 + (1 << 20)) >> 21;
    s14 += carry13;
    s13 -= carry13 << 21;
    carry15 = (s15 + (1 << 20)) >> 21;
    s16 += carry15;
    s15 -= carry15 << 21;

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (1 << 20)) >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry2 = (s2 + (1 << 20)) >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry4 = (s4 + (1 << 20)) >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry6 = (s6 + (1 << 20)) >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry8 = (s8 + (1 << 20)) >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry10 = (s10 + (1 << 20)) >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    carry1 = (s1 + (1 << 20)) >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry3 = (s3 + (1 << 20)) >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry5 = (s5 + (1 << 20)) >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry7 = (s7 + (1 << 20)) >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry9 = (s9 + (1 << 20)) >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry11 = (s11 + (1 << 20)) >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;
    carry11 = s11 >> 21;
    s12 += carry11;
    s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;

    carry0 = s0 >> 21;
    s1 += carry0;
    s0 -= carry0 << 21;
    carry1 = s1 >> 21;
    s2 += carry1;
    s1 -= carry1 << 21;
    carry2 = s2 >> 21;
    s3 += carry2;
    s2 -= carry2 << 21;
    carry3 = s3 >> 21;
    s4 += carry3;
    s3 -= carry3 << 21;
    carry4 = s4 >> 21;
    s5 += carry4;
    s4 -= carry4 << 21;
    carry5 = s5 >> 21;
    s6 += carry5;
    s5 -= carry5 << 21;
    carry6 = s6 >> 21;
    s7 += carry6;
    s6 -= carry6 << 21;
    carry7 = s7 >> 21;
    s8 += carry7;
    s7 -= carry7 << 21;
    carry8 = s8 >> 21;
    s9 += carry8;
    s8 -= carry8 << 21;
    carry9 = s9 >> 21;
    s10 += carry9;
    s9 -= carry9 << 21;
    carry10 = s10 >> 21;
    s11 += carry10;
    s10 -= carry10 << 21;

    s[0] = (s0 >> 0) as u8;
    s[1] = (s0 >> 8) as u8;
    s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
    s[3] = (s1 >> 3) as u8;
    s[4] = (s1 >> 11) as u8;
    s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
    s[6] = (s2 >> 6) as u8;
    s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
    s[8] = (s3 >> 1) as u8;
    s[9] = (s3 >> 9) as u8;
    s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
    s[11] = (s4 >> 4) as u8;
    s[12] = (s4 >> 12) as u8;
    s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
    s[14] = (s5 >> 7) as u8;
    s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
    s[16] = (s6 >> 2) as u8;
    s[17] = (s6 >> 10) as u8;
    s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
    s[19] = (s7 >> 5) as u8;
    s[20] = (s7 >> 13) as u8;
    s[21] = (s8 >> 0) as u8;
    s[22] = (s8 >> 8) as u8;
    s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
    s[24] = (s9 >> 3) as u8;
    s[25] = (s9 >> 11) as u8;
    s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
    s[27] = (s10 >> 6) as u8;
    s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
    s[29] = (s11 >> 1) as u8;
    s[30] = (s11 >> 9) as u8;
    s[31] = (s11 >> 17) as u8;
}

pub fn sc_reject_noncanonical(s: &[u8]) -> Result<()> {
    static L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    if s.len() != 32 {
        panic!("Invalid compressed length")
    }
    let mut c: u8 = 0;
    let mut n: u8 = 1;

    let mut i = 31;
    loop {
        c |= ((((s[i] as i32) - (L[i] as i32)) >> 8) as u8) & n;
        n &= ((((s[i] ^ L[i]) as i32) - 1) >> 8) as u8;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    if c != 0 {
        Ok(())
    } else {
        Err(err!(Crypto,"Non canonical"))
    }
}

pub fn is_identity(s: &[u8; 32]) -> bool {
    let mut c = s[0] ^ 0x01;
    for i in 1..31 {
        c |= s[i];
    }
    c |= s[31] & 0x7f;
    c == 0
}

static BI: [GePrecomp; 8] = [
    GePrecomp {
        y_plus_x: Fe([
            1288382639258501,
            245678601348599,
            269427782077623,
            1462984067271730,
            137412439391563,
        ]),
        y_minus_x: Fe([
            62697248952638,
            204681361388450,
            631292143396476,
            338455783676468,
            1213667448819585,
        ]),
        xy2d: Fe([
            301289933810280,
            1259582250014073,
            1422107436869536,
            796239922652654,
            1953934009299142,
        ]),
    },
    GePrecomp {
        y_plus_x: Fe([
            1601611775252272,
            1720807796594148,
            1132070835939856,
            1260455018889551,
            2147779492816911,
        ]),
        y_minus_x: Fe([
            316559037616741,
            2177824224946892,
            1459442586438991,
            1461528397712656,
            751590696113597,
        ]),
        xy2d: Fe([
            1850748884277385,
            1200145853858453,
            1068094770532492,
            672251375690438,
            1586055907191707,
        ]),
    },
    GePrecomp {
        y_plus_x: Fe([
            769950342298419,
            132954430919746,
            844085933195555,
            974092374476333,
            726076285546016,
        ]),
        y_minus_x: Fe([
            425251763115706,
            608463272472562,
            442562545713235,
            837766094556764,
            374555092627893,
        ]),
        xy2d: Fe([
            1086255230780037,
            274979815921559,
            1960002765731872,
            929474102396301,
            1190409889297339,
        ]),
    },
    GePrecomp {
        y_plus_x: Fe([
            665000864555967,
            2065379846933859,
            370231110385876,
            350988370788628,
            1233371373142985,
        ]),
        y_minus_x: Fe([
            2019367628972465,
            676711900706637,
            110710997811333,
            1108646842542025,
            517791959672113,
        ]),
        xy2d: Fe([
            965130719900578,
            247011430587952,
            526356006571389,
            91986625355052,
            2157223321444601,
        ]),
    },
    GePrecomp {
        y_plus_x: Fe([
            1802695059465007,
            1664899123557221,
            593559490740857,
            2160434469266659,
            927570450755031,
        ]),
        y_minus_x: Fe([
            1725674970513508,
            1933645953859181,
            1542344539275782,
            1767788773573747,
            1297447965928905,
        ]),
        xy2d: Fe([
            1381809363726107,
            1430341051343062,
            2061843536018959,
            1551778050872521,
            2036394857967624,
        ]),
    },
    GePrecomp {
        y_plus_x: Fe([
            1970894096313054,
            528066325833207,
            1619374932191227,
            2207306624415883,
            1169170329061080,
        ]),
        y_minus_x: Fe([
            2070390218572616,
            1458919061857835,
            624171843017421,
            1055332792707765,
            433987520732508,
        ]),
        xy2d: Fe([
            893653801273833,
            1168026499324677,
            1242553501121234,
            1306366254304474,
            1086752658510815,
        ]),
    },
    GePrecomp {
        y_plus_x: Fe([
            213454002618221,
            939771523987438,
            1159882208056014,
            317388369627517,
            621213314200687,
        ]),
        y_minus_x: Fe([
            1971678598905747,
            338026507889165,
            762398079972271,
            655096486107477,
            42299032696322,
        ]),
        xy2d: Fe([
            177130678690680,
            1754759263300204,
            1864311296286618,
            1180675631479880,
            1292726903152791,
        ]),
    },
    GePrecomp {
        y_plus_x: Fe([
            1913163449625248,
            460779200291993,
            2193883288642314,
            1008900146920800,
            1721983679009502,
        ]),
        y_minus_x: Fe([
            1070401523076875,
            1272492007800961,
            1910153608563310,
            2075579521696771,
            1191169788841221,
        ]),
        xy2d: Fe([
            692896803108118,
            500174642072499,
            2068223309439677,
            1162190621851337,
            1426986007309901,
        ]),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hex() {
        let hex = generate_hex(32);
        assert_eq!(hex.len(), 32);
        assert!(is_valid_hex(&hex));
    }

    #[test]
    fn test_generate_password() {
        let password = generate_password(24);
        assert_eq!(password.len(), 24);
    }

    #[test]
    fn test_generate_wireguard_key() {
        let key = generate_wireguard_key();
        assert!(is_valid_base64(&key));
    }

    #[test]
    fn test_sha256() {
        // Test vector from FIPS 180-4
        let input = b"abc";
        let hash = sha256(input);
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_empty() {
        let input = b"";
        let hash = sha256(input);
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha512() {
        // Test vector from FIPS 180-4
        let input = b"abc";
        let hash = sha512(input);
        let expected = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha512_empty() {
        let input = b"";
        let hash = sha512(input);
        let expected = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_ed25519_keypair_generation() {
        let (secret_key, public_key, ssh_public_key) = generate_ed25519_keypair();
        
        // Ed25519 secret key should be 64 bytes (32 seed + 32 public)
        assert_eq!(secret_key.len(), 64, "Secret key should be 64 bytes");
        
        // Ed25519 public key should be 32 bytes
        assert_eq!(public_key.len(), 32, "Public key should be 32 bytes");
        
        // SSH public key should start with "ssh-ed25519"
        assert!(ssh_public_key.starts_with("ssh-ed25519"), 
                "SSH public key should start with 'ssh-ed25519'");
        
        // SSH public key should contain base64 encoded data
        let parts: Vec<&str> = ssh_public_key.split_whitespace().collect();
        assert!(parts.len() >= 2, "SSH public key should have at least 2 parts");
        
        println!("Generated Ed25519 keypair successfully");
        println!("Secret key (hex): {}", encode_hex(&secret_key));
        println!("Public key (hex): {}", encode_hex(&public_key));
        println!("SSH public key: {}", ssh_public_key);
    }

    #[test]
    fn test_ssh_ed25519_key_generation() {
        let ssh_key = generate_ssh_ed25519_key();
        
        // SSH key should start with "ssh-ed25519"
        assert!(ssh_key.starts_with("ssh-ed25519"), 
                "SSH key should start with 'ssh-ed25519'");
        
        println!("Generated SSH Ed25519 key: {}", ssh_key);
    }

    #[test]
    fn test_ed25519_key_uniqueness() {
        // Generate two different keypairs
        let (sk1, pk1, ssh1) = generate_ed25519_keypair();
        let (sk2, pk2, ssh2) = generate_ed25519_keypair();
        
        // Keys should be different (random generation)
        assert_ne!(sk1, sk2, "Secret keys should be different");
        assert_ne!(pk1, pk2, "Public keys should be different");
        assert_ne!(ssh1, ssh2, "SSH public keys should be different");
    }

    #[test]
    fn test_ed25519_keypair_consistency() {
        // Generate a keypair
        let (secret_key, public_key, _) = generate_ed25519_keypair();
        
        // The public key should be the last 32 bytes of the secret key
        let expected_public_key = &secret_key[32..64];
        assert_eq!(public_key, expected_public_key, 
                   "Public key should match last 32 bytes of secret key");
    }
}
