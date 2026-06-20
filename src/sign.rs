//! ED25519 signing & verification.
//!
//! Signing protocol is compatible with ZygiskNext.
//! For each file, the following is fed into the signature:
//!   filename, then 0x00, then file_size as LE u64, then file_content.
//! All file data is accumulated and signed once.
//! Returns a 96-byte blob: signature (64 bytes) followed by public key (32 bytes).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::key::{PrivateKey, PublicKey};

/// A file entry to be signed.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Relative path (e.g. "lib/arm64/libzygisk.so"), using `/` as separator.
    pub relative_path: String,
    /// File content.
    pub content: Vec<u8>,
}

/// Signature result: 96 bytes = signature(64) followed by public_key(32).
///
/// Can be written directly to a machikado file.
pub type SignedBlob = Vec<u8>;

/// Signing/verification error.
#[derive(Debug)]
pub enum SignError {
    InvalidPrivateKey,
    InvalidBlob,
    VerificationFailed,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::InvalidPrivateKey => write!(f, "invalid private key bytes"),
            SignError::InvalidBlob => write!(f, "invalid signed blob (expected 96 bytes)"),
            SignError::VerificationFailed => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for SignError {}

/// Sign file entries, returning a 96-byte blob.
///
/// The caller must ensure `entries` is sorted by relative path.
/// Signing protocol: for each entry, concatenate
/// `relative_path`, `0x00`, `content.len().to_le_bytes()`, `content`,
/// accumulate, then sign once.
///
/// # Example
///
/// ```ignore
/// let entries = machikado_rs::load_folder_files(module_dir, &[\".git\"], &[])?;
/// let blob = machikado_rs::sign_file_entries(&entries, &private_key)?;
/// std::fs::write("machikado", blob)?;
/// ```
pub fn sign_file_entries(
    entries: &[FileEntry],
    private_key: &[u8; 64],
) -> Result<SignedBlob, SignError> {
    let signing_key =
        SigningKey::from_keypair_bytes(private_key).map_err(|_| SignError::InvalidPrivateKey)?;
    let public_key = signing_key.verifying_key().to_bytes();

    let data = build_signing_data(entries);
    let signature = signing_key.sign(&data);

    // 96 bytes = signature(64) || public_key(32)
    let mut blob = Vec::with_capacity(96);
    blob.extend_from_slice(&signature.to_bytes());
    blob.extend_from_slice(&public_key);
    Ok(blob)
}

/// Verify a 96-byte signed blob.
///
/// Extracts the public key from the last 32 bytes of the blob.
///
/// # Example
///
/// ```ignore
/// let blob = std::fs::read("machikado")?;
/// let entries = machikado_rs::load_folder_files(module_dir, &[".git"], &["machikado", "mazoku"])?;
/// machikado_rs::verify_signed_blob(&entries, &blob)?;
/// ```
pub fn verify_signed_blob(entries: &[FileEntry], signed_blob: &[u8]) -> Result<(), SignError> {
    if signed_blob.len() != 96 {
        return Err(SignError::InvalidBlob);
    }

    // First 64 bytes = signature, last 32 bytes = public key
    let signature_bytes: &[u8; 64] = signed_blob[..64]
        .try_into()
        .map_err(|_| SignError::InvalidBlob)?;
    let public_key_bytes: &[u8; 32] = signed_blob[64..]
        .try_into()
        .map_err(|_| SignError::InvalidBlob)?;

    let signature = Signature::from_bytes(signature_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(public_key_bytes).map_err(|_| SignError::VerificationFailed)?;

    let data = build_signing_data(entries);
    verifying_key
        .verify(&data, &signature)
        .map_err(|_| SignError::VerificationFailed)
}

// ── mazoku ──────────────────────────────────────────────────────────

/// Sign mazoku (organization-level signature).
///
/// The signed data is `env_content` followed by `machikado_public_key`,
/// signed with the organization private key (`org_private_key`).
/// Returns a 96-byte blob: signature(64) followed by org_public_key(32).
///
/// # Example
///
/// ```ignore
/// let env = std::env::var("SIGN_ENV").unwrap_or_default();
/// let mazoku = machikado_rs::sign_mazoku(env.as_bytes(), &member_kp.public_key, &org_kp.private_key)?;
/// std::fs::write("mazoku", mazoku)?;
/// ```
pub fn sign_mazoku(
    env_content: &[u8],
    machikado_public_key: &PublicKey,
    org_private_key: &PrivateKey,
) -> Result<SignedBlob, SignError> {
    let signing_key = SigningKey::from_keypair_bytes(org_private_key)
        .map_err(|_| SignError::InvalidPrivateKey)?;
    let org_public_key = signing_key.verifying_key().to_bytes();

    // mazoku signed data: env_content followed by machikado_public_key
    let mut data = Vec::with_capacity(env_content.len() + 32);
    data.extend_from_slice(env_content);
    data.extend_from_slice(machikado_public_key);

    let signature = signing_key.sign(&data);

    let mut blob = Vec::with_capacity(96);
    blob.extend_from_slice(&signature.to_bytes());
    blob.extend_from_slice(&org_public_key);
    Ok(blob)
}

/// Verify mazoku.
///
/// Extracts the org public key from the tail of the mazoku blob,
/// verifies the signature over `env_content` followed by `machikado_public_key`.
/// The `machikado_public_key` comes from the last 32 bytes of the machikado blob.
///
/// A successful verification means the machikado public key is authorized by the org.
pub fn verify_mazoku(
    mazoku_blob: &[u8],
    env_content: &[u8],
    machikado_public_key: &PublicKey,
) -> Result<(), SignError> {
    if mazoku_blob.len() != 96 {
        return Err(SignError::InvalidBlob);
    }

    let signature_bytes: &[u8; 64] = mazoku_blob[..64]
        .try_into()
        .map_err(|_| SignError::InvalidBlob)?;
    let org_public_key_bytes: &[u8; 32] = mazoku_blob[64..]
        .try_into()
        .map_err(|_| SignError::InvalidBlob)?;

    let signature = Signature::from_bytes(signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(org_public_key_bytes)
        .map_err(|_| SignError::VerificationFailed)?;

    let mut data = Vec::with_capacity(env_content.len() + 32);
    data.extend_from_slice(env_content);
    data.extend_from_slice(machikado_public_key);

    verifying_key
        .verify(&data, &signature)
        .map_err(|_| SignError::VerificationFailed)
}

/// Full two-tier verification: mazoku first, then machikado.
///
/// 1. Extract the member public key from the machikado blob
/// 2. Verify mazoku (org authorizes this member key)
/// 3. Verify machikado (files signed by this member)
///
/// Fails immediately if any step fails.
pub fn verify_full(
    machikado_blob: &[u8],
    mazoku_blob: &[u8],
    entries: &[FileEntry],
    env_content: &[u8],
) -> Result<(), SignError> {
    // 1. extract member public key from machikado blob
    if machikado_blob.len() != 96 {
        return Err(SignError::InvalidBlob);
    }
    let member_pubkey: &PublicKey = machikado_blob[64..]
        .try_into()
        .map_err(|_| SignError::InvalidBlob)?;

    // 2. verify mazoku: org authorizes this member key
    verify_mazoku(mazoku_blob, env_content, member_pubkey)?;

    // 3. verify machikado: files signed by this member
    verify_signed_blob(entries, machikado_blob)
}

fn build_signing_data(entries: &[FileEntry]) -> Vec<u8> {
    let mut data = Vec::new();
    for entry in entries {
        data.extend_from_slice(entry.relative_path.as_bytes());
        data.push(0); // null terminator
        data.extend_from_slice(&(entry.content.len() as u64).to_le_bytes());
        data.extend_from_slice(&entry.content);
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;

    fn make_entries() -> Vec<FileEntry> {
        vec![
            FileEntry {
                relative_path: "bin/zygiskd64".into(),
                content: b"binary_content_64".to_vec(),
            },
            FileEntry {
                relative_path: "lib/arm64/libzygisk.so".into(),
                content: b"library_content".to_vec(),
            },
            FileEntry {
                relative_path: "module.prop".into(),
                content: b"id=module\nname=test\n".to_vec(),
            },
        ]
    }

    fn make_temp_module_dir() -> std::path::PathBuf {
        use std::fs;
        let dir = std::env::temp_dir().join(format!("machikado_sig_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        fs::write(dir.join("sub/b.txt"), b"world").unwrap();
        fs::write(dir.join("sig.txt"), b"signature_placeholder").unwrap();
        dir
    }

    fn load_entries(dir: &std::path::Path, ignore_names: &[&str]) -> Vec<FileEntry> {
        use crate::load_folder_files;
        load_folder_files(dir, &[], ignore_names, None).unwrap()
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let kp = generate_keypair();
        let entries = make_entries();
        let blob = sign_file_entries(&entries, &kp.private_key).unwrap();
        assert_eq!(blob.len(), 96);
        verify_signed_blob(&entries, &blob).unwrap();
    }

    #[test]
    fn test_tampered_content_fails() {
        let kp = generate_keypair();
        let entries = make_entries();
        let blob = sign_file_entries(&entries, &kp.private_key).unwrap();

        let mut bad = entries.clone();
        bad[1].content = b"tampered!".to_vec();
        let err = verify_signed_blob(&bad, &blob).unwrap_err();
        assert!(matches!(err, SignError::VerificationFailed));
    }

    #[test]
    fn test_tampered_path_fails() {
        let kp = generate_keypair();
        let entries = make_entries();
        let blob = sign_file_entries(&entries, &kp.private_key).unwrap();

        let mut bad = entries.clone();
        bad[1].relative_path = "lib/x86/libzygisk.so".into();
        let err = verify_signed_blob(&bad, &blob).unwrap_err();
        assert!(matches!(err, SignError::VerificationFailed));
    }

    #[test]
    fn test_order_matters() {
        let kp = generate_keypair();
        let mut entries = make_entries();
        let blob1 = sign_file_entries(&entries, &kp.private_key).unwrap();

        entries.swap(0, 2);
        let blob2 = sign_file_entries(&entries, &kp.private_key).unwrap();
        assert_ne!(blob1, blob2);
    }

    #[test]
    fn test_empty_entries() {
        let kp = generate_keypair();
        let blob = sign_file_entries(&[], &kp.private_key).unwrap();
        assert_eq!(blob.len(), 96);
        verify_signed_blob(&[], &blob).unwrap();
    }

    #[test]
    fn test_invalid_blob_length() {
        let entries = make_entries();
        let err = verify_signed_blob(&entries, b"too_short").unwrap_err();
        assert!(matches!(err, SignError::InvalidBlob));
    }

    #[test]
    fn test_invalid_private_key() {
        let bad_key = [0u8; 64];
        let entries = make_entries();
        let err = sign_file_entries(&entries, &bad_key).unwrap_err();
        assert!(matches!(err, SignError::InvalidPrivateKey));
    }

    #[test]
    fn test_verify_with_wrong_blob_fails() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let entries = make_entries();

        let blob = sign_file_entries(&entries, &kp1.private_key).unwrap();
        let blob2 = sign_file_entries(&entries, &kp2.private_key).unwrap();

        verify_signed_blob(&entries, &blob).unwrap();

        let mut hybrid = Vec::from(&blob2[..64]);
        hybrid.extend_from_slice(&blob[64..]);
        let err = verify_signed_blob(&entries, &hybrid).unwrap_err();
        assert!(matches!(err, SignError::VerificationFailed));
    }
    #[test]
    fn test_machikado_and_mazoku_full_flow() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let entries = make_entries();
        let env = b"some_arbitrary_env_data";
        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        assert_eq!(machikado.len(), 96);
        let mazoku = sign_mazoku(env, &member_kp.public_key, &org_kp.private_key).unwrap();
        assert_eq!(mazoku.len(), 96);
        verify_mazoku(&mazoku, env, &member_kp.public_key).unwrap();
        verify_signed_blob(&entries, &machikado).unwrap();
        verify_full(&machikado, &mazoku, &entries, env).unwrap();
    }

    #[test]
    fn test_mazoku_tampered_env_fails() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let env = b"correct_env";
        let mazoku = sign_mazoku(env, &member_kp.public_key, &org_kp.private_key).unwrap();
        let bad_env = b"tampered_env";
        let err = verify_mazoku(&mazoku, bad_env, &member_kp.public_key).unwrap_err();
        assert!(matches!(err, SignError::VerificationFailed));
    }

    #[test]
    fn test_mazoku_wrong_member_pubkey_fails() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let other_member = generate_keypair();
        let env = b"some_env";

        let mazoku = sign_mazoku(env, &member_kp.public_key, &org_kp.private_key).unwrap();

        let err = verify_mazoku(&mazoku, env, &other_member.public_key).unwrap_err();
        assert!(matches!(err, SignError::VerificationFailed));
    }

    #[test]
    fn test_mazoku_wrong_org_key_fails() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let env = b"some_env";

        let mazoku = sign_mazoku(env, &member_kp.public_key, &org_kp.private_key).unwrap();

        let mut tampered = mazoku.clone();
        tampered[80] ^= 0xFF;
        let err = verify_mazoku(&tampered, env, &member_kp.public_key).unwrap_err();
        assert!(matches!(err, SignError::VerificationFailed));

        verify_mazoku(&mazoku, env, &member_kp.public_key).unwrap();
    }

    #[test]
    fn test_verify_full_mismatched_member_keys() {
        let org_kp = generate_keypair();
        let alice = generate_keypair();
        let bob = generate_keypair();
        let entries = make_entries();
        let env = b"build_env_data";

        let machikado = sign_file_entries(&entries, &alice.private_key).unwrap();
        let mazoku = sign_mazoku(env, &bob.public_key, &org_kp.private_key).unwrap();

        let err = verify_full(&machikado, &mazoku, &entries, env).unwrap_err();
        assert!(matches!(err, SignError::VerificationFailed));
    }

    #[test]
    fn test_verify_full_tampered_files_after_valid_mazoku() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let entries = make_entries();
        let env = b"build_env_data";

        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        let mazoku = sign_mazoku(env, &member_kp.public_key, &org_kp.private_key).unwrap();

        verify_full(&machikado, &mazoku, &entries, env).unwrap();

        let mut bad = entries.clone();
        bad[0].content = b"hacked".to_vec();
        let err = verify_full(&machikado, &mazoku, &bad, env).unwrap_err();
        assert!(matches!(err, SignError::VerificationFailed));
    }

    #[test]
    fn test_verify_full_bad_mazoku_env() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let entries = make_entries();
        let env = b"the_real_env";

        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        let mazoku = sign_mazoku(env, &member_kp.public_key, &org_kp.private_key).unwrap();

        // env mismatch → verify_full fails at mazoku stage
        let err = verify_full(&machikado, &mazoku, &entries, b"wrong_env").unwrap_err();
        assert!(matches!(err, SignError::VerificationFailed));
    }

    /// End-to-end: write machikado + mazoku to a temp dir, then verify from disk.
    #[test]
    fn test_write_and_verify_machikado_mazoku_on_disk() {
        use std::fs;

        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let env = b"some_env_for_signing";

        // Create a temp module directory with real files
        let dir = make_temp_module_dir();
        // Also create dummy "machikado" and "mazoku" that will be overwritten
        fs::write(dir.join("machikado"), b"placeholder").unwrap();
        fs::write(dir.join("mazoku"), b"placeholder").unwrap();

        // Build time: load files, excluding the sig files themselves
        let entries = load_entries(&dir, &["machikado", "mazoku"]);
        assert!(!entries.is_empty(), "should have module files to sign");

        // Sign machikado and mazoku
        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        let mazoku = sign_mazoku(env, &member_kp.public_key, &org_kp.private_key).unwrap();
        assert_eq!(machikado.len(), 96);
        assert_eq!(mazoku.len(), 96);

        // Write them to disk
        fs::write(dir.join("machikado"), &machikado).unwrap();
        fs::write(dir.join("mazoku"), &mazoku).unwrap();

        // Verify time: read blobs from disk
        let machikado_from_disk = fs::read(dir.join("machikado")).unwrap();
        let mazoku_from_disk = fs::read(dir.join("mazoku")).unwrap();
        assert_eq!(machikado_from_disk, machikado);
        assert_eq!(mazoku_from_disk, mazoku);

        // Reload files (excluding sig files)
        let entries_v = load_entries(&dir, &["machikado", "mazoku"]);
        assert_eq!(entries_v.len(), entries.len());

        // Full two-tier verification
        verify_full(&machikado_from_disk, &mazoku_from_disk, &entries_v, env).unwrap();
    }

    /// Signing with one file excluded produces a different signature
    /// than signing with that file included.
    #[test]
    fn test_ignore_consistency() {
        let kp = generate_keypair();
        let dir = make_temp_module_dir();

        // Entries with all files (including the sig file placeholder)
        let all = load_entries(&dir, &[]);
        // Entries excluding "sig.txt"
        let filtered = load_entries(&dir, &["sig.txt"]);

        let sig_all = sign_file_entries(&all, &kp.private_key).unwrap();
        let sig_filtered = sign_file_entries(&filtered, &kp.private_key).unwrap();

        // With vs without the extra file → signatures differ
        assert_ne!(sig_all, sig_filtered);

        // Filtered signature verifies against filtered entries
        verify_signed_blob(&filtered, &sig_filtered).unwrap();
    }
}
