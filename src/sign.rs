//! ED25519 signing & verification compatible with ZygiskNext.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

use crate::key::{PrivateKey, PublicKey};

/// A file entry to be signed.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Relative path (e.g. "lib/arm64/libzygisk.so"), using `/` as separator.
    pub relative_path: String,
    /// File content.
    pub content: Vec<u8>,
}

/// A 96-byte signed blob: Ed25519 signature (64 bytes) followed by public key (32 bytes).
///
/// Use [`SignedBlob::as_bytes`] or [`SignedBlob::to_vec`] to serialize for writing to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlob {
    signature: [u8; 64],
    public_key: [u8; 32],
}

impl SignedBlob {
    /// Create from a 64-byte signature and 32-byte public key.
    pub fn new(signature: &[u8; 64], public_key: &[u8; 32]) -> Self {
        Self {
            signature: *signature,
            public_key: *public_key,
        }
    }

    /// Parse from raw bytes. Fails if not exactly 96 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignError> {
        if bytes.len() != 96 {
            return Err(SignError::InvalidBlob);
        }
        let mut signature = [0u8; 64];
        let mut public_key = [0u8; 32];
        signature.copy_from_slice(&bytes[..64]);
        public_key.copy_from_slice(&bytes[64..]);
        Ok(Self {
            signature,
            public_key,
        })
    }

    /// The 64-byte Ed25519 signature.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// The raw 96 bytes as a flat array.
    pub fn as_bytes(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[..64].copy_from_slice(&self.signature);
        bytes[64..].copy_from_slice(&self.public_key);
        bytes
    }

    /// Convert to an owned `Vec<u8>` (useful for mutation or FFI).
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

#[derive(Debug, PartialEq, Error)]
pub enum SignError {
    #[error("invalid private key bytes")]
    InvalidPrivateKey,
    #[error("invalid signed blob (expected 96 bytes)")]
    InvalidBlob,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("invalid module id: must match ^[a-zA-Z][a-zA-Z0-9._-]+$")]
    InvalidModuleId,
    #[error("public key mismatch")]
    PublicKeyMismatch,
}

/// Sign file entries, returning a 96-byte [`SignedBlob`].
///
/// The caller must ensure `entries` is sorted by relative path.
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

    Ok(SignedBlob::new(&signature.to_bytes(), &public_key))
}

/// Two-tier verification: mazoku (org authorization) → machikado (file integrity).
///
/// Returns `(true, None)` on success, `(false, Some(err))` on failure.
pub fn verify(
    machikado_blob: &[u8],
    mazoku_blob: &[u8],
    entries: &[FileEntry],
    module_id: &str,
    expected_org_pk: &PublicKey,
) -> (bool, Option<SignError>) {
    let machikado = match SignedBlob::from_bytes(machikado_blob) {
        Ok(b) => b,
        Err(e) => return (false, Some(e)),
    };

    let mazoku = match SignedBlob::from_bytes(mazoku_blob) {
        Ok(b) => b,
        Err(e) => return (false, Some(e)),
    };

    if mazoku.public_key() != expected_org_pk {
        return (false, Some(SignError::PublicKeyMismatch));
    }

    let mazoku_sig = Signature::from_bytes(mazoku.signature());
    let Ok(org_key) = VerifyingKey::from_bytes(mazoku.public_key()) else {
        return (false, Some(SignError::VerificationFailed));
    };
    let mut mazoku_data = Vec::with_capacity(module_id.len() + 1 + 32);
    mazoku_data.extend_from_slice(module_id.as_bytes());
    mazoku_data.push(0x00);
    mazoku_data.extend_from_slice(machikado.public_key());
    if org_key.verify(&mazoku_data, &mazoku_sig).is_err() {
        return (false, Some(SignError::VerificationFailed));
    }

    let machikado_sig = Signature::from_bytes(machikado.signature());
    let Ok(member_key) = VerifyingKey::from_bytes(machikado.public_key()) else {
        return (false, Some(SignError::VerificationFailed));
    };
    let file_data = build_signing_data(entries);
    if member_key.verify(&file_data, &machikado_sig).is_err() {
        return (false, Some(SignError::VerificationFailed));
    }

    (true, None)
}

/// Single-tier verification: machikado only (no mazoku).
///
/// The embedded public key in the machikado blob must match `expected_pk`.
pub fn verify_machikado(
    machikado_blob: &[u8],
    entries: &[FileEntry],
    expected_pk: &PublicKey,
) -> (bool, Option<SignError>) {
    let machikado = match SignedBlob::from_bytes(machikado_blob) {
        Ok(b) => b,
        Err(e) => return (false, Some(e)),
    };

    if machikado.public_key() != expected_pk {
        return (false, Some(SignError::PublicKeyMismatch));
    }

    let machikado_sig = Signature::from_bytes(machikado.signature());
    let Ok(member_key) = VerifyingKey::from_bytes(machikado.public_key()) else {
        return (false, Some(SignError::VerificationFailed));
    };
    let file_data = build_signing_data(entries);
    if member_key.verify(&file_data, &machikado_sig).is_err() {
        return (false, Some(SignError::VerificationFailed));
    }

    (true, None)
}

fn is_valid_module_id(id: &str) -> bool {
    if id.is_empty() {
        return false;
    }
    let first = id.as_bytes()[0];
    if !first.is_ascii_alphabetic() {
        return false;
    }
    id.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Sign mazoku (organization-level signature), returning a 96-byte [`SignedBlob`].
///
/// # Example
///
/// ```ignore
/// let mazoku = machikado_rs::sign_mazoku("my_module", &member_kp.public_key, &org_kp.private_key)?;
/// std::fs::write("mazoku", mazoku)?;
/// ```
pub fn sign_mazoku(
    module_id: &str,
    project_public_key: &PublicKey,
    org_private_key: &PrivateKey,
) -> Result<SignedBlob, SignError> {
    if !is_valid_module_id(module_id) {
        return Err(SignError::InvalidModuleId);
    }

    let signing_key = SigningKey::from_keypair_bytes(org_private_key)
        .map_err(|_| SignError::InvalidPrivateKey)?;
    let org_public_key = signing_key.verifying_key().to_bytes();

    let mut data = Vec::with_capacity(module_id.len() + 1 + 32);
    data.extend_from_slice(module_id.as_bytes());
    data.push(0x00);
    data.extend_from_slice(project_public_key);

    let signature = signing_key.sign(&data);
    Ok(SignedBlob::new(&signature.to_bytes(), &org_public_key))
}

fn build_signing_data(entries: &[FileEntry]) -> Vec<u8> {
    let mut data = Vec::new();
    for entry in entries {
        data.extend_from_slice(entry.relative_path.as_bytes());
        data.push(0);
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
        let org_kp = generate_keypair();
        let kp = generate_keypair();
        let entries = make_entries();
        let machikado = sign_file_entries(&entries, &kp.private_key).unwrap();
        assert_eq!(machikado.as_bytes().len(), 96);
        let mazoku = sign_mazoku("test", &kp.public_key, &org_kp.private_key).unwrap();
        assert_eq!(
            verify(
                &machikado.as_bytes(),
                &mazoku.as_bytes(),
                &entries,
                "test",
                &org_kp.public_key
            ),
            (true, None)
        );
    }

    #[test]
    fn test_tampered_content_fails() {
        let org_kp = generate_keypair();
        let kp = generate_keypair();
        let entries = make_entries();
        let machikado = sign_file_entries(&entries, &kp.private_key).unwrap();
        let mazoku = sign_mazoku("test", &kp.public_key, &org_kp.private_key).unwrap();

        let mut bad = entries.clone();
        bad[1].content = b"tampered!".to_vec();
        let (ok, err) = verify(
            &machikado.as_bytes(),
            &mazoku.as_bytes(),
            &bad,
            "test",
            &org_kp.public_key,
        );
        assert!(!ok);
        assert_eq!(err, Some(SignError::VerificationFailed));
    }

    #[test]
    fn test_tampered_path_fails() {
        let org_kp = generate_keypair();
        let kp = generate_keypair();
        let entries = make_entries();
        let machikado = sign_file_entries(&entries, &kp.private_key).unwrap();
        let mazoku = sign_mazoku("test", &kp.public_key, &org_kp.private_key).unwrap();

        let mut bad = entries.clone();
        bad[1].relative_path = "lib/x86/libzygisk.so".into();
        let (ok, err) = verify(
            &machikado.as_bytes(),
            &mazoku.as_bytes(),
            &bad,
            "test",
            &org_kp.public_key,
        );
        assert!(!ok);
        assert_eq!(err, Some(SignError::VerificationFailed));
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
        let org_kp = generate_keypair();
        let kp = generate_keypair();
        let machikado = sign_file_entries(&[], &kp.private_key).unwrap();
        assert_eq!(machikado.as_bytes().len(), 96);
        let mazoku = sign_mazoku("test", &kp.public_key, &org_kp.private_key).unwrap();
        assert_eq!(
            verify(
                &machikado.as_bytes(),
                &mazoku.as_bytes(),
                &[],
                "test",
                &org_kp.public_key
            ),
            (true, None)
        );
    }

    #[test]
    fn test_invalid_blob_length() {
        let org_kp = generate_keypair();
        let kp = generate_keypair();
        let entries = make_entries();
        let mazoku = sign_mazoku("test", &kp.public_key, &org_kp.private_key).unwrap();
        let (ok, err) = verify(
            b"too_short",
            &mazoku.as_bytes(),
            &entries,
            "test",
            &org_kp.public_key,
        );
        assert!(!ok);
        assert_eq!(err, Some(SignError::InvalidBlob));
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
        let org_kp = generate_keypair();
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let entries = make_entries();

        let machikado = sign_file_entries(&entries, &kp1.private_key).unwrap();
        let machikado2 = sign_file_entries(&entries, &kp2.private_key).unwrap();
        let mazoku = sign_mazoku("test", &kp1.public_key, &org_kp.private_key).unwrap();

        assert_eq!(
            verify(
                &machikado.as_bytes(),
                &mazoku.as_bytes(),
                &entries,
                "test",
                &org_kp.public_key
            ),
            (true, None)
        );

        let mut hybrid = machikado2.signature().to_vec();
        hybrid.extend_from_slice(machikado.public_key());
        let (ok, err) = verify(
            &hybrid,
            &mazoku.as_bytes(),
            &entries,
            "test",
            &org_kp.public_key,
        );
        assert!(!ok);
        assert_eq!(err, Some(SignError::VerificationFailed));
    }

    #[test]
    fn test_machikado_and_mazoku_full_flow() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let entries = make_entries();
        let module_id = "test_module";
        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        assert_eq!(machikado.as_bytes().len(), 96);
        let mazoku = sign_mazoku(module_id, &member_kp.public_key, &org_kp.private_key).unwrap();
        assert_eq!(mazoku.as_bytes().len(), 96);
        assert_eq!(
            verify(
                &machikado.as_bytes(),
                &mazoku.as_bytes(),
                &entries,
                module_id,
                &org_kp.public_key
            ),
            (true, None)
        );
    }

    #[test]
    fn test_mazoku_tampered_module_id_fails() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let entries = make_entries();
        let module_id = "correct_id";
        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        let mazoku = sign_mazoku(module_id, &member_kp.public_key, &org_kp.private_key).unwrap();

        assert_eq!(
            verify(
                &machikado.as_bytes(),
                &mazoku.as_bytes(),
                &entries,
                module_id,
                &org_kp.public_key
            ),
            (true, None)
        );

        let (ok, err) = verify(
            &machikado.as_bytes(),
            &mazoku.as_bytes(),
            &entries,
            "tampered_id",
            &org_kp.public_key,
        );
        assert!(!ok);
        assert_eq!(err, Some(SignError::VerificationFailed));
    }

    #[test]
    fn test_mazoku_wrong_member_pubkey_fails() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let other_member = generate_keypair();
        let entries = make_entries();
        let module_id = "my_module";

        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        let mazoku = sign_mazoku(module_id, &other_member.public_key, &org_kp.private_key).unwrap();

        let (ok, err) = verify(
            &machikado.as_bytes(),
            &mazoku.as_bytes(),
            &entries,
            module_id,
            &org_kp.public_key,
        );
        assert!(!ok);
        assert_eq!(err, Some(SignError::VerificationFailed));
    }

    #[test]
    fn test_mazoku_wrong_org_key_fails() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let entries = make_entries();
        let module_id = "some_module";

        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        let mazoku = sign_mazoku(module_id, &member_kp.public_key, &org_kp.private_key).unwrap();

        let mut tampered = mazoku.to_vec();
        tampered[80] ^= 0xFF;
        let (ok, err) = verify(
            &machikado.as_bytes(),
            &tampered,
            &entries,
            module_id,
            &org_kp.public_key,
        );
        assert!(!ok);
        assert!(matches!(
            err,
            Some(SignError::VerificationFailed | SignError::PublicKeyMismatch)
        ));

        assert_eq!(
            verify(
                &machikado.as_bytes(),
                &mazoku.as_bytes(),
                &entries,
                module_id,
                &org_kp.public_key
            ),
            (true, None)
        );
    }

    #[test]
    fn test_verify_mismatched_member_keys() {
        let org_kp = generate_keypair();
        let alice = generate_keypair();
        let bob = generate_keypair();
        let entries = make_entries();
        let module_id = "build_module";

        let machikado = sign_file_entries(&entries, &alice.private_key).unwrap();
        let mazoku = sign_mazoku(module_id, &bob.public_key, &org_kp.private_key).unwrap();

        let (ok, err) = verify(
            &machikado.as_bytes(),
            &mazoku.as_bytes(),
            &entries,
            module_id,
            &org_kp.public_key,
        );
        assert!(!ok);
        assert_eq!(err, Some(SignError::VerificationFailed));
    }

    #[test]
    fn test_verify_tampered_files_after_valid_mazoku() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let entries = make_entries();
        let module_id = "build_module";

        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        let mazoku = sign_mazoku(module_id, &member_kp.public_key, &org_kp.private_key).unwrap();

        assert_eq!(
            verify(
                &machikado.as_bytes(),
                &mazoku.as_bytes(),
                &entries,
                module_id,
                &org_kp.public_key
            ),
            (true, None)
        );

        let mut bad = entries.clone();
        bad[0].content = b"hacked".to_vec();
        let (ok, err) = verify(
            &machikado.as_bytes(),
            &mazoku.as_bytes(),
            &bad,
            module_id,
            &org_kp.public_key,
        );
        assert!(!ok);
        assert_eq!(err, Some(SignError::VerificationFailed));
    }

    #[test]
    fn test_verify_bad_mazoku_module_id() {
        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let entries = make_entries();
        let module_id = "the_real_id";

        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        let mazoku = sign_mazoku(module_id, &member_kp.public_key, &org_kp.private_key).unwrap();

        let (ok, err) = verify(
            &machikado.as_bytes(),
            &mazoku.as_bytes(),
            &entries,
            "wrong_id",
            &org_kp.public_key,
        );
        assert!(!ok);
        assert_eq!(err, Some(SignError::VerificationFailed));
    }

    /// End-to-end: write machikado + mazoku to a temp dir, then verify from disk.
    #[test]
    fn test_write_and_verify_machikado_mazoku_on_disk() {
        use std::fs;

        let org_kp = generate_keypair();
        let member_kp = generate_keypair();
        let module_id = "some_module";

        let dir = make_temp_module_dir();
        fs::write(dir.join("machikado"), b"placeholder").unwrap();
        fs::write(dir.join("mazoku"), b"placeholder").unwrap();

        let entries = load_entries(&dir, &["machikado", "mazoku"]);
        assert!(!entries.is_empty(), "should have module files to sign");

        let machikado = sign_file_entries(&entries, &member_kp.private_key).unwrap();
        let mazoku = sign_mazoku(module_id, &member_kp.public_key, &org_kp.private_key).unwrap();
        assert_eq!(machikado.as_bytes().len(), 96);
        assert_eq!(mazoku.as_bytes().len(), 96);

        fs::write(dir.join("machikado"), machikado.as_bytes()).unwrap();
        fs::write(dir.join("mazoku"), mazoku.as_bytes()).unwrap();

        let machikado_from_disk = fs::read(dir.join("machikado")).unwrap();
        let mazoku_from_disk = fs::read(dir.join("mazoku")).unwrap();
        assert_eq!(machikado_from_disk, &machikado.as_bytes()[..]);
        assert_eq!(mazoku_from_disk, &mazoku.as_bytes()[..]);

        let entries_v = load_entries(&dir, &["machikado", "mazoku"]);
        assert_eq!(entries_v.len(), entries.len());

        assert_eq!(
            verify(
                &machikado_from_disk,
                &mazoku_from_disk,
                &entries_v,
                module_id,
                &org_kp.public_key
            ),
            (true, None)
        );
    }

    /// Signing with one file excluded produces a different signature
    /// than signing with that file included.
    #[test]
    fn test_ignore_consistency() {
        let org_kp = generate_keypair();
        let kp = generate_keypair();
        let dir = make_temp_module_dir();

        let all = load_entries(&dir, &[]);
        let filtered = load_entries(&dir, &["sig.txt"]);

        let sig_all = sign_file_entries(&all, &kp.private_key).unwrap();
        let sig_filtered = sign_file_entries(&filtered, &kp.private_key).unwrap();

        assert_ne!(sig_all, sig_filtered);

        let mazoku = sign_mazoku("test", &kp.public_key, &org_kp.private_key).unwrap();
        assert_eq!(
            verify(
                &sig_filtered.as_bytes(),
                &mazoku.as_bytes(),
                &filtered,
                "test",
                &org_kp.public_key
            ),
            (true, None)
        );
    }

    /// End-to-end: sign, simulate customize.sh + Magisk modification, verify with mapping.
    #[test]
    fn test_user_scenario_module_prop_backup() {
        use crate::{FileMapping, load_folder_files};
        use std::fs;

        let org_kp = generate_keypair();
        let member_kp = generate_keypair();

        let dir = std::env::temp_dir().join(format!("machikado_user_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(dir.join("webroot")).unwrap();

        fs::write(
            dir.join("module.prop"),
            b"id=test\nname=Test\nversion=v1.0\n",
        )
        .unwrap();
        fs::write(
            dir.join("customize.sh"),
            b"#!/bin/sh\ncp module.prop module.prop.orig\n",
        )
        .unwrap();
        fs::write(dir.join("config.toml"), b"key = \"value\"\n").unwrap();
        fs::write(dir.join("webroot/index.html"), b"<html></html>\n").unwrap();

        let entries_sign = load_folder_files(&dir, &[], &["customize.sh", "mazoku"], None).unwrap();
        assert!(!entries_sign.is_empty());
        let machikado = sign_file_entries(&entries_sign, &member_kp.private_key).unwrap();
        let mazoku = sign_mazoku("test", &member_kp.public_key, &org_kp.private_key).unwrap();

        fs::copy(dir.join("module.prop"), dir.join("module.prop.orig")).unwrap();
        fs::remove_file(dir.join("customize.sh")).ok();

        fs::write(
            dir.join("module.prop"),
            b"id=test\nname=Test (NXT)\nversion=v1.0\n",
        )
        .unwrap();

        fs::write(dir.join("machikado"), machikado.as_bytes()).unwrap();
        fs::write(dir.join("mazoku"), mazoku.as_bytes()).unwrap();

        let mapping = FileMapping::from(("module.prop", "module.prop.orig"));
        let entries_verify =
            load_folder_files(&dir, &[], &["machikado", "mazoku"], Some(&mapping)).unwrap();

        assert_eq!(
            entries_verify.len(),
            entries_sign.len(),
            "verify entries count differs from sign entries count"
        );

        for (s, v) in entries_sign.iter().zip(entries_verify.iter()) {
            assert_eq!(
                s.relative_path, v.relative_path,
                "path mismatch: sign='{}' vs verify='{}'",
                s.relative_path, v.relative_path
            );
            assert_eq!(
                s.content, v.content,
                "content mismatch for '{}'",
                s.relative_path
            );
        }

        assert_eq!(
            verify(
                &machikado.as_bytes(),
                &mazoku.as_bytes(),
                &entries_verify,
                "test",
                &org_kp.public_key
            ),
            (true, None)
        );
    }

    #[test]
    fn test_verify_machikado_roundtrip() {
        let kp = generate_keypair();
        let entries = make_entries();
        let machikado = sign_file_entries(&entries, &kp.private_key).unwrap();
        assert_eq!(
            verify_machikado(&machikado.as_bytes(), &entries, &kp.public_key),
            (true, None)
        );
    }

    #[test]
    fn test_verify_machikado_wrong_pk() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        let entries = make_entries();
        let machikado = sign_file_entries(&entries, &kp1.private_key).unwrap();
        let (ok, err) = verify_machikado(&machikado.as_bytes(), &entries, &kp2.public_key);
        assert!(!ok);
        assert_eq!(err, Some(SignError::PublicKeyMismatch));
    }

    #[test]
    fn test_verify_machikado_tampered_files() {
        let kp = generate_keypair();
        let entries = make_entries();
        let machikado = sign_file_entries(&entries, &kp.private_key).unwrap();
        let mut bad = entries.clone();
        bad[0].content = b"hacked".to_vec();
        let (ok, err) = verify_machikado(&machikado.as_bytes(), &bad, &kp.public_key);
        assert!(!ok);
        assert_eq!(err, Some(SignError::VerificationFailed));
    }

    #[test]
    fn test_invalid_module_id_empty() {
        let org_kp = generate_keypair();
        let kp = generate_keypair();
        let err = sign_mazoku("", &kp.public_key, &org_kp.private_key).unwrap_err();
        assert_eq!(err, SignError::InvalidModuleId);
    }

    #[test]
    fn test_invalid_module_id_starts_with_digit() {
        let org_kp = generate_keypair();
        let kp = generate_keypair();
        let err = sign_mazoku("0abc", &kp.public_key, &org_kp.private_key).unwrap_err();
        assert_eq!(err, SignError::InvalidModuleId);
    }

    #[test]
    fn test_invalid_module_id_special_chars() {
        let org_kp = generate_keypair();
        let kp = generate_keypair();
        let err = sign_mazoku("ab c", &kp.public_key, &org_kp.private_key).unwrap_err();
        assert_eq!(err, SignError::InvalidModuleId);
    }

    #[test]
    fn test_valid_module_ids() {
        let org_kp = generate_keypair();
        let kp = generate_keypair();
        let entries = make_entries();

        for id in ["a", "Abc", "a.b", "a_b", "a-b", "A1.B2_C3-d4"] {
            let mazoku = sign_mazoku(id, &kp.public_key, &org_kp.private_key).unwrap();
            let machikado = sign_file_entries(&entries, &kp.private_key).unwrap();
            assert_eq!(
                verify(
                    &machikado.as_bytes(),
                    &mazoku.as_bytes(),
                    &entries,
                    id,
                    &org_kp.public_key
                ),
                (true, None)
            );
        }
    }

    #[test]
    fn test_verify_wrong_expected_org_pk() {
        let org_kp = generate_keypair();
        let other_org = generate_keypair();
        let kp = generate_keypair();
        let entries = make_entries();
        let machikado = sign_file_entries(&entries, &kp.private_key).unwrap();
        let mazoku = sign_mazoku("test", &kp.public_key, &org_kp.private_key).unwrap();

        let (ok, err) = verify(
            &machikado.as_bytes(),
            &mazoku.as_bytes(),
            &entries,
            "test",
            &other_org.public_key,
        );
        assert!(!ok);
        assert_eq!(err, Some(SignError::PublicKeyMismatch));
    }
}
