# machikado-rs

ED25519 signing for the Machikado Mazoku module ecosystem.
Two-tier: **machikado** (files) + **mazoku** (org auth).
Supports machikado-only mode for single-keypair scenarios.

## Concepts

| Term | Description |
|------|-------------|
| **org key** | Organization/team key pair. Authorizes projects via mazoku. |
| **member key** | Project key pair. Signs module files (machikado). |
| **machikado** | 96 bytes: `signature(64) ‖ member_pk(32)`. |
| **mazoku** | 96 bytes: `signature(64) ‖ org_pk(32)`, over `module_id ‖ 0x00 ‖ member_pk`. |

## Usage

### Generate keys

```rust
use machikado_rs::generate_keypair;

let org_kp = generate_keypair();
let member_kp = generate_keypair();

std::fs::write("org_sk", org_kp.private_key)?;
std::fs::write("member_sk", member_kp.private_key)?;
```

### Sign (build time)

```rust
use machikado_rs::{load_folder_files, sign_file_entries, sign_mazoku};

let module_id = "my_module";
let entries = load_folder_files(&module_dir, &[".git"], &[], None)?;

let machikado = sign_file_entries(&entries, &member_sk)?;
std::fs::write(module_dir.join("machikado"), machikado.as_bytes())?;

let mazoku = sign_mazoku(module_id, &member_pk, &org_sk)?;
std::fs::write(module_dir.join("mazoku"), mazoku.as_bytes())?;
```

### Verify two-tier (device side)

```rust
use machikado_rs::{load_folder_files, verify};

let module_id = "my_module";
let entries = load_folder_files(&dir, &[], &["machikado", "mazoku"], None)?;
let machikado = std::fs::read(dir.join("machikado"))?;
let mazoku = std::fs::read(dir.join("mazoku"))?;

let (ok, _) = verify(&machikado, &mazoku, &entries, module_id, &expected_org_pk);
assert!(ok);
```

### Verify machikado-only (single keypair)

```rust
use machikado_rs::{load_folder_files, sign_file_entries, verify_machikado};

let kp = generate_keypair();
let entries = load_folder_files(&dir, &[], &["machikado"], None)?;

// Sign
let machikado = sign_file_entries(&entries, &kp.private_key)?;

// Verify — embedded public key must match expected_pk
let (ok, _) = verify_machikado(&machikado.as_bytes(), &entries, &kp.public_key);
assert!(ok);
```

### File mapping

Map source paths to signed paths — for when `customize.sh` moves files at install time.

```rust
use machikado_rs::FileMapping;

// Arch-specific → generic
let mapping = FileMapping::from(("bin/zygiskd64", "bin/arm64-v8a/zygiskd"));

// Backup → original (for verification after Magisk modifies files)
let mapping = FileMapping::from(("module.prop", "module.prop.orig"));

// Multiple pairs
let mapping = FileMapping::from([
    ("bin/zygiskd64", "bin/arm64-v8a/zygiskd"),
    ("bin/zygiskd32", "bin/armeabi-v7a/zygiskd"),
]);

let entries = load_folder_files(&dir, &[], &[], Some(&mapping))?;
```

## API

| Function | Returns |
|----------|---------|
| `generate_keypair()` | `Ed25519KeyPair` |
| `sign_file_entries(&[FileEntry], &[u8; 64])` | `Result<SignedBlob, SignError>` |
| `sign_mazoku(&str, &[u8; 32], &[u8; 64])` | `Result<SignedBlob, SignError>` |
| `verify(&[u8], &[u8], &[FileEntry], &str, &[u8; 32])` | `(bool, Option<SignError>)` |
| `verify_machikado(&[u8], &[FileEntry], &[u8; 32])` | `(bool, Option<SignError>)` |
| `load_folder_files(&Path, &[&str], &[&str], Option<&FileMapping>)` | `io::Result<Vec<FileEntry>>` |

`SignedBlob` is a 96-byte newtype with `.as_bytes()`, `.to_vec()`, `.signature()`, `.public_key()`.

## Signing protocol

Compatible with ZygiskNext. Each file feeds into the signature as:

```
relative_path ‖ 0x00 ‖ file_size(LE u64) ‖ file_content
```

Accumulated in lexicographic order, signed once.

**mazoku** signing data: `module_id ‖ 0x00 ‖ project_public_key`, where `module_id` must match `^[a-zA-Z][a-zA-Z0-9._-]+$`.

Both `verify` and `verify_machikado` compare the embedded public key against a hardcoded expected key for integrity.

## License

* [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0)