# machikado-rs

ED25519 signing library for the Machikado Mazoku module ecosystem.
Provides two-tier signature verification: **machikado** (file-level) and **mazoku** (org authorization).

## Concepts

| Term | Description |
|------|-------------|
| **org key** | Organization-level key pair. The org authorizes member/project keys via mazoku. |
| **member key** | Member/project-level key pair. Used to sign module files (machikado). |
| **machikado** | 96-byte blob: signature(64) + member_public_key(32). Signs all files in a module directory. |
| **mazoku** | 96-byte blob: signature(64) + org_public_key(32). Signs `env_content` + `member_public_key`. |

## Usage

### Generate keys (one-time setup)

```rust
use machikado_rs::generate_keypair;

let org_kp = generate_keypair();     // org key pair
let member_kp = generate_keypair();  // member key pair

// Save keys (keep private keys secret!)
std::fs::write("org_sk", org_kp.private_key)?;
std::fs::write("org_pk", org_kp.public_key)?;
std::fs::write("member_sk", member_kp.private_key)?;
std::fs::write("member_pk", member_kp.public_key)?;
```

### Build-time: sign module (xtask/CI)

```rust
use machikado_rs::{load_folder_files, sign_file_entries, sign_mazoku};

// Load module files, skip .git directory
let entries = load_folder_files(&module_dir, &[".git"], &[])?;

// Sign files with member key → machikado (96 bytes)
let machikado = sign_file_entries(&entries, &member_sk)?;
std::fs::write(module_dir.join("machikado"), &machikado)?;

// Sign env + member_pk with org key → mazoku (96 bytes)
let env = b"my_secret_env_string";  // arbitrary data, e.g. from CI secrets
let mazoku = sign_mazoku(env, &member_pk, &org_sk)?;
std::fs::write(module_dir.join("mazoku"), &mazoku)?;
```

### Verify-time: device-side check

```rust
use machikado_rs::{load_folder_files, verify_full};

let machikado = std::fs::read("module/machikado")?;
let mazoku    = std::fs::read("module/mazoku")?;
let env = b"my_secret_env_string";  // same arbitrary data, hardcoded in module source

// Load module files, excluding signature files themselves
let entries = load_folder_files(&module_dir, &[".git"], &["machikado", "mazoku"])?;

// Two-tier verification: mazoku first, then machikado
verify_full(&machikado, &mazoku, &entries, env)?;
// → Ok: module is trusted
```

### Verification flow

```
verify_full(machikado, mazoku, entries, env)
  │
  ├─ 1. Extract member_pk from machikado blob tail
  │
  ├─ 2. verify_mazoku(mazoku, env, member_pk)
  │      Extract org_pk from mazoku tail
  │      Verify signature over (env ‖ member_pk)
  │      → fails if org didn't authorize this member key
  │
  └─ 3. verify_signed_blob(entries, machikado)
         Verify signature over file data (ZygiskNext protocol)
         → fails if files were tampered
```

## API Reference

| Function | Description |
|----------|-------------|
| `generate_keypair()` | Generate random ED25519 key pair |
| `sign_file_entries(entries, member_sk)` | Sign file list → 96-byte machikado blob |
| `verify_signed_blob(entries, blob)` | Verify machikado blob against file list |
| `sign_mazoku(env, member_pk, org_sk)` | Sign env + member_pk → 96-byte mazoku blob |
| `verify_mazoku(blob, env, member_pk)` | Verify mazoku blob |
| `verify_full(machikado, mazoku, entries, env)` | Two-tier verification |
| `load_folder_files(dir, ignore_prefixes, ignore_names)` | Load + sort files from directory |

## Signing Protocol

Each file contributes to the signed data as:

```
relative_path ‖ 0x00 ‖ file_size(LE u64) ‖ file_content
```

All files are accumulated in sorted order (lexicographic by path with `/` separator),
then signed as a single ED25519 signature. This is compatible with ZygiskNext.

## AI based

The project was originally written using AI. If you have a cleanliness obsession, please don't use this.

| Version | TODO |
|---------|------|
| Since v0.0.x | Mostly AI-generated, with a small part done manually |
| Since v0.1.x | Replace the AI parts with handmade ones as much as possible |
| Since v1.x.x | Major overhaul, ditching the AI part |

## License

* [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0)