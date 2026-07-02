# LockBox (`lb`)

A simple command-line file encryption tool written in Rust.

Encrypt any file with a password. The output is a `.lb` file that can only be decrypted with the same password.

---

## How it works

1. You provide a password
2. A random salt is generated, and your password + salt are fed into **Argon2id** to derive a strong AES-256 key
3. The file is encrypted using **AES-256-GCM**, which also produces an authentication tag
4. Everything needed to decrypt (salt, nonce, ciphertext + tag) is packed into a `.lb` file

If anyone tampers with the `.lb` file, decryption will fail — the authentication tag catches it.

---

## The `.lb` file format

```
Offset   Size   Field
0        4      Magic bytes: "LBOX"
4        1      Version (currently 1)
5        16     Salt (Argon2 input)
21       12     Nonce (AES-GCM input)
33       N+16   Ciphertext + GCM authentication tag
```

---

## Installation

Make sure you have [Rust installed](https://rustup.rs), then:

```bash
git clone https://github.com/yourusername/lockbox
cd lockbox
cargo build --release
```

The binary will be at `target/release/lb`.

---

## Usage

### Encrypt a file

```bash
lb encrypt secret.txt
```

You'll be prompted to enter and confirm a password. This produces `secret.txt.lb`.

Optionally delete the original after encrypting:

```bash
lb encrypt secret.txt --delete-original
```

### Decrypt a file

```bash
lb decrypt secret.txt.lb
```

You'll be prompted for the password. This produces `secret.txt` (strips the `.lb` extension).

Decrypt to a custom path:

```bash
lb decrypt secret.txt.lb -o output.txt
```

---

## Security notes

- **Argon2id** is used for key derivation with 64 MiB memory, 3 iterations, 4 lanes — deliberately slow to resist brute-force attacks
- **AES-256-GCM** provides both encryption and authentication
- The derived key is zeroed from memory immediately after use
- Salt and nonce are randomly generated per encryption — encrypting the same file twice produces different output every time
- If you lose your password, there is no recovery. The encryption is real.

---

## Dependencies

| Crate | Purpose |
|-------|---------|
| `aes-gcm` | AES-256-GCM encryption |
| `argon2` | Password-based key derivation |
| `clap` | CLI argument parsing |
| `rand` | Cryptographically secure random number generation |
| `rpassword` | Password input without terminal echo |
| `zeroize` | Securely wipe key from memory after use |
| `anyhow` | Error handling |