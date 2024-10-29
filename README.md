# signal-piv

`signal-piv` is a Unix Domain Socket (UDS) server that can perform YubiKey operations upon request.

## Building and Running

Using an up-to-date Rust toolchain, building and running is a matter of:

```bash
cargo run [--release]
```

The [Cargo.toml](./Cargo.toml) expects a [fork of yubikey.rs](https://github.com/sandbox-quantum/yubikey.rs/tree/gaetan-sbt/x25519) that supports X25519 operations to be present on the file system.