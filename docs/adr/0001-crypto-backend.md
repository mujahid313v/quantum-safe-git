# ADR 0001: ML-DSA-65 backend

- Status: accepted for M1
- Date: 2026-11-03

## Decision

Use RustCrypto `ml-dsa` **0.1.2**, with its `zeroize` feature, and pin it exactly in Cargo.toml. It implements final FIPS 204 ML-DSA, including ML-DSA-65, and exposes context-taking deterministic signing and verification. This release is pre-1.0 and has not had an independent security audit; treat it as experimental. It is maintained in RustCrypto's signatures repository. Its published licence is `Apache-2.0 OR MIT`.

This is pure Rust: no CMake, C compiler, OpenSSL, or libclang is required. The crate declares Rust 1.87 as its minimum; CI's stable Rust meets it. Ubuntu and macOS need no manual native setup. Context strings are limited to 255 bytes.

The upstream test suite documents the NIST ACVP ML-DSA FIPS 204 key-generation, signature-generation, and signature-verification internal-projection vectors. NIST's `usnistgov/ACVP-Server` repository publishes these vectors. U.S. government works are generally public domain in the United States under 17 U.S.C. section 105, but this does not automatically settle rights outside the U.S. or third-party contributions. This repository does not redistribute vector files. **M1 did not obtain or run an official vector locally.** Deterministic-signing repeatability is the next-best local check, not a KAT; direct ACVP-vector coverage remains TODO: verify/add.

## Alternative considered: `oqs` on liboqs

`oqs` **0.11.0** corresponds to `oqs-sys 0.11.0+liboqs-0.13.0`, which builds liboqs release **0.13.0**. It provides `Algorithm::MlDsa65` and context-aware `sign_with_ctx_str` / `verify_with_ctx_str`. The Rust bindings and liboqs are MIT licensed (the bindings also offer Apache-2.0 terms). liboqs is **not independently audited and is not FIPS-validated**; upstream describes it as a research and prototyping library.

The binding can build vendored liboqs, but needs a native toolchain. On Ubuntu: CMake, a C compiler toolchain, libclang for bindgen, and pkg-config; OpenSSL development headers are needed when its default OpenSSL feature is enabled. On macOS: Xcode Command Line Tools, CMake, libclang, and pkg-config; OpenSSL headers/libraries are needed with that feature. `ml-dsa` avoids those native dependencies.

## Rationale and consequences

Both options target final ML-DSA-65, accept a context, and have upstream ACVP test coverage. RustCrypto keeps Linux/macOS CI free of native installation and reduces backend build variation. The tradeoff is a young, unaudited 0.1.x implementation. M1 pins the exact version; upgrades require review and known-answer coverage. The API retains context for later use of `QSGit-v1`.

The requested core API exposes the 4032-byte expanded secret-key encoding. `ml-dsa` recommends a 32-byte seed as its canonical export and deprecates expanded-key import/export. M1 uses the expanded encoding to meet the requested size; revisit this compatibility point before defining stable key storage.

References: [ml-dsa 0.1.2](https://crates.io/crates/ml-dsa/0.1.2), [RustCrypto source and tests](https://github.com/RustCrypto/signatures/tree/master/ml-dsa), [NIST ACVP vectors](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigGen-FIPS204), [`oqs` 0.11.0](https://crates.io/crates/oqs/0.11.0), [`oqs-sys` 0.11.0+liboqs-0.13.0](https://crates.io/crates/oqs-sys/0.11.0%2Bliboqs-0.13.0), [liboqs](https://github.com/open-quantum-safe/liboqs).
