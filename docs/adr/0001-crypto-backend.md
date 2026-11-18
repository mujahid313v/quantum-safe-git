# ADR 0001: ML-DSA-65 backend

- Status: accepted for M1
- Date: 2026-11-03

## Decision

Use RustCrypto `ml-dsa` **0.1.2**, with its `zeroize` feature, and pin it exactly in Cargo.toml. It implements final FIPS 204 ML-DSA, including ML-DSA-65, and exposes context-taking deterministic and randomized signing and verification. Production `qsg_core::sign` uses the randomized (hedged) API with `getrandom::SysRng`, the OS CSPRNG; deterministic signing is limited to the ACVP test. This release is pre-1.0 and has not had an independent security audit; its README explicitly says it "has never been independently audited". It is maintained in RustCrypto's signatures repository. Its published licence is `Apache-2.0 OR MIT`. Version 0.1.2 was released on 2026-10-31, three days before this ADR's date.

This is pure Rust: no CMake, C compiler, OpenSSL, or libclang is required. The crate declares Rust 1.88 as its minimum; CI's stable Rust meets it. Ubuntu and macOS need no manual native setup. Context strings are limited to 255 bytes.

Official ACVP coverage is added using `crates/qsg-core/tests/fetch_acvp_vectors.py`. It downloads only the pinned NIST `internalProjection.json` files at commit `975de31eb83d87039ec88934fdc47d8c312b892d` (2026-08-12), extracts a small ML-DSA-65 subset into ignored `target/acvp/`, and does not redistribute NIST vector data. NIST's repository has no license file or SPDX license metadata. NIST's general copyright policy says works authored by NIST employees are not subject to copyright within the U.S., while foreign rights are reserved; therefore the helper downloads the vectors at test time rather than committing them. The helper and vector subset provenance are described in `crates/qsg-core/tests/ACVP-VECTORS.md`.

## Alternative considered: `oqs` on liboqs

`oqs` **0.11.0** corresponds to `oqs-sys 0.11.0+liboqs-0.13.0`, which builds liboqs release **0.13.0**. It provides `Algorithm::MlDsa65` and context-aware `sign_with_ctx_str` / `verify_with_ctx_str`. The Rust bindings and liboqs are MIT licensed (the bindings also offer Apache-2.0 terms). liboqs is **not independently audited and is not FIPS-validated**; upstream describes it as a research and prototyping library.

The binding can build vendored liboqs, but needs a native toolchain. On Ubuntu: CMake, a C compiler toolchain, libclang for bindgen, and pkg-config; OpenSSL development headers are needed when its default OpenSSL feature is enabled. On macOS: Xcode Command Line Tools, CMake, libclang, and pkg-config; OpenSSL headers/libraries are needed with that feature. `ml-dsa` avoids those native dependencies.

## Rationale and consequences

Both options target final ML-DSA-65, accept a context, and have upstream ACVP test coverage. RustCrypto keeps Linux/macOS CI free of native installation and reduces backend build variation. The tradeoff is a young, unaudited 0.1.x implementation. M1 pins the exact version; upgrades require review and known-answer coverage. The API retains context for later use of `QSGit-v1`.

### Secret key storage

The recommended on-disk private-key form is the 32-byte seed: the crate exposes `SigningKey::from_seed` and `to_seed`, and documents the seed as its preferred serialization. The 4032-byte expanded key is for in-memory use and interoperability with APIs/test vectors that require the expanded form. The current qsg-core API still exposes the M1-required 4032-byte form. The persistent storage choice is deferred to M3 (issue #53); M1 does not implement seed storage.

### Release changes

The crate changelog dates 0.1.2 to 2026-10-31; 0.1.1 was dated 2026-06-05. Changes in 0.1.2 include a `c_tilde` getter, heap placement for large signature components, reporting rejection-sampling exhaustion instead of panicking, a `module-lattice` update, row-wise expanded-matrix construction/cloning, public-key reuse during key generation, zeroization of SHAKE state with the feature enabled, stricter PKCS#8/SPKI algorithm parameters, oversized-context rejection in `compute_mu`, and constant-time fixes. See the [upstream changelog](https://github.com/RustCrypto/signatures/blob/master/ml-dsa/CHANGELOG.md).

References: [ml-dsa 0.1.2](https://crates.io/crates/ml-dsa/0.1.2), [RustCrypto source and tests](https://github.com/RustCrypto/signatures/tree/master/ml-dsa), [NIST ACVP vectors](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigGen-FIPS204), [`oqs` 0.11.0](https://crates.io/crates/oqs/0.11.0), [`oqs-sys` 0.11.0+liboqs-0.13.0](https://crates.io/crates/oqs-sys/0.11.0%2Bliboqs-0.13.0), [liboqs](https://github.com/open-quantum-safe/liboqs).
