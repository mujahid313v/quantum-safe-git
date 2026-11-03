# ACVP test-vector provenance

`fetch_acvp_vectors.py` downloads a small subset of NIST's ACVP internal projection files at a fixed upstream revision and writes extracted hex values under ignored `target/acvp/`. No vector bytes are stored in this repository. Run the helper before `cargo test --workspace`:

```sh
python3 crates/qsg-core/tests/fetch_acvp_vectors.py
cargo test --workspace
```

Source: [NIST ACVP-Server `gen-val/json-files`](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files), commit `975de31eb83d87039ec88934fdc47d8c312b892d`, committed 2026-08-12. The helper retrieves `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204`, and `ML-DSA-sigVer-FIPS204/internalProjection.json`, all pinned to that commit. Retrieval date for this change: 2026-11-03. It selects parameter set `ML-DSA-65` only.

The upstream repository has no license file and GitHub's license endpoint reports no detected license. NIST's general copyright guidance says works authored by NIST employees are not subject to copyright within the United States, while foreign rights are reserved. The ACVP repository does not state a separate license for these generated vector files. Since redistribution rights are unclear, this project fetches the pinned data when tests run and does not commit vector contents. See [NIST copyright guidance](https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications) and the [NIST ACVP ML-DSA JSON specification](https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html).

The subset comprises one keyGen case (seed to expected public key), one deterministic sigGen case, one passing sigVer case, and one failing sigVer case. sigGen and sigVer use `signatureInterface=external`, `preHash=pure`, and `externalMu=false`; sigGen also sets `deterministic=true`. Thus the cases supply raw message bytes and a context. qsg-core's public `verify` API can directly consume the sigVer cases. qsg-core's public keygen API intentionally accepts no seed, and public `sign` uses hedged randomness; the keyGen and deterministic sigGen known-answer tests therefore call the lowest-level public API exposed by `ml-dsa` (`SigningKey::from_seed` and `ExpandedSigningKey::sign_deterministic`). This test set does not cover prehash or external-mu interfaces, which qsg-core does not expose.
