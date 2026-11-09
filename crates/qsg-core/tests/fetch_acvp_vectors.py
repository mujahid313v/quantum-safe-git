#!/usr/bin/env python3
"""Fetch a pinned, minimal ML-DSA-65 ACVP subset into ignored target/ data."""

import hashlib
import json
from pathlib import Path
from urllib.request import Request, urlopen


COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
BASE = f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{COMMIT}/gen-val/json-files"
ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "target" / "acvp" / "ml-dsa65-kat.txt"

# SHA-256 of the raw HTTP response bytes at the pinned commit.
# To update: change COMMIT, re-run, copy the hashes printed on mismatch.
SOURCE_SHA256 = {
    "ML-DSA-keyGen-FIPS204": "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf",
    "ML-DSA-sigGen-FIPS204": "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22",
    "ML-DSA-sigVer-FIPS204": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
}

# SHA-256 of the generated output file (LF line endings, ASCII).
# To update: run `sha256sum target/acvp/ml-dsa65-kat.txt` or
#   `(Get-FileHash target/acvp/ml-dsa65-kat.txt -Algorithm SHA256).Hash.ToLower()`
# after re-generating, and paste the hex below (lower-case).
OUTPUT_SHA256 = "e9130ae5edeab1972c10609c72cde1437920d318064cd6ca3b43dfc52d2f0e95"


def load_vector(directory):
    url = f"{BASE}/{directory}/internalProjection.json"
    request = Request(url, headers={"User-Agent": "QSGit-ACVP-test-helper"})
    with urlopen(request, timeout=90) as response:
        raw = response.read()
    actual = hashlib.sha256(raw).hexdigest()
    expected = SOURCE_SHA256[directory]
    if actual != expected:
        raise RuntimeError(
            f"Hash mismatch for {directory}/internalProjection.json\n"
            f"  expected: {expected}\n"
            f"  actual:   {actual}\n"
            f"  If the pinned commit changed, update SOURCE_SHA256 in this script."
        )
    data = json.loads(raw)
    if (data.get("algorithm"), data.get("revision")) != ("ML-DSA", "FIPS204"):
        raise RuntimeError(f"Unexpected ACVP metadata at {directory}")
    return data


def group(data, **properties):
    for item in data["testGroups"]:
        if all(item.get(key) == value for key, value in properties.items()):
            if item.get("parameterSet") == "ML-DSA-65":
                return item
    raise RuntimeError("Required ML-DSA-65 test group is missing")


def case(group_data, predicate):
    for item in group_data["tests"]:
        if predicate(item):
            return item
    raise RuntimeError("Required ACVP test case is missing")


def write_section(output, name, item, fields):
    output.append(f"[{name}]")
    output.append(f"tc_id={item['tcId']}")
    for output_name, vector_name in fields.items():
        output.append(f"{output_name}={item[vector_name]}")


def main():
    key_data = load_vector("ML-DSA-keyGen-FIPS204")
    key_group = group(key_data, testType="AFT")
    key_case = case(key_group, lambda item: "seed" in item and "pk" in item)

    gen_data = load_vector("ML-DSA-sigGen-FIPS204")
    gen_group = group(
        gen_data,
        testType="AFT",
        signatureInterface="external",
        preHash="pure",
        externalMu=False,
        deterministic=True,
    )
    gen_case = case(gen_group, lambda item: all(k in item for k in ("sk", "message", "context", "signature")))

    ver_data = load_vector("ML-DSA-sigVer-FIPS204")
    ver_group = group(
        ver_data,
        testType="AFT",
        signatureInterface="external",
        preHash="pure",
        externalMu=False,
    )
    ver_pass = case(ver_group, lambda item: item.get("testPassed") is True)
    ver_fail = case(ver_group, lambda item: item.get("testPassed") is False)

    lines = [
        f"source_commit={COMMIT}",
        "source_commit_date=2026-08-12",
    ]
    write_section(lines, "keygen", key_case, {"seed": "seed", "public_key": "pk"})
    write_section(
        lines,
        "siggen_deterministic",
        gen_case,
        {"secret_key": "sk", "message": "message", "context": "context", "signature": "signature"},
    )
    fields = {"public_key": "pk", "message": "message", "context": "context", "signature": "signature"}
    write_section(lines, "sigver_pass", ver_pass, fields)
    write_section(lines, "sigver_fail", ver_fail, fields)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    # Only metadata and test IDs are printed; vector bytes are never logged.
    print(
        "Fetched pinned NIST ML-DSA-65 ACVP subset: "
        f"keyGen tcId {key_case['tcId']}, sigGen tcId {gen_case['tcId']}, "
        f"sigVer tcIds {ver_pass['tcId']} (pass), {ver_fail['tcId']} (fail)."
    )


if __name__ == "__main__":
    main()
