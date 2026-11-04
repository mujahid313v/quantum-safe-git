use super::*;
use base64::engine::general_purpose::STANDARD;
use qsg_core::keygen;

fn key_blob() -> Vec<u8> {
    let (public, _secret) = keygen().expect("generate public test key");
    qsg_sshsig::encode_ml_dsa65_public_key_blob(&public).expect("encode test key blob")
}

fn line(blob: &[u8], principals: &str, options: &str) -> String {
    format!(
        "{principals} {options} {KEY_TYPE} {} test comment\n",
        STANDARD.encode(blob)
    )
}

fn ssh_string(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
    output
}

#[test]
fn parses_valid_lf_crlf_comments_and_duplicate_entries() {
    let blob = key_blob();
    let one = line(
        &blob,
        "alice@example.test,bob@example.test",
        "namespaces=\"git,tag\"",
    );
    let text = format!(
        "# comment\r\n\r\n{}{}",
        one.replace('\n', "\r\n"),
        one.replace('\n', "\r\n")
    );
    let parsed = parse_allowed_signers(&text).unwrap();
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(
        parsed.entries[0].principals,
        ["alice@example.test", "bob@example.test"]
    );
    assert_eq!(parsed.entries[0].namespaces, ["git", "tag"]);
    assert_eq!(
        parsed.entries[0].fingerprint,
        qsg_sshsig::fingerprint(&blob).unwrap()
    );
    assert!(parsed.skipped.is_empty());
}

#[test]
fn rejects_principal_and_option_errors_with_line_numbers() {
    let blob = key_blob();
    let cases = [
        (
            line(&blob, "al*ce", "namespaces=\"git\""),
            TrustError::UnsupportedPrincipalPattern { line: 1 },
        ),
        (
            line(&blob, "al?ce", "namespaces=\"git\""),
            TrustError::UnsupportedPrincipalPattern { line: 1 },
        ),
        (
            line(&blob, "!alice", "namespaces=\"git\""),
            TrustError::UnsupportedPrincipalPattern { line: 1 },
        ),
        (
            line(&blob, "alice", "valid-after=20250101"),
            TrustError::MissingGitNamespace { line: 1 },
        ),
        (
            line(&blob, "alice", "cert-authority"),
            TrustError::CertificateAuthority { line: 1 },
        ),
        (
            line(&blob, "alice", "namespaces=\"git\",mystery=yes"),
            TrustError::UnknownOption {
                line: 1,
                option: "mystery".into(),
            },
        ),
        (
            line(&blob, "alice", "namespaces=\"git\",valid-after=20250230"),
            TrustError::InvalidTimestamp {
                line: 1,
                value: "20250230".into(),
            },
        ),
        (
            line(&blob, "alice", "namespaces=\"git\",namespaces=\"git\""),
            TrustError::DuplicateOption {
                line: 1,
                option: "namespaces".into(),
            },
        ),
        (
            format!("alice {KEY_TYPE} {}\n", STANDARD.encode(&blob)),
            TrustError::MissingGitNamespace { line: 1 },
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(parse_allowed_signers(&text).unwrap_err(), expected);
    }
}

#[test]
fn quoted_options_bad_base64_bad_blob_and_other_key_type() {
    let blob = key_blob();
    let parsed = parse_allowed_signers(&line(
        &blob,
        "alice",
        "namespaces=\"git\",valid-after=\"202501010000Z\",valid-before=20251231Z",
    ))
    .unwrap();
    assert_eq!(parsed.entries[0].valid_after.unwrap().basis, TimeBasis::Utc);
    assert_eq!(parsed.entries[0].valid_before.unwrap().civil.hour, 0);

    let bad_b64 = format!("alice namespaces=\"git\" {KEY_TYPE} !!!\n");
    assert!(matches!(
        parse_allowed_signers(&bad_b64),
        Err(TrustError::InvalidBase64 { line: 1 })
    ));
    let bad_blob = format!(
        "alice namespaces=\"git\" {KEY_TYPE} {}\n",
        STANDARD.encode(b"not an SSH key blob")
    );
    assert!(matches!(
        parse_allowed_signers(&bad_blob),
        Err(TrustError::InvalidPublicKey { line: 1 })
    ));
    let mut short_key_blob = ssh_string(KEY_TYPE.as_bytes());
    short_key_blob.extend(ssh_string(&[0; qsg_core::PUBLIC_KEY_SIZE - 1]));
    let short_key = format!(
        "alice namespaces=\"git\" {KEY_TYPE} {}\n",
        STANDARD.encode(short_key_blob)
    );
    assert!(matches!(
        parse_allowed_signers(&short_key),
        Err(TrustError::InvalidPublicKey { line: 1 })
    ));
    let skipped =
        parse_allowed_signers("alice namespaces=\"git\" ssh-ed25519 AAAA legacy key comment\n")
            .unwrap();
    assert!(skipped.entries.is_empty());
    assert_eq!(
        skipped.skipped,
        [SkippedEntry {
            line: 1,
            key_type: "ssh-ed25519".into()
        }]
    );
    let skipped_without_options = parse_allowed_signers("alice ssh-ed25519 AAAA\n").unwrap();
    assert_eq!(skipped_without_options.skipped[0].key_type, "ssh-ed25519");
}

#[test]
fn limits_are_enforced() {
    assert!(matches!(
        parse_allowed_signers(&"x".repeat(MAX_FILE_SIZE + 1)),
        Err(TrustError::FileTooLarge)
    ));
    assert!(matches!(
        parse_allowed_signers(&format!("{}\n", "x".repeat(MAX_LINE_LENGTH + 1))),
        Err(TrustError::LineTooLong { line: 1 })
    ));
    let many = "a namespaces=\"git\" ssh-ed25519 AAAA\n".repeat(MAX_ENTRIES + 1);
    assert!(matches!(
        parse_allowed_signers(&many),
        Err(TrustError::TooManyEntries)
    ));
    assert!(matches!(
        Revocations::parse(&"x".repeat(MAX_FILE_SIZE + 1)),
        Err(TrustError::FileTooLarge)
    ));
}

#[test]
fn revocation_parsing_and_revoked_key_fails_even_when_trusted() {
    let blob = key_blob();
    let allowed = parse_allowed_signers(&line(&blob, "alice", "namespaces=\"git\"")).unwrap();
    let fingerprint = qsg_sshsig::fingerprint(&blob).unwrap();
    let no_revocations = Revocations::default();
    let when = parse_verify_time("20250101000000").unwrap();
    assert_eq!(
        allowed
            .check("alice", &blob, "git", when, None, &no_revocations)
            .unwrap()
            .fingerprint,
        fingerprint
    );
    let revocations =
        Revocations::parse(&format!("# revoked keys\r\n\r\n{fingerprint}\r\n")).unwrap();
    assert!(revocations.is_revoked(&fingerprint));
    assert!(matches!(
        allowed.check("alice", &blob, "git", when, None, &revocations),
        Err(TrustError::Revoked(_))
    ));
    assert!(Revocations::parse("MD5:bad\n").is_err());
    assert!(Revocations::parse("SHA256:abc\n").is_err());
}

#[test]
fn boundary_times_are_inclusive_and_mixed_bases_need_offset() {
    let blob = key_blob();
    let entry = parse_allowed_signers(&line(
        &blob,
        "alice",
        "namespaces=\"git\",valid-after=20250101000000Z,valid-before=20250102000000Z",
    ))
    .unwrap()
    .entries
    .remove(0);
    let exact_after = parse_verify_time("20250101000000Z").unwrap();
    let exact_before = parse_verify_time("20250102000000Z").unwrap();
    assert!(entry.is_valid_at(exact_after, None).unwrap());
    assert!(entry.is_valid_at(exact_before, None).unwrap());
    assert!(
        !entry
            .is_valid_at(parse_verify_time("20241231235959Z").unwrap(), None)
            .unwrap()
    );
    assert!(
        !entry
            .is_valid_at(parse_verify_time("20250102000001Z").unwrap(), None)
            .unwrap()
    );
    let local_same_instant = parse_verify_time("20250101053000").unwrap();
    assert!(matches!(
        entry.is_valid_at(local_same_instant, None),
        Err(TrustError::MixedTimeBasis)
    ));
    assert!(
        entry
            .is_valid_at(local_same_instant, Some(UtcOffset::new(330).unwrap()))
            .unwrap()
    );
    assert!(UtcOffset::new(1440).is_err());
}

#[test]
fn find_principals_filters_key_namespace_and_validity() {
    let blob = key_blob();
    let text = format!(
        "{}{}",
        line(
            &blob,
            "alice,bob",
            "namespaces=\"git,tag\",valid-after=20250102"
        ),
        line(&blob, "carol", "namespaces=\"git\"")
    );
    let allowed = parse_allowed_signers(&text).unwrap();
    let before = parse_verify_time("20250101").unwrap();
    let after = parse_verify_time("20250102").unwrap();
    assert_eq!(
        allowed.find_principals(&blob, "git", before, None).unwrap(),
        ["carol"]
    );
    assert_eq!(
        allowed.find_principals(&blob, "git", after, None).unwrap(),
        ["alice", "bob", "carol"]
    );
    assert_eq!(
        allowed.find_principals(&blob, "tag", after, None).unwrap(),
        ["alice", "bob"]
    );
}

#[test]
fn verify_time_syntax_is_strict_and_validates_calendar() {
    assert_eq!(parse_verify_time("20240229").unwrap().civil.day, 29);
    assert_eq!(parse_verify_time("202501011234Z").unwrap().civil.second, 0);
    for bad in [
        "20230229",
        "2025010112",
        "20250101000000+0000",
        "20250101006000",
        "20250101000000z",
    ] {
        assert!(
            parse_verify_time(bad).is_err(),
            "accepted invalid date format"
        );
    }
}

#[test]
fn arbitrary_bytes_and_text_never_panic() {
    use proptest::prelude::*;
    proptest!(|(bytes in proptest::collection::vec(any::<u8>(), 0..2048), text in any::<String>())| {
        let lossy = String::from_utf8_lossy(&bytes);
        let parsed_bytes = std::panic::catch_unwind(|| parse_allowed_signers(&lossy));
        let parsed_text = std::panic::catch_unwind(|| parse_allowed_signers(&text));
        let revocations = std::panic::catch_unwind(|| Revocations::parse(&text));
        prop_assert!(parsed_bytes.is_ok());
        prop_assert!(parsed_text.is_ok());
        prop_assert!(revocations.is_ok());
    });
}
