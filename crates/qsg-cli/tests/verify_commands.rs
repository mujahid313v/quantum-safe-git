use qsg_keystore::generate;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const PRINCIPAL: &str = "verify@example.test";

struct Setup {
    _temp: TempDir,
    repo: PathBuf,
    allowed: PathBuf,
    key1: PathBuf,
    key2: PathBuf,
    fp1: String,
}

fn tools_present() -> bool {
    let missing = ["git", "ssh-keygen"]
        .into_iter()
        .find(|name| Command::new(name).arg("--version").output().is_err());
    if let Some(name) = missing {
        let message = format!("skipped qsg verify integration: {name} is missing");
        if std::env::var("QSG_REQUIRE_SSH_KEYGEN").as_deref() == Ok("1") {
            panic!("{message} while QSG_REQUIRE_SSH_KEYGEN=1");
        }
        eprintln!("{message}");
        return false;
    }
    true
}

fn setup() -> Setup {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    fs::create_dir(&keys).unwrap();
    let first = generate(&keys, "verify-one", None, "verify", false, true).unwrap();
    let second = generate(&keys, "verify-two", None, "verify", false, true).unwrap();
    let public = qsg_keystore::read_public(&first.public_path).unwrap();
    let allowed = temp.path().join("allowed_signers");
    fs::write(&allowed, allowed_line(&public.blob)).unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    for (key, value) in [
        ("user.name", "Verify Test"),
        ("user.email", PRINCIPAL),
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", shim_path().to_str().unwrap()),
        ("gpg.ssh.allowedSignersFile", allowed.to_str().unwrap()),
        ("user.signingkey", first.private_path.to_str().unwrap()),
    ] {
        git(&repo, &["config", key, value]);
    }
    Setup {
        _temp: temp,
        repo,
        allowed,
        key1: first.private_path,
        key2: second.private_path,
        fp1: public.fingerprint,
    }
}

fn allowed_line(blob: &[u8]) -> String {
    allowed_line_with(blob, "")
}

fn allowed_line_with(blob: &[u8], options: &str) -> String {
    format!(
        "{PRINCIPAL} namespaces=\"git\"{options} ssh-mldsa65@qsgit {}\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, blob)
    )
}

fn shim_path() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(if cfg!(windows) {
            "qsg-ssh-keygen.exe"
        } else {
            "qsg-ssh-keygen"
        })
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", repo.join("global.gitconfig"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", repo.parent().unwrap())
        .env("USERPROFILE", repo.parent().unwrap())
        .env("APPDATA", repo.parent().unwrap())
        .env("GIT_AUTHOR_NAME", "Verify Test")
        .env("GIT_AUTHOR_EMAIL", PRINCIPAL)
        .env("GIT_COMMITTER_NAME", "Verify Test")
        .env("GIT_COMMITTER_EMAIL", PRINCIPAL)
        .env_remove("QSG_REVOKED_KEYS")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn qsg(repo: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qsg"))
        .args(args)
        .current_dir(repo)
        .env_remove("QSG_REVOKED_KEYS")
        .output()
        .unwrap()
}

fn commit(repo: &Path, message: &str, sign: bool, committer: &str, author: &str) -> String {
    let p = repo.join("note");
    fs::write(&p, format!("{message}\n")).unwrap();
    git(repo, &["add", "note"]);
    let mut command = Command::new("git");
    command
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", repo.join("global.gitconfig"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", repo.parent().unwrap())
        .env("GIT_AUTHOR_NAME", "Verify Test")
        .env("GIT_AUTHOR_EMAIL", PRINCIPAL)
        .env("GIT_COMMITTER_NAME", "Verify Test")
        .env("GIT_COMMITTER_EMAIL", PRINCIPAL)
        .env("GIT_AUTHOR_DATE", author)
        .env("GIT_COMMITTER_DATE", committer)
        .env_remove("QSG_REVOKED_KEYS")
        .args(["commit", "--allow-empty"]);
    if sign {
        command.arg("-S");
    }
    let out = command.args(["-m", message]).output().unwrap();
    assert!(
        out.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    git(repo, &["rev-parse", "HEAD"])
}

#[test]
fn verify_signed_objects_times_and_failure_reasons() {
    if !tools_present() {
        return;
    }
    let setup = setup();
    let base = commit(
        &setup.repo,
        "signed base",
        true,
        "2025-01-01T00:00:00+0000",
        "2020-01-01T00:00:00+0000",
    );
    let verified = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--commit",
            &base,
        ],
    );
    assert_eq!(
        verified.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(String::from_utf8_lossy(&verified.stdout).contains(&setup.fp1));

    let tagger = commit(
        &setup.repo,
        "old target",
        true,
        "2020-01-01T00:00:00+0000",
        "2020-01-01T00:00:00+0000",
    );
    let tag = Command::new("git")
        .current_dir(&setup.repo)
        .env("GIT_CONFIG_GLOBAL", setup.repo.join("global.gitconfig"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", setup.repo.parent().unwrap())
        .env("GIT_COMMITTER_DATE", "2025-01-01T00:00:00+0000")
        .args(["tag", "-s", "verify-tag", "-m", "signed tag", &tagger])
        .output()
        .unwrap();
    assert!(
        tag.status.success(),
        "{}",
        String::from_utf8_lossy(&tag.stderr)
    );
    let key_blob = qsg_keystore::read_public(setup.key1.with_extension("pub"))
        .unwrap()
        .blob;
    fs::write(
        &setup.allowed,
        allowed_line_with(&key_blob, ",valid-after=20240101Z"),
    )
    .unwrap();
    let verified_tag = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--tag",
            "verify-tag",
        ],
    );
    assert_eq!(
        verified_tag.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&verified_tag.stderr)
    );
    let target_commit = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--commit",
            &tagger,
        ],
    );
    assert_eq!(target_commit.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&target_commit.stderr).contains("validity"));

    let default_time = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--commit",
            &base,
        ],
    );
    assert_eq!(default_time.status.code(), Some(0));
    let override_time = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--verify-time",
            "20200101000000Z",
            "--commit",
            &base,
        ],
    );
    assert_eq!(override_time.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&override_time.stderr).contains("validity"));

    let object =
        String::from_utf8(git(&setup.repo, &["cat-file", "commit", &base]).into_bytes()).unwrap();
    let footer = object.find("-----END SSH SIGNATURE-----").unwrap();
    let mut corrupted = object.into_bytes();
    let byte = footer - 20;
    corrupted[byte] = if corrupted[byte] == b'A' { b'B' } else { b'A' };
    let bad_object = setup.repo.join("corrupted-commit");
    fs::write(&bad_object, corrupted).unwrap();
    let bad_oid = git(
        &setup.repo,
        &[
            "hash-object",
            "-t",
            "commit",
            "-w",
            bad_object.to_str().unwrap(),
        ],
    );
    let tampered = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--commit",
            &bad_oid,
        ],
    );
    assert_eq!(tampered.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("signature"));

    let unsigned = commit(
        &setup.repo,
        "unsigned",
        false,
        "2025-01-01T00:00:00+0000",
        "2025-01-01T00:00:00+0000",
    );
    let result = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--commit",
            &unsigned,
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("unsigned"));

    git(
        &setup.repo,
        &["config", "user.signingkey", setup.key2.to_str().unwrap()],
    );
    let untrusted = commit(
        &setup.repo,
        "untrusted",
        true,
        "2025-01-01T00:00:00+0000",
        "2025-01-01T00:00:00+0000",
    );
    let result = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--commit",
            &untrusted,
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("trusted"));

    fs::write(
        &setup.allowed,
        allowed_line_with(&key_blob, ",valid-before=20200101Z"),
    )
    .unwrap();
    git(
        &setup.repo,
        &["config", "user.signingkey", setup.key1.to_str().unwrap()],
    );
    let expired = commit(
        &setup.repo,
        "expired",
        true,
        "2025-01-01T00:00:00+0000",
        "2020-01-01T00:00:00+0000",
    );
    let result = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--commit",
            &expired,
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("validity"));

    fs::write(&setup.allowed, allowed_line(&key_blob)).unwrap();
    let revoked = setup._temp.path().join("revoked");
    let no_revocations = setup._temp.path().join("no-revocations");
    fs::write(&no_revocations, b"# empty revocation list\n").unwrap();
    let baseline = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--revoked-keys",
            no_revocations.to_str().unwrap(),
            "--commit",
            &base,
        ],
    );
    assert_eq!(baseline.status.code(), Some(0));
    let missing_revocations = setup._temp.path().join("missing-revocations");
    let missing = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--revoked-keys",
            missing_revocations.to_str().unwrap(),
            "--commit",
            &base,
        ],
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("could not read revocation file"));
    let invalid_revocations = setup._temp.path().join("invalid-revocations");
    fs::write(&invalid_revocations, b"not a fingerprint\n").unwrap();
    let invalid = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--revoked-keys",
            invalid_revocations.to_str().unwrap(),
            "--commit",
            &base,
        ],
    );
    assert_eq!(invalid.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("revocation"));
    fs::write(&revoked, format!("{}\n", setup.fp1)).unwrap();
    let result = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--revoked-keys",
            revoked.to_str().unwrap(),
            "--commit",
            &base,
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("revoked"));

    let (pubkey, secret, _) = qsg_keystore::load_secret(&setup.key1, None, true).unwrap();
    let original_record = qsg_sshsig::sign_ml_dsa65(&pubkey, &secret, b"message\n").unwrap();
    let original_blob = qsg_sshsig::encode_blob(&original_record).unwrap();
    let original_armor = qsg_sshsig::encode_armor(&original_blob).unwrap();
    let sig = setup._temp.path().join("wrong.sig");
    let msg = setup._temp.path().join("message");
    fs::write(&sig, original_armor).unwrap();
    fs::write(&msg, b"message\n").unwrap();
    let baseline = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--signature",
            sig.to_str().unwrap(),
            "--message",
            msg.to_str().unwrap(),
        ],
    );
    assert_eq!(baseline.status.code(), Some(0));
    let mut record = original_record;
    record.namespace = "other".into();
    let mut blob = b"SSHSIG".to_vec();
    blob.extend_from_slice(&1u32.to_be_bytes());
    for field in [
        record.public_key.as_slice(),
        record.namespace.as_bytes(),
        record.reserved.as_slice(),
        record.hash_algorithm.as_bytes(),
        record.signature.as_slice(),
    ] {
        blob.extend_from_slice(&(field.len() as u32).to_be_bytes());
        blob.extend_from_slice(field);
    }
    let mut armor = String::from("-----BEGIN SSH SIGNATURE-----\n");
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, blob);
    for line in encoded.as_bytes().chunks(70) {
        armor.push_str(std::str::from_utf8(line).unwrap());
        armor.push('\n');
    }
    armor.push_str("-----END SSH SIGNATURE-----\n");
    fs::write(&sig, armor).unwrap();
    let result = qsg(
        &setup.repo,
        &[
            "verify",
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
            "--signature",
            sig.to_str().unwrap(),
            "--message",
            msg.to_str().unwrap(),
        ],
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("namespace"));
}

#[test]
fn verify_range_handles_json_failures_empty_ranges_and_trust_source() {
    if !tools_present() {
        return;
    }
    let setup = setup();
    let base = commit(
        &setup.repo,
        "base",
        true,
        "2025-01-01T00:00:00+0000",
        "2025-01-01T00:00:00+0000",
    );
    let valid = commit(
        &setup.repo,
        "valid",
        true,
        "2025-01-02T00:00:00+0000",
        "2025-01-02T00:00:00+0000",
    );
    let allowed = setup.allowed.to_str().unwrap();
    let pass = qsg(
        &setup.repo,
        &[
            "verify-range",
            &format!("{base}..{valid}"),
            "--allowed-signers",
            allowed,
        ],
    );
    assert_eq!(
        pass.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&pass.stdout)
    );
    let json = qsg(
        &setup.repo,
        &[
            "verify-range",
            &format!("{base}..{valid}"),
            "--allowed-signers",
            allowed,
            "--format",
            "json",
        ],
    );
    assert_eq!(json.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&json.stdout).contains("\"schema_version\":1"));
    if Command::new("python3").arg("--version").output().is_ok() {
        let parsed = Command::new("python3").args(["-c", "import json,sys; d=json.load(sys.stdin); assert d['schema_version']==1 and len(d['commits'])==1"]).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::piped()).spawn();
        let mut child = parsed.unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(&json.stdout).unwrap();
        assert!(child.wait().unwrap().success());
    }

    let empty = qsg(
        &setup.repo,
        &[
            "verify-range",
            &format!("{valid}..{valid}"),
            "--allowed-signers",
            allowed,
        ],
    );
    assert_eq!(empty.status.code(), Some(0));
    assert_eq!(empty.stdout, b"0 commits in range\n");
    let empty_fail = qsg(
        &setup.repo,
        &[
            "verify-range",
            &format!("{valid}..{valid}"),
            "--allowed-signers",
            allowed,
            "--fail-on-empty",
        ],
    );
    assert_eq!(empty_fail.status.code(), Some(1));
    let unresolved = qsg(
        &setup.repo,
        &[
            "verify-range",
            "missing-base..HEAD",
            "--allowed-signers",
            allowed,
        ],
    );
    assert_eq!(unresolved.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&unresolved.stderr).contains("could not resolve"));

    let unsigned = commit(
        &setup.repo,
        "unsigned middle",
        false,
        "2025-01-03T00:00:00+0000",
        "2025-01-03T00:00:00+0000",
    );
    let later = commit(
        &setup.repo,
        "signed after",
        true,
        "2025-01-04T00:00:00+0000",
        "2025-01-04T00:00:00+0000",
    );
    let failed = qsg(
        &setup.repo,
        &[
            "verify-range",
            &format!("{base}..{later}"),
            "--allowed-signers",
            allowed,
        ],
    );
    assert_eq!(failed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&failed.stdout).contains(&unsigned));
    assert!(String::from_utf8_lossy(&failed.stdout).contains("FAILED"));

    // Trust source guard: compare the actual bytes used to the base blob.
    let tracked = setup.repo.join("policy");
    fs::write(
        &tracked,
        allowed_line(
            &qsg_keystore::read_public(setup.key1.with_extension("pub"))
                .unwrap()
                .blob,
        ),
    )
    .unwrap();
    git(&setup.repo, &["add", "policy"]);
    let tracked_base = commit(
        &setup.repo,
        "track policy at base",
        true,
        "2025-01-05T00:00:00+0000",
        "2025-01-05T00:00:00+0000",
    );
    fs::write(
        &tracked,
        format!(
            "{}# head version\n",
            allowed_line(
                &qsg_keystore::read_public(setup.key1.with_extension("pub"))
                    .unwrap()
                    .blob
            )
        ),
    )
    .unwrap();
    git(&setup.repo, &["add", "policy"]);
    let tracked_head = commit(
        &setup.repo,
        "change policy",
        true,
        "2025-01-06T00:00:00+0000",
        "2025-01-06T00:00:00+0000",
    );
    let base_copy = git(&setup.repo, &["show", &format!("{tracked_base}:policy")]);
    fs::write(&tracked, format!("{base_copy}\n")).unwrap();
    let copied = qsg(
        &setup.repo,
        &[
            "verify-range",
            &format!("{tracked_base}..{tracked_head}"),
            "--allowed-signers",
            tracked.to_str().unwrap(),
        ],
    );
    assert_eq!(
        copied.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&copied.stderr)
    );
    fs::write(
        &tracked,
        format!(
            "{}# head version\n",
            allowed_line(
                &qsg_keystore::read_public(setup.key1.with_extension("pub"))
                    .unwrap()
                    .blob
            )
        ),
    )
    .unwrap();
    let head_file = qsg(
        &setup.repo,
        &[
            "verify-range",
            &format!("{tracked_base}..{tracked_head}"),
            "--allowed-signers",
            tracked.to_str().unwrap(),
        ],
    );
    assert_eq!(
        head_file.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&head_file.stdout),
        String::from_utf8_lossy(&head_file.stderr)
    );
    assert!(String::from_utf8_lossy(&head_file.stderr).contains("differs byte-for-byte"));
    let override_output = qsg(
        &setup.repo,
        &[
            "verify-range",
            &format!("{tracked_base}..{tracked_head}"),
            "--allowed-signers",
            tracked.to_str().unwrap(),
            "--trust-file-from-head",
        ],
    );
    assert_eq!(
        override_output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&override_output.stderr)
    );

    // Head-only tracked trust files are rejected when used.
    let new_policy = setup.repo.join("new-policy");
    fs::write(
        &new_policy,
        allowed_line(
            &qsg_keystore::read_public(setup.key1.with_extension("pub"))
                .unwrap()
                .blob,
        ),
    )
    .unwrap();
    git(&setup.repo, &["add", "new-policy"]);
    let new_head = commit(
        &setup.repo,
        "add policy",
        true,
        "2025-01-07T00:00:00+0000",
        "2025-01-07T00:00:00+0000",
    );
    let added = qsg(
        &setup.repo,
        &[
            "verify-range",
            &format!("{tracked_head}..{new_head}"),
            "--allowed-signers",
            new_policy.to_str().unwrap(),
        ],
    );
    assert_eq!(added.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&added.stderr).contains("not at base"));

    let merge_base = new_head;
    let primary = git(&setup.repo, &["branch", "--show-current"]);
    git(&setup.repo, &["checkout", "-b", "verify-feature"]);
    git(
        &setup.repo,
        &["commit", "--allow-empty", "-S", "-m", "feature commit"],
    );
    git(&setup.repo, &["checkout", &primary]);
    git(
        &setup.repo,
        &["commit", "--allow-empty", "-S", "-m", "main commit"],
    );
    git(
        &setup.repo,
        &[
            "merge",
            "--no-ff",
            "-S",
            "-m",
            "signed merge",
            "verify-feature",
        ],
    );
    let merge_head = git(&setup.repo, &["rev-parse", "HEAD"]);
    let merged = qsg(
        &setup.repo,
        &[
            "verify-range",
            &format!("{merge_base}..{merge_head}"),
            "--allowed-signers",
            setup.allowed.to_str().unwrap(),
        ],
    );
    assert_eq!(
        merged.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&merged.stdout),
        String::from_utf8_lossy(&merged.stderr)
    );
    assert!(String::from_utf8_lossy(&merged.stdout).lines().count() >= 3);

    #[cfg(unix)]
    {
        let shallow = setup._temp.path().join("shallow");
        let source = setup
            .repo
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .replace(' ', "%20");
        let url = format!("file://{source}");
        let clone = Command::new("git")
            .args([
                "-c",
                "protocol.file.allow=always",
                "clone",
                "--depth=1",
                "--quiet",
                &url,
                shallow.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            clone.status.success(),
            "{}",
            String::from_utf8_lossy(&clone.stderr)
        );
        let missing = qsg(
            &shallow,
            &[
                "verify-range",
                &format!("{base}..HEAD"),
                "--allowed-signers",
                allowed,
            ],
        );
        assert_eq!(missing.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&missing.stderr).contains("could not resolve base"));
    }
}

#[test]
fn revision_option_injection_is_usage_error() {
    let temp = tempfile::tempdir().unwrap();
    let cases: [&[&str]; 3] = [
        &["verify", "--allowed-signers", "a", "--commit", "--output=x"],
        &["verify", "--allowed-signers", "a", "--tag", "-bad-tag"],
        &["verify-range", "-bad..HEAD", "--allowed-signers", "a"],
    ];
    for args in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_qsg"))
            .args(args)
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "args={args:?} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
