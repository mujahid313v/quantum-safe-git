use qsg_keystore::generate;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const PRINCIPAL: &str = "qsgit-m5a@example.test";

fn tool_exists(name: &str) -> bool {
    Command::new(name).arg("--version").output().is_ok()
}

fn git(dir: &Path, args: &[&str]) -> Output {
    git_custom(dir, args, None, None, None)
}

fn git_with_dates(
    dir: &Path,
    args: &[&str],
    author_date: Option<&str>,
    committer_date: Option<&str>,
) -> Output {
    git_custom(dir, args, author_date, committer_date, None)
}

fn git_custom(
    dir: &Path,
    args: &[&str],
    author_date: Option<&str>,
    committer_date: Option<&str>,
    revoked_keys: Option<&Path>,
) -> Output {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", dir.join("global-config"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", dir.parent().unwrap())
        .env("USERPROFILE", dir.parent().unwrap())
        .env("APPDATA", dir.parent().unwrap())
        .env("GIT_AUTHOR_NAME", "QSGit test")
        .env("GIT_AUTHOR_EMAIL", PRINCIPAL)
        .env("GIT_COMMITTER_NAME", "QSGit test")
        .env("GIT_COMMITTER_EMAIL", PRINCIPAL)
        .env_remove("QSG_REVOKED_KEYS");
    if let Some(date) = author_date {
        command.env("GIT_AUTHOR_DATE", date);
    }
    if let Some(date) = committer_date {
        command.env("GIT_COMMITTER_DATE", date);
    }
    if let Some(path) = revoked_keys {
        command.env("QSG_REVOKED_KEYS", path);
    }
    command.output().expect("run git")
}

fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "command failed ({:?}): stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn success_all(output: Output) -> String {
    assert!(
        output.status.success(),
        "command failed ({:?}): stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn report_failure(label: &str, output: &Output) {
    println!(
        "D7 {label}: exit={:?}; stdout={:?}; stderr={:?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Setup {
    temp: TempDir,
    repo: PathBuf,
    key1: PathBuf,
    key2: PathBuf,
    allowed: PathBuf,
}

fn setup() -> Setup {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    fs::create_dir(&keys).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let first = generate(&keys, "first", None, "test key", false, true).unwrap();
    let second = generate(&keys, "second", None, "other key", false, true).unwrap();
    let first_key = qsg_keystore::read_public(&first.public_path).unwrap();
    let line = format!(
        "{PRINCIPAL} namespaces=\"git\" ssh-mldsa65@qsgit {}\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, first_key.blob)
    );
    let allowed = temp.path().join("allowed_signers");
    fs::write(&allowed, line).unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    success(git(&repo, &["init", "-q"]));
    success(git(&repo, &["config", "user.name", "QSGit test"]));
    success(git(&repo, &["config", "user.email", PRINCIPAL]));
    success(git(&repo, &["config", "gpg.format", "ssh"]));
    success(git(
        &repo,
        &[
            "config",
            "gpg.ssh.program",
            env!("CARGO_BIN_EXE_qsg-ssh-keygen"),
        ],
    ));
    success(git(
        &repo,
        &[
            "config",
            "user.signingkey",
            first.public_path.to_str().unwrap(),
        ],
    ));
    success(git(
        &repo,
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            allowed.to_str().unwrap(),
        ],
    ));
    fs::write(repo.join("file.txt"), "M5a commit test\n").unwrap();
    success(git(&repo, &["add", "file.txt"]));
    Setup {
        temp,
        repo,
        key1: first.private_path,
        key2: second.private_path,
        allowed,
    }
}

#[test]
fn git_commit_tag_and_verification_failures_work_end_to_end() {
    if !tool_exists("git") || !tool_exists("ssh-keygen") {
        let message = "skipped qsg Git integration: git or ssh-keygen is missing";
        if std::env::var_os("QSG_REQUIRE_SSH_KEYGEN").is_some() {
            panic!("{message} while QSG_REQUIRE_SSH_KEYGEN is set");
        }
        eprintln!("{message}");
        return;
    }
    let setup = setup();
    let repo = &setup.repo;

    success(git(repo, &["commit", "-S", "-m", "signed commit"]));
    let first_pub = qsg_keystore::read_public(setup.temp.path().join("keys/first.pub")).unwrap();
    let git_revocations = setup.temp.path().join("gpg-revocations");
    fs::write(&git_revocations, format!("{}\n", first_pub.fingerprint)).unwrap();
    success(git(
        repo,
        &[
            "config",
            "gpg.ssh.revocationFile",
            git_revocations.to_str().unwrap(),
        ],
    ));
    let rejected_r = git(repo, &["verify-commit", "HEAD"]);
    report_failure("gpg.ssh.revocationFile with QSG shim", &rejected_r);
    assert!(!rejected_r.status.success());
    assert!(
        String::from_utf8_lossy(&rejected_r.stderr).contains("unsupported flag -r"),
        "shim -r output: {}",
        String::from_utf8_lossy(&rejected_r.stderr)
    );
    success(git(repo, &["config", "--unset", "gpg.ssh.revocationFile"]));
    fs::write(&setup.allowed, format!("{PRINCIPAL} namespaces=\"git\",valid-after=20240101Z,valid-before=20260101Z ssh-mldsa65@qsgit {}\n", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &first_pub.blob))).unwrap();
    // The 2020 author date is outside the window; the 2025 committer date is inside.
    success(git_with_dates(
        repo,
        &["commit", "--allow-empty", "-S", "-m", "committer time"],
        Some("2020-01-01T00:00:00+0000"),
        Some("2025-01-01T00:00:00+0000"),
    ));
    let verified = success_all(git(repo, &["verify-commit", "HEAD"]));
    assert!(
        verified.contains("Good \"git\" signature for"),
        "{verified}"
    );
    let shown = success_all(git(repo, &["log", "--show-signature", "-1"]));
    assert!(shown.contains("Good \"git\" signature for"), "{shown}");
    success(git_with_dates(
        repo,
        &[
            "commit",
            "--allow-empty",
            "-S",
            "-m",
            "old commit for tag time",
        ],
        Some("2020-01-01T00:00:00+0000"),
        Some("2020-01-01T00:00:00+0000"),
    ));
    // Tagger date is 2025 while its target commit date is 2020.
    success(git_with_dates(
        repo,
        &["tag", "-s", "v-m5a", "-m", "signed tag"],
        Some("2020-01-01T00:00:00+0000"),
        Some("2025-01-01T00:00:00+0000"),
    ));
    success_all(git(repo, &["verify-tag", "v-m5a"]));
    fs::write(
        &setup.allowed,
        format!(
            "{PRINCIPAL} namespaces=\"git\" ssh-mldsa65@qsgit {}\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &first_pub.blob)
        ),
    )
    .unwrap();

    // Rewrite only the commit message and retain the gpgsig header verbatim.
    let object = success(git(repo, &["cat-file", "commit", "HEAD"]));
    let (headers, message) = object.split_once("\n\n").expect("commit headers");
    let rewritten = format!("{headers}\n\n{message}tampered");
    // Supply the rewritten object as a file so the original gpgsig bytes stay intact.
    let payload = setup.temp.path().join("tampered-commit");
    fs::write(&payload, rewritten).unwrap();
    let hash = String::from_utf8_lossy(
        &Command::new("git")
            .args(["hash-object", "-t", "commit", "-w"])
            .arg(&payload)
            .current_dir(repo)
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_owned();
    assert!(!hash.is_empty());
    let branch = success(git(repo, &["symbolic-ref", "--short", "HEAD"]));
    success(git(
        repo,
        &[
            "update-ref",
            &format!("refs/heads/{}", branch.trim()),
            &hash,
        ],
    ));
    let tampered = git(repo, &["verify-commit", "HEAD"]);
    report_failure("tampered commit (QSG shim)", &tampered);
    assert!(!tampered.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&tampered.stdout),
            String::from_utf8_lossy(&tampered.stderr)
        )
        .contains("Could not verify signature")
    );

    // A valid signature from an absent key fails trust checking.
    success(git(
        repo,
        &["config", "user.signingkey", setup.key2.to_str().unwrap()],
    ));
    success(git(
        repo,
        &["commit", "--allow-empty", "-S", "-m", "untrusted key"],
    ));
    let untrusted = git(repo, &["verify-commit", "HEAD"]);
    report_failure("untrusted key (QSG shim)", &untrusted);
    assert!(!untrusted.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&untrusted.stdout),
            String::from_utf8_lossy(&untrusted.stderr)
        )
        .contains("unsupported -Y subcommand: check-novalidate"),
        "untrusted-key failure output: stdout={} stderr={}",
        String::from_utf8_lossy(&untrusted.stdout),
        String::from_utf8_lossy(&untrusted.stderr)
    );

    // Restore the trusted key; expiry and revocation are independently checked.
    success(git(
        repo,
        &["config", "user.signingkey", setup.key1.to_str().unwrap()],
    ));
    let key = qsg_keystore::read_public(setup.temp.path().join("keys/first.pub")).unwrap();
    let fp = key.fingerprint;
    fs::write(
        &setup.allowed,
        format!(
            "{PRINCIPAL} namespaces=\"git\",valid-before=20200101000000 ssh-mldsa65@qsgit {}\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key.blob)
        ),
    )
    .unwrap();
    success(git_with_dates(
        repo,
        &["commit", "--allow-empty", "-S", "-m", "expired key"],
        Some("2020-01-01T00:00:00+0000"),
        Some("2025-01-01T00:00:00+0000"),
    ));
    let expired = git(repo, &["verify-commit", "HEAD"]);
    report_failure("expired key (QSG shim)", &expired);
    assert!(!expired.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&expired.stdout),
            String::from_utf8_lossy(&expired.stderr)
        )
        .contains("unsupported -Y subcommand: check-novalidate")
    );
    fs::write(
        &setup.allowed,
        format!(
            "{PRINCIPAL} namespaces=\"git\" ssh-mldsa65@qsgit {}\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key.blob)
        ),
    )
    .unwrap();
    fs::write(setup.temp.path().join("revoked_keys"), format!("{fp}\n")).unwrap();
    let revoked = git(repo, &["verify-commit", "HEAD"]);
    report_failure("revoked sibling file (QSG shim)", &revoked);
    assert!(!revoked.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&revoked.stdout),
            String::from_utf8_lossy(&revoked.stderr)
        )
        .contains("revoked")
    );
    fs::remove_file(setup.temp.path().join("revoked_keys")).unwrap();
    let external_revocations = setup.temp.path().join("revocations-from-env");
    fs::write(&external_revocations, format!("{fp}\n")).unwrap();
    let revoked = git_custom(
        repo,
        &["verify-commit", "HEAD"],
        None,
        None,
        Some(&external_revocations),
    );
    report_failure("revoked QSG_REVOKED_KEYS (QSG shim)", &revoked);
    assert!(!revoked.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&revoked.stdout),
            String::from_utf8_lossy(&revoked.stderr)
        )
        .contains("revoked")
    );
}

#[test]
fn git_openssh_revocation_file_blocks_revoked_ed25519_key() {
    if !tool_exists("git") || !tool_exists("ssh-keygen") {
        let message = "skipped OpenSSH Git revocation test: git or ssh-keygen is missing";
        if std::env::var("QSG_REQUIRE_SSH_KEYGEN").as_deref() == Ok("1") {
            panic!("{message} while QSG_REQUIRE_SSH_KEYGEN=1");
        }
        eprintln!("{message}");
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    success(git(&repo, &["init", "-q"]));
    let key = temp.path().join("ed25519");
    let generated = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(&key)
        .output()
        .expect("run ssh-keygen");
    assert!(
        generated.status.success(),
        "ssh-keygen key generation failed: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let public_line = fs::read_to_string(key.with_extension("pub")).unwrap();
    let allowed = temp.path().join("allowed_signers");
    fs::write(
        &allowed,
        format!("{PRINCIPAL} namespaces=\"git\" {public_line}"),
    )
    .unwrap();
    for (name, value) in [
        ("user.name", "QSGit test"),
        ("user.email", PRINCIPAL),
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", "ssh-keygen"),
    ] {
        success(git(&repo, &["config", name, value]));
    }
    success(git(
        &repo,
        &["config", "user.signingkey", key.to_str().unwrap()],
    ));
    success(git(
        &repo,
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            allowed.to_str().unwrap(),
        ],
    ));
    fs::write(repo.join("file.txt"), "Ed25519 revocation test\n").unwrap();
    success(git(&repo, &["add", "file.txt"]));
    success(git(&repo, &["commit", "-S", "-m", "Ed25519 signed commit"]));

    let revocations = temp.path().join("revoked.krl");
    let created_krl = Command::new("ssh-keygen")
        .args(["-q", "-k", "-f"])
        .arg(&revocations)
        .arg(key.with_extension("pub"))
        .output()
        .expect("create OpenSSH KRL");
    assert!(
        created_krl.status.success(),
        "ssh-keygen KRL generation failed: {}",
        String::from_utf8_lossy(&created_krl.stderr)
    );
    assert!(fs::metadata(&revocations).unwrap().len() > 0);
    let krl_query = Command::new("ssh-keygen")
        .args(["-Q", "-f"])
        .arg(&revocations)
        .arg(key.with_extension("pub"))
        .output()
        .expect("query OpenSSH KRL");
    assert!(
        !krl_query.status.success(),
        "the generated KRL does not revoke the Ed25519 public key"
    );
    success(git(
        &repo,
        &[
            "config",
            "gpg.ssh.revocationFile",
            revocations.to_str().unwrap(),
        ],
    ));
    let result = git(&repo, &["verify-commit", "HEAD"]);
    println!(
        "D7 OpenSSH Ed25519 revoked key: exit={:?}; stdout={:?}; stderr={:?}",
        result.status.code(),
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        !result.status.success(),
        "Git accepted an Ed25519 key independently confirmed as revoked by ssh-keygen -Q"
    );
}
