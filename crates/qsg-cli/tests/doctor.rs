mod common;

use qsg_keystore::generate;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

struct Setup {
    _temp: TempDir,
    repo: PathBuf,
    global: PathBuf,
    shim: PathBuf,
    allowed: PathBuf,
    #[cfg(unix)]
    private_key: PathBuf,
}

fn setup() -> Setup {
    let temp = TempDir::new().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let global = temp.path().join("global.gitconfig");
    fs::write(&global, "").unwrap();
    let keys = temp.path().join("keys");
    fs::create_dir(&keys).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = generate(&keys, "doctor-key", None, "doctor", false, true).unwrap();
    let public = qsg_keystore::read_public(&key.public_path).unwrap();
    let allowed = temp.path().join("allowed_signers");
    fs::write(
        &allowed,
        format!(
            "doctor@example.test namespaces=\"git\" ssh-mldsa65@qsgit {}\n",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, public.blob)
        ),
    )
    .unwrap();
    git(&repo, &global, &["init", "-q"]);
    let shim = common::shim_path();
    for (key, value) in [
        ("gpg.format", "ssh".to_owned()),
        ("gpg.ssh.program", shim.to_string_lossy().into_owned()),
        (
            "user.signingkey",
            key.public_path.to_string_lossy().into_owned(),
        ),
        (
            "gpg.ssh.allowedSignersFile",
            allowed.to_string_lossy().into_owned(),
        ),
    ] {
        git(&repo, &global, &["config", key, &value]);
    }
    Setup {
        _temp: temp,
        repo,
        global,
        shim,
        allowed,
        #[cfg(unix)]
        private_key: key.private_path,
    }
}

fn git(repo: &Path, global: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_GLOBAL", global)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn doctor(setup: &Setup, extra: &[(&str, &str)], remove: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_qsg"));
    command
        .arg("doctor")
        .current_dir(&setup.repo)
        .env("GIT_CONFIG_GLOBAL", &setup.global)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", setup._temp.path());
    #[cfg(windows)]
    {
        command
            .env("APPDATA", setup._temp.path())
            .env("USERPROFILE", setup._temp.path());
    }
    command.env_remove("QSG_REVOKED_KEYS");
    for (k, v) in extra {
        command.env(k, v);
    }
    for k in remove {
        command.env_remove(k);
    }
    command.output().unwrap()
}

#[test]
fn doctor_reports_errors_and_warnings_with_isolated_git_configuration() {
    let setup = setup();
    let baseline = doctor(&setup, &[], &[]);
    assert_eq!(
        baseline.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&baseline.stdout)
    );
    let baseline_text = String::from_utf8_lossy(&baseline.stdout);
    assert!(baseline_text.contains("no passphrase encryption"));
    assert!(baseline_text.contains("INFO: config gpg.format"));

    let missing_revoked = setup._temp.path().join("missing-revocations");
    let warn = doctor(
        &setup,
        &[("QSG_REVOKED_KEYS", missing_revoked.to_str().unwrap())],
        &[],
    );
    assert_eq!(warn.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&warn.stdout).contains("QSG_REVOKED_KEYS points to missing file")
    );

    let mismatch_allowed = setup._temp.path().join("not-listed");
    fs::write(&mismatch_allowed, "").unwrap();
    git(
        &setup.repo,
        &setup.global,
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            mismatch_allowed.to_str().unwrap(),
        ],
    );
    let mismatch = doctor(&setup, &[], &[]);
    assert_eq!(mismatch.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&mismatch.stdout).contains("is not listed in allowed_signers"));
    git(
        &setup.repo,
        &setup.global,
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            setup.allowed.to_str().unwrap(),
        ],
    );

    let revocation = setup._temp.path().join("git-krl");
    fs::write(&revocation, "ignored by doctor").unwrap();
    git(
        &setup.repo,
        &setup.global,
        &[
            "config",
            "gpg.ssh.revocationFile",
            revocation.to_str().unwrap(),
        ],
    );
    let error = doctor(&setup, &[], &[]);
    assert_eq!(error.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&error.stdout)
            .contains("unset it and use QSG_REVOKED_KEYS or revoked_keys")
    );
    git(
        &setup.repo,
        &setup.global,
        &["config", "--unset", "gpg.ssh.revocationFile"],
    );

    git(
        &setup.repo,
        &setup.global,
        &["config", "gpg.ssh.program", "git"],
    );
    let bad_shim = doctor(&setup, &[], &[]);
    assert_eq!(bad_shim.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad_shim.stdout).contains("not this QSGit installation"));
    git(
        &setup.repo,
        &setup.global,
        &["config", "gpg.ssh.program", setup.shim.to_str().unwrap()],
    );

    git(
        &setup.repo,
        &setup.global,
        &["config", "gpg.format", "openpgp"],
    );
    let bad_format = doctor(&setup, &[], &[]);
    assert_eq!(bad_format.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad_format.stdout).contains("QSGit requires ssh"));
    git(&setup.repo, &setup.global, &["config", "gpg.format", "ssh"]);

    let malformed = setup._temp.path().join("malformed");
    fs::write(&malformed, "doctor@example.test ssh-mldsa65@qsgit AAAA\n").unwrap();
    git(
        &setup.repo,
        &setup.global,
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            malformed.to_str().unwrap(),
        ],
    );
    let bad_allowed = doctor(&setup, &[], &[]);
    assert_eq!(bad_allowed.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad_allowed.stdout).contains("is malformed"));
    git(
        &setup.repo,
        &setup.global,
        &[
            "config",
            "gpg.ssh.allowedSignersFile",
            setup.allowed.to_str().unwrap(),
        ],
    );

    git(
        &setup.repo,
        &setup.global,
        &["config", "user.signingkey", "key::not-qsgit"],
    );
    let bad_key = doctor(&setup, &[], &[]);
    assert_eq!(bad_key.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad_key.stdout).contains("not a readable QSGit key"));
}

#[cfg(unix)]
#[test]
fn doctor_reports_private_key_and_directory_permission_errors() {
    use std::os::unix::fs::PermissionsExt;
    let setup = setup();
    fs::set_permissions(&setup.private_key, fs::Permissions::from_mode(0o644)).unwrap();
    let bad_file = doctor(&setup, &[], &[]);
    assert_eq!(bad_file.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad_file.stdout).contains("chmod 600"));
    fs::set_permissions(&setup.private_key, fs::Permissions::from_mode(0o600)).unwrap();

    let key_dir = setup.private_key.parent().unwrap();
    fs::set_permissions(key_dir, fs::Permissions::from_mode(0o755)).unwrap();
    let bad_dir = doctor(&setup, &[], &[]);
    assert_eq!(bad_dir.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&bad_dir.stdout).contains("chmod 700"));
}
