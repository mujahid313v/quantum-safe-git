use std::process::Command;

#[test]
fn keygen_prints_setup_instructions_and_pubkey_reads_the_result() {
    let dir = tempfile::tempdir().unwrap();
    // tempfile follows the process umask; the keystore requires a 0700 key
    // directory on Unix, so make the fixture satisfy that production policy.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let output = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .args(["keygen", "--name", "test-key", "--dir"])
        .arg(dir.path())
        .args(["--comment", "M5a test", "--no-passphrase"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Public key:"));
    assert!(stdout.contains("Fingerprint: SHA256:"));
    assert!(stdout.contains("you@example.org namespaces=\"git\" ssh-mldsa65@qsgit "));
    assert!(stdout.contains("git config --global gpg.format ssh"));
    assert!(stdout.contains("git config --global gpg.ssh.program qsg-ssh-keygen"));
    assert!(stdout.contains("git config --global user.signingkey"));
    assert!(stdout.contains("git config --global gpg.ssh.allowedSignersFile"));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("WARNING: creating an unencrypted private key")
    );
    let public_path = dir.path().join("test-key.pub");
    let output = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .arg("pubkey")
        .arg(public_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("ssh-mldsa65@qsgit "));
    let output = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .arg("pubkey")
        .arg(dir.path().join("test-key"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let duplicate = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .args(["keygen", "--name", "test-key", "--dir"])
        .arg(dir.path())
        .args(["--no-passphrase"])
        .output()
        .unwrap();
    assert_eq!(duplicate.status.code(), Some(1));
    let usage = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .arg("unknown-command")
        .output()
        .unwrap();
    assert_eq!(usage.status.code(), Some(2));

    let runtime_config = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .args(["keygen", "--name", "../invalid", "--dir"])
        .arg(dir.path())
        .arg("--no-passphrase")
        .output()
        .unwrap();
    assert_eq!(runtime_config.status.code(), Some(1));

    let help = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .arg("help")
        .output()
        .unwrap();
    assert_eq!(help.status.code(), Some(0));
}

#[test]
fn pubkey_cli_bounds_public_files_and_rejects_invalid_utf8() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let generated = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .args(["keygen", "--name", "bounded", "--dir"])
        .arg(dir.path())
        .args(["--no-passphrase"])
        .output()
        .unwrap();
    assert_eq!(generated.status.code(), Some(0));

    let normal = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .arg("pubkey")
        .arg(dir.path().join("bounded.pub"))
        .output()
        .unwrap();
    assert_eq!(normal.status.code(), Some(0));

    let oversized = dir.path().join("oversized.pub");
    std::fs::write(&oversized, vec![b'A'; 16 * 1024 + 1]).unwrap();
    let rejected_size = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .arg("pubkey")
        .arg(&oversized)
        .output()
        .unwrap();
    assert_eq!(rejected_size.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected_size.stderr).contains("exceeds 16384 byte limit"));

    let invalid = dir.path().join("invalid-utf8.pub");
    std::fs::write(&invalid, [0xff, 0xfe]).unwrap();
    let rejected_utf8 = Command::new(env!("CARGO_BIN_EXE_qsg"))
        .arg("pubkey")
        .arg(&invalid)
        .output()
        .unwrap();
    assert_eq!(rejected_utf8.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected_utf8.stderr).contains("is not UTF-8"));
}
