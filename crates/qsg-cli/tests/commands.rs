use std::process::Command;

#[test]
fn keygen_prints_setup_instructions_and_pubkey_reads_the_result() {
    let dir = tempfile::tempdir().unwrap();
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
