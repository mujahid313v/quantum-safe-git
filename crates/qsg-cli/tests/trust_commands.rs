use qsg_keystore::generate;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn qsg(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qsg"))
        .args(args)
        .output()
        .unwrap()
}

fn key(dir: &Path, name: &str) -> (std::path::PathBuf, String) {
    let result = generate(dir, name, None, "test", false, true).unwrap();
    let public = qsg_keystore::read_public(&result.public_path).unwrap();
    (result.public_path, public.fingerprint)
}

#[test]
fn trust_add_list_revoke_round_trip_preserves_text_and_permissions() {
    let temp = TempDir::new().unwrap();
    let keys = temp.path().join("keys");
    fs::create_dir(&keys).unwrap();
    let (first, first_fp) = key(&keys, "first");
    let (second, _) = key(&keys, "second");
    let allowed = temp.path().join("allowed_signers");
    fs::write(
        &allowed,
        b"# keep this comment\nlegacy namespaces=\"git\" ssh-ed25519 AAAA old-key\n",
    )
    .unwrap();

    let added = qsg(&[
        "trust",
        "add",
        "alice@example.test",
        first.to_str().unwrap(),
        "--allowed-signers",
        allowed.to_str().unwrap(),
        "--valid-after",
        "20240101Z",
        "--valid-before",
        "20270101Z",
    ]);
    assert_eq!(
        added.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    assert!(String::from_utf8_lossy(&added.stdout).contains(&first_fp));
    let bytes_after_add = fs::read(&allowed).unwrap();
    assert!(
        bytes_after_add.starts_with(
            b"# keep this comment\nlegacy namespaces=\"git\" ssh-ed25519 AAAA old-key\n"
        )
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&allowed, fs::Permissions::from_mode(0o640)).unwrap();
    }
    let listed = qsg(&[
        "trust",
        "list",
        "--allowed-signers",
        allowed.to_str().unwrap(),
    ]);
    assert_eq!(listed.status.code(), Some(0));
    let listing = String::from_utf8_lossy(&listed.stdout);
    assert!(listing.contains("alice@example.test"));
    assert!(listing.contains(&first_fp));
    assert!(listing.contains("skipped line"));

    let before_duplicate = fs::read(&allowed).unwrap();
    let duplicate = qsg(&[
        "trust",
        "add",
        "alice@example.test",
        first.to_str().unwrap(),
        "--allowed-signers",
        allowed.to_str().unwrap(),
    ]);
    assert!(!duplicate.status.success());
    assert_eq!(fs::read(&allowed).unwrap(), before_duplicate);
    let invalid = qsg(&[
        "trust",
        "add",
        "bad user",
        second.to_str().unwrap(),
        "--allowed-signers",
        allowed.to_str().unwrap(),
    ]);
    assert!(!invalid.status.success());
    assert_eq!(fs::read(&allowed).unwrap(), before_duplicate);
    let bad_key = qsg(&[
        "trust",
        "add",
        "bob@example.test",
        allowed.to_str().unwrap(),
        "--allowed-signers",
        allowed.to_str().unwrap(),
    ]);
    assert!(!bad_key.status.success());
    assert_eq!(fs::read(&allowed).unwrap(), before_duplicate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&allowed).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    let revoked = temp.path().join("revoked_keys");
    let revoke = qsg(&[
        "trust",
        "revoke",
        &first_fp,
        "--revoked-keys",
        revoked.to_str().unwrap(),
    ]);
    assert_eq!(
        revoke.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&revoke.stderr)
    );
    assert!(String::from_utf8_lossy(&revoke.stdout).contains("ALL signatures"));
    assert_eq!(
        fs::read_to_string(&revoked).unwrap(),
        format!("{first_fp}\n")
    );
    let before_duplicate_revoke = fs::read(&revoked).unwrap();
    let duplicate_revoke = qsg(&[
        "trust",
        "revoke",
        &first_fp,
        "--revoked-keys",
        revoked.to_str().unwrap(),
    ]);
    assert!(!duplicate_revoke.status.success());
    assert_eq!(fs::read(&revoked).unwrap(), before_duplicate_revoke);
    let invalid_fp = qsg(&[
        "trust",
        "revoke",
        "SHA256:bad",
        "--revoked-keys",
        revoked.to_str().unwrap(),
    ]);
    assert!(!invalid_fp.status.success());
    assert_eq!(fs::read(&revoked).unwrap(), before_duplicate_revoke);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&revoked).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
