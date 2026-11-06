#[cfg(unix)]
use super::*;

#[cfg(all(test, unix))]
mod parity_tests {
    use super::*;
    use base64::Engine as _;
    use std::fs;
    use std::process::Output;

    const FIXTURE: &[u8] = include_bytes!("../../qsg-sshsig/tests/vectors/ml-dsa65-valid-1.sshsig");

    fn git(dir: &Path, args: &[&str]) -> Output {
        Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("Git must start")
    }

    fn success(output: Output) -> Vec<u8> {
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    #[test]
    fn qsg_payload_matches_git_v255_recording_program() {
        if Command::new("git").arg("--version").output().is_err() {
            let text = "skipped payload parity: git is missing";
            if std::env::var("QSG_REQUIRE_SSH_KEYGEN").as_deref() == Ok("1") {
                panic!("{text} while QSG_REQUIRE_SSH_KEYGEN=1");
            }
            eprintln!("{text}");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        success(git(repo, &["init", "-q"]));
        success(git(repo, &["config", "user.name", "Parity Test"]));
        success(git(repo, &["config", "user.email", "parity@example.test"]));
        let signature = repo.join("fixture.sshsig");
        let armor = qsg_sshsig::encode_armor(FIXTURE).unwrap();
        fs::write(&signature, armor).unwrap();
        let record = qsg_sshsig::decode_blob(FIXTURE).unwrap();
        let fp = qsg_sshsig::fingerprint(&record.public_key).unwrap();
        let allowed = repo.join("allowed_signers");
        let public_blob = record.public_key.as_slice();
        let encoded = base64::engine::general_purpose::STANDARD.encode(public_blob);
        fs::write(
            &allowed,
            format!("parity@example.test namespaces=\"git\" ssh-mldsa65@qsgit {encoded}\n"),
        )
        .unwrap();
        let recorder = repo.join("qsg-recorder.sh");
        let capture = repo.join("git-payload.bin");
        let script = format!(
            "#!/bin/sh\nsig={}\ncapture={}\ncase \"$2\" in\n sign) cp \"$sig\" \"$7.sig\" ;;\n find-principals) printf 'parity@example.test\\n' ;;\n verify) cat > \"$capture\"; printf 'Good \\\"git\\\" signature for parity@example.test with test key SHA256:fixture\\n' ;;\n *) exit 2 ;;\nesac\n",
            shell_quote(signature.to_str().unwrap()),
            shell_quote(capture.to_str().unwrap())
        );
        fs::write(&recorder, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&recorder, fs::Permissions::from_mode(0o700)).unwrap();
        for (key, value) in [
            ("gpg.format", "ssh"),
            ("gpg.ssh.program", recorder.to_str().unwrap()),
            ("gpg.ssh.allowedSignersFile", allowed.to_str().unwrap()),
            ("user.signingkey", "fixture-key"),
        ] {
            success(git(repo, &["config", key, value]));
        }
        let mut case = 0usize;
        let verify_head = |repo: &Path, capture: &Path| {
            success(git(repo, &["verify-commit", "HEAD"]));
            let raw = git_limited_in(repo, &["cat-file", "commit", "HEAD"], MAX_OBJECT).unwrap();
            let format = git_limited_in(repo, &["rev-parse", "--show-object-format"], 128).unwrap();
            let (_, extracted) = extract_commit(&raw, &format).unwrap();
            assert_eq!(fs::read(capture).unwrap(), extracted);
        };
        let commit = |message: &str| {
            fs::write(repo.join("file"), format!("{message}\n")).unwrap();
            success(git(repo, &["add", "file"]));
            success(git(repo, &["commit", "-S", "-m", message]));
        };
        commit("signed commit");
        verify_head(repo, &capture);
        case += 1;
        commit("message contains gpgsig");
        verify_head(repo, &capture);
        case += 1;

        // A merge commit exercises multiple parent headers.
        let base_branch = String::from_utf8(success(git(repo, &["branch", "--show-current"])))
            .unwrap()
            .trim()
            .to_owned();
        success(git(repo, &["checkout", "-q", "-b", "parity-side"]));
        fs::write(repo.join("side"), "side\n").unwrap();
        success(git(repo, &["add", "side"]));
        success(git(repo, &["commit", "-S", "-m", "side branch"]));
        success(git(repo, &["checkout", "-q", &base_branch]));
        fs::write(repo.join("main"), "main\n").unwrap();
        success(git(repo, &["add", "main"]));
        success(git(repo, &["commit", "-S", "-m", "main branch"]));
        success(git(
            repo,
            &["merge", "--no-ff", "-S", "-m", "merge", "parity-side"],
        ));
        verify_head(repo, &capture);
        case += 1;

        let tag_message = repo.join("tag-message.txt");
        fs::write(&tag_message, "annotated tag message\n").unwrap();
        success(git(
            repo,
            &[
                "tag",
                "-s",
                "parity-tag",
                "-F",
                tag_message.to_str().unwrap(),
            ],
        ));
        success(git(repo, &["verify-tag", "parity-tag"]));
        let tag_raw = git_limited_in(repo, &["cat-file", "tag", "parity-tag"], MAX_OBJECT).unwrap();
        let (_, extracted_tag) = extract_tag(&tag_raw).unwrap();
        assert_eq!(fs::read(&capture).unwrap(), extracted_tag);
        case += 1;

        fs::write(&tag_message, "fake block follows\n-----BEGIN SSH SIGNATURE-----\nZmFrZQ==\n-----END SSH SIGNATURE-----\nreal signature follows\n").unwrap();
        success(git(
            repo,
            &[
                "tag",
                "-s",
                "parity-fake-tag",
                "-F",
                tag_message.to_str().unwrap(),
            ],
        ));
        success(git(repo, &["verify-tag", "parity-fake-tag"]));
        let raw =
            git_limited_in(repo, &["cat-file", "tag", "parity-fake-tag"], MAX_OBJECT).unwrap();
        let marker = locate_tag_signature(&raw).unwrap();
        let extracted = remove_tag_header_signatures(&raw[..marker]);
        assert_eq!(fs::read(&capture).unwrap(), extracted);
        case += 1;

        // Custom multiline headers use Git's continuation convention and stay
        // in the signed payload. Insert before gpgsig without changing it.
        let raw = git_limited_in(repo, &["cat-file", "commit", "HEAD"], MAX_OBJECT).unwrap();
        let position = raw.windows(2).position(|w| w == b"\n\n").unwrap();
        let mut altered = raw[..position].to_vec();
        altered.extend_from_slice(b"\nx-extra value\n continuation\n");
        altered.extend_from_slice(&raw[position + 1..]);
        let path = repo.join("multiline-commit");
        fs::write(&path, altered).unwrap();
        let oid = String::from_utf8(success(git(
            repo,
            &["hash-object", "-t", "commit", "-w", path.to_str().unwrap()],
        )))
        .unwrap()
        .trim()
        .to_owned();
        success(git(repo, &["verify-commit", &oid]));
        let raw = git_limited_in(repo, &["cat-file", "commit", &oid], MAX_OBJECT).unwrap();
        let format = git_limited_in(repo, &["rev-parse", "--show-object-format"], 128).unwrap();
        let (_, extracted) = extract_commit(&raw, &format).unwrap();
        assert_eq!(fs::read(&capture).unwrap(), extracted);
        case += 1;

        let sha = repo.join("sha256");
        fs::create_dir(&sha).unwrap();
        let init = git(&sha, &["init", "-q", "--object-format=sha256"]);
        if init.status.success() {
            success(git(&sha, &["config", "user.name", "Parity Test"]));
            success(git(&sha, &["config", "user.email", "parity@example.test"]));
            for (key, value) in [
                ("gpg.format", "ssh"),
                ("gpg.ssh.program", recorder.to_str().unwrap()),
                ("gpg.ssh.allowedSignersFile", allowed.to_str().unwrap()),
                ("user.signingkey", "fixture-key"),
            ] {
                success(git(&sha, &["config", key, value]));
            }
            fs::write(sha.join("file"), "sha256 payload\n").unwrap();
            success(git(&sha, &["add", "file"]));
            success(git(&sha, &["commit", "-S", "-m", "sha256"]));
            success(git(&sha, &["verify-commit", "HEAD"]));
            let raw = git_limited_in(&sha, &["cat-file", "commit", "HEAD"], MAX_OBJECT).unwrap();
            let format = git_limited_in(&sha, &["rev-parse", "--show-object-format"], 128).unwrap();
            assert!(
                raw.windows(b"gpgsig-sha256 ".len())
                    .any(|w| w == b"gpgsig-sha256 ")
            );
            let (_, extracted) = extract_commit(&raw, &format).unwrap();
            assert_eq!(fs::read(&capture).unwrap(), extracted);
            case += 1;
        } else {
            eprintln!(
                "skipped sha256 payload parity: this Git build does not support SHA-256 repositories: {}",
                String::from_utf8_lossy(&init.stderr).trim()
            );
        }
        assert!(case >= 5);
        assert!(fp.starts_with("SHA256:"));
    }

    fn shell_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    fn git_limited_in(dir: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>, String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).into_owned());
        }
        if out.stdout.len() > limit {
            return Err("git output too large".into());
        }
        Ok(out.stdout)
    }
}

#[cfg(all(test, windows))]
#[test]
fn payload_parity_platform_note() {
    eprintln!(
        "skipped recording-program payload parity on Windows: no portable executable script launcher in this test"
    );
}
