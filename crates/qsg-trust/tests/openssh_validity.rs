use base64::{Engine as _, engine::general_purpose::STANDARD};
use qsg_core::keygen;
use qsg_trust::{parse_allowed_signers, parse_verify_time};
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

const PRINCIPAL: &str = "qsgit-validity@example.test";
const MESSAGE: &[u8] = b"QSGit allowed_signers validity test\n";

fn ssh_keygen_available() -> bool {
    match Command::new("ssh-keygen").arg("-?").output() {
        Ok(_) => {
            let version = Command::new("ssh").arg("-V").output();
            if let Ok(version) = version {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&version.stdout),
                    String::from_utf8_lossy(&version.stderr)
                );
                println!("ssh-keygen validity experiment: {}", text.trim());
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if std::env::var("QSG_REQUIRE_SSH_KEYGEN").as_deref() == Ok("1") {
                panic!("ssh-keygen is required by QSG_REQUIRE_SSH_KEYGEN=1 but was not found");
            }
            eprintln!("skipping ssh-keygen validity experiment: ssh-keygen missing");
            false
        }
        Err(error) => panic!("failed to start ssh-keygen: {error}"),
    }
}

fn run(mut command: Command) -> std::process::Output {
    command.output().expect("run external command")
}

#[test]
fn allowed_signer_validity_boundaries_match_real_openssh() {
    if !ssh_keygen_available() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("id_ed25519");
    let generated = run({
        let mut command = Command::new("ssh-keygen");
        command.args(["-q", "-t", "ed25519", "-N", "", "-C", "qsgit-test"]);
        command.arg("-f").arg(&key_path);
        command
    });
    assert!(
        generated.status.success(),
        "ssh-keygen key generation failed"
    );
    let public_line = fs::read_to_string(key_path.with_extension("pub")).unwrap();
    let mut fields = public_line.split_whitespace();
    let _ssh_type = fields.next().unwrap();
    let ed_public = fields.next().unwrap();

    let message_path = directory.path().join("message.txt");
    fs::write(&message_path, MESSAGE).unwrap();
    let signed = run({
        let mut command = Command::new("ssh-keygen");
        command.args(["-Y", "sign", "-n", "git", "-f"]);
        command.arg(&key_path).arg(&message_path);
        command
    });
    assert!(signed.status.success(), "ssh-keygen signing failed");
    let signature_path = directory.path().join("message.txt.sig");

    let qsg_blob = {
        let (public, _secret) = keygen().unwrap();
        qsg_sshsig::encode_ml_dsa65_public_key_blob(&public).unwrap()
    };
    let cases: &[(&str, &[(&str, bool)])] = &[
        (
            "valid-after=20250101000000",
            &[
                ("20241231235959", false),
                ("20250101000000", true),
                ("20250101000001", true),
            ],
        ),
        (
            "valid-before=20250101000000",
            &[
                ("20241231235959", true),
                ("20250101000000", true),
                ("20250101000001", false),
            ],
        ),
        (
            "valid-after=20250101000000Z",
            &[
                ("20241231235959Z", false),
                ("20250101000000Z", true),
                ("20250101000001Z", true),
            ],
        ),
        (
            "valid-before=202501010000Z",
            &[("202501010000Z", true), ("202501010001Z", false)],
        ),
        (
            "valid-after=20250101",
            &[("20241231", false), ("20250101", true), ("20250102", true)],
        ),
        (
            "valid-before=20250101Z",
            &[
                ("20241231Z", true),
                ("20250101Z", true),
                ("20250102Z", false),
            ],
        ),
    ];

    for (window, times) in cases {
        let (option_name, option_value) = window.split_once('=').unwrap();
        let options = format!("namespaces=\"git\",{option_name}=\"{option_value}\"");
        let qsg_line = format!(
            "{PRINCIPAL} {options} ssh-mldsa65@qsgit {}\n",
            STANDARD.encode(&qsg_blob)
        );
        let parsed = parse_allowed_signers(&qsg_line).unwrap();
        let entry = &parsed.entries[0];
        let openssh_line = format!("{PRINCIPAL} {options} ssh-ed25519 {ed_public} validity-test\n");
        let allowed_path = directory.path().join("allowed_signers");
        fs::write(&allowed_path, openssh_line).unwrap();

        for (time_text, expected) in *times {
            let ours = entry
                .is_valid_at(parse_verify_time(time_text).unwrap(), None)
                .unwrap();
            assert_eq!(
                ours, *expected,
                "QSGit window result for {window} at {time_text}"
            );
            let mut command = Command::new("ssh-keygen");
            command.args(["-Y", "verify", "-n", "git", "-f"]);
            command.arg(&allowed_path).arg("-I").arg(PRINCIPAL);
            command.arg("-s").arg(&signature_path);
            command.arg(format!("-Overify-time={time_text}"));
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().expect("start ssh-keygen verify");
            child.stdin.take().unwrap().write_all(MESSAGE).unwrap();
            let result = child.wait_with_output().unwrap();
            let openssh_accepts = result.status.success();
            println!("window={window}; verify-time={time_text}; ssh-keygen={openssh_accepts}");
            assert_eq!(
                openssh_accepts,
                *expected,
                "OpenSSH result for {window} at {time_text}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(
                ours, openssh_accepts,
                "implementation disagreed with ssh-keygen for {window} at {time_text}"
            );
        }
    }
}
