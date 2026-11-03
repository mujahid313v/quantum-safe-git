use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use qsg_sshsig::{
    ED25519_KEY_TYPE, SshSignature, build_signed_data, decode_armor, decode_blob, encode_armor,
    encode_blob, fingerprint,
};
use ssh_key::PrivateKey;
use std::{
    fs,
    io::Write,
    process::{Command, Output, Stdio},
};
use tempfile::TempDir;

const PRINCIPAL: &str = "qsgit-interop@example.test";
const MESSAGE: &[u8] = b"QSGit OpenSSH SSHSIG interoperability test\n";

fn ssh_keygen_available() -> bool {
    match Command::new("ssh-keygen").arg("-?").output() {
        Ok(_) => {
            let version = Command::new("ssh").arg("-V").output();
            if let Ok(version) = version {
                let text = String::from_utf8_lossy(&version.stderr);
                println!("OpenSSH version used with ssh-keygen: {}", text.trim());
            } else {
                println!("ssh-keygen is available; ssh version command unavailable");
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if std::env::var("QSG_REQUIRE_SSH_KEYGEN").as_deref() == Ok("1") {
                panic!("ssh-keygen is required by QSG_REQUIRE_SSH_KEYGEN=1 but was not found");
            }
            eprintln!("skipping OpenSSH interop: ssh-keygen is not installed");
            false
        }
        Err(error) => panic!("failed to start ssh-keygen: {error}"),
    }
}

fn generate_keypair(dir: &TempDir, name: &str) -> (std::path::PathBuf, PrivateKey, Vec<u8>) {
    let private_path = dir.path().join(name);
    let output = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "qsgit-test"])
        .arg("-f")
        .arg(&private_path)
        .output()
        .expect("run ssh-keygen to generate Ed25519 key");
    assert!(
        output.status.success(),
        "ssh-keygen key generation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let private_text = fs::read_to_string(&private_path).expect("read generated private key");
    let private = PrivateKey::from_openssh(&private_text).expect("parse generated OpenSSH key");
    let ed25519 = private
        .key_data()
        .ed25519()
        .expect("generated key is Ed25519");
    let public_blob = ssh_string(ED25519_KEY_TYPE.as_bytes());
    let mut public_blob = public_blob;
    append_ssh_string(&mut public_blob, ed25519.public.as_ref());
    (private_path, private, public_blob)
}

fn ssh_string(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    append_ssh_string(&mut out, value);
    out
}

fn append_ssh_string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn signature_blob(signature: &[u8]) -> Vec<u8> {
    let mut out = ssh_string(ED25519_KEY_TYPE.as_bytes());
    append_ssh_string(&mut out, signature);
    out
}

fn allowed_signer(public_output: &str, key_line: Option<&str>) -> String {
    let line = key_line.unwrap_or(public_output).trim();
    let mut fields = line.split_whitespace();
    let key_type = fields.next().expect("ssh-keygen public key type");
    let key_b64 = fields.next().expect("ssh-keygen public key data");
    format!("{PRINCIPAL} namespaces=\"git\" {key_type} {key_b64}\n")
}

fn public_line(private_path: &std::path::Path) -> String {
    let output = Command::new("ssh-keygen")
        .arg("-y")
        .arg("-f")
        .arg(private_path)
        .output()
        .expect("run ssh-keygen -y");
    assert!(
        output.status.success(),
        "ssh-keygen -y failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("OpenSSH public key is UTF-8")
}

fn ssh_verify(
    args: &[&str],
    allowed: Option<&std::path::Path>,
    signature_file: &std::path::Path,
    message: &[u8],
) -> Output {
    let mut command = Command::new("ssh-keygen");
    command.args(["-Y", args[0]]);
    if args[0] == "verify" {
        command.arg("-f").arg(allowed.expect("allowed signers"));
        command.arg("-I").arg(PRINCIPAL);
    }
    command.arg("-n").arg(args[1]).arg("-s").arg(signature_file);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start ssh-keygen verification");
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(message)
        .expect("write signed message to ssh-keygen");
    child.wait_with_output().expect("wait for ssh-keygen")
}

fn verify_with_ed25519(public_blob: &[u8], signature_blob: &[u8], data: &[u8]) -> bool {
    let key_type_len = u32::from_be_bytes(public_blob[..4].try_into().unwrap()) as usize;
    let key_type_end = 4 + key_type_len;
    assert_eq!(&public_blob[4..key_type_end], ED25519_KEY_TYPE.as_bytes());
    let key_len = u32::from_be_bytes(
        public_blob[key_type_end..key_type_end + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let key_bytes: [u8; 32] = public_blob[key_type_end + 4..key_type_end + 4 + key_len]
        .try_into()
        .expect("Ed25519 key is 32 bytes");

    let sig_type_len = u32::from_be_bytes(signature_blob[..4].try_into().unwrap()) as usize;
    let sig_type_end = 4 + sig_type_len;
    assert_eq!(
        &signature_blob[4..sig_type_end],
        ED25519_KEY_TYPE.as_bytes()
    );
    let sig_len = u32::from_be_bytes(
        signature_blob[sig_type_end..sig_type_end + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let sig_bytes: [u8; 64] = signature_blob[sig_type_end + 4..sig_type_end + 4 + sig_len]
        .try_into()
        .expect("Ed25519 signature is 64 bytes");
    VerifyingKey::from_bytes(&key_bytes)
        .expect("valid Ed25519 public key")
        .verify_strict(data, &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

fn verify_decoded(record: &SshSignature, message: &[u8]) -> bool {
    let data = build_signed_data(
        &record.namespace,
        &record.reserved,
        &record.hash_algorithm,
        message,
    )
    .expect("supported namespace and hash");
    verify_with_ed25519(&record.public_key, &record.signature, &data)
}

#[test]
fn both_directions_interoperate_with_openssh_and_reject_tampering() {
    if !ssh_keygen_available() {
        return;
    }
    let dir = tempfile::tempdir().expect("temporary interop directory");
    let (private_path, private, public_blob) = generate_keypair(&dir, "id_ed25519");
    let public_output = public_line(&private_path);
    assert_eq!(
        fingerprint(&public_blob).unwrap(),
        ssh_keygen_fingerprint(&private_path)
    );
    let allowed_path = dir.path().join("allowed_signers");
    fs::write(&allowed_path, allowed_signer(&public_output, None)).unwrap();
    let ed_keypair = private.key_data().ed25519().unwrap();
    let signing_key = SigningKey::from_bytes(ed_keypair.private.as_ref());

    // Direction 1: this crate builds/signs the SSHSIG data and OpenSSH verifies it.
    let signed_data = build_signed_data("git", b"", "sha512", MESSAGE).unwrap();
    let ed_signature = signing_key.sign(&signed_data).to_bytes();
    let our_record = SshSignature {
        public_key: public_blob.clone(),
        namespace: "git".to_owned(),
        reserved: Vec::new(),
        hash_algorithm: "sha512".to_owned(),
        signature: signature_blob(&ed_signature),
    };
    let our_binary = encode_blob(&our_record).unwrap();
    let our_armor = encode_armor(&our_binary).unwrap();
    let our_sig_path = dir.path().join("ours.sig");
    fs::write(&our_sig_path, &our_armor).unwrap();
    assert!(
        ssh_verify(
            &["verify", "git"],
            Some(&allowed_path),
            &our_sig_path,
            MESSAGE
        )
        .status
        .success()
    );
    assert!(
        ssh_verify(&["check-novalidate", "git"], None, &our_sig_path, MESSAGE)
            .status
            .success()
    );
    assert!(
        !ssh_verify(
            &["verify", "git"],
            Some(&allowed_path),
            &our_sig_path,
            b"changed message"
        )
        .status
        .success()
    );
    assert!(
        !ssh_verify(&["check-novalidate", "other"], None, &our_sig_path, MESSAGE)
            .status
            .success()
    );

    let (wrong_private_path, _, _) = generate_keypair(&dir, "wrong_ed25519");
    let wrong_public = public_line(&wrong_private_path);
    let wrong_allowed = dir.path().join("wrong_allowed_signers");
    fs::write(&wrong_allowed, allowed_signer(&wrong_public, None)).unwrap();
    assert!(
        !ssh_verify(
            &["verify", "git"],
            Some(&wrong_allowed),
            &our_sig_path,
            MESSAGE
        )
        .status
        .success()
    );

    // Direction 2: OpenSSH signs; this crate parses the armor and Ed25519 verifies.
    let message_path = dir.path().join("message.bin");
    fs::write(&message_path, MESSAGE).unwrap();
    let sign_output = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(&private_path)
        .arg(&message_path)
        .output()
        .expect("run ssh-keygen -Y sign");
    assert!(
        sign_output.status.success(),
        "ssh-keygen signing failed: {}",
        String::from_utf8_lossy(&sign_output.stderr)
    );
    let openssh_sig_path = dir.path().join("message.bin.sig");
    let openssh_armor = fs::read_to_string(&openssh_sig_path).unwrap();
    let decoded = decode_armor(&openssh_armor).unwrap();
    let openssh_record = decode_blob(&decoded).unwrap();
    assert!(verify_decoded(&openssh_record, MESSAGE));
    assert!(!verify_decoded(&openssh_record, b"changed message"));

    assert!(build_signed_data("other", b"", "sha512", MESSAGE).is_err());
    assert!(
        !ssh_verify(
            &["check-novalidate", "other"],
            None,
            &openssh_sig_path,
            MESSAGE
        )
        .status
        .success()
    );
    let wrong_key = PrivateKey::from_openssh(
        fs::read_to_string(wrong_private_path).expect("read second OpenSSH key"),
    )
    .unwrap();
    let wrong_public_data = wrong_key.key_data().ed25519().unwrap().public.as_ref();
    let wrong_public_blob = {
        let mut bytes = ssh_string(ED25519_KEY_TYPE.as_bytes());
        append_ssh_string(&mut bytes, wrong_public_data);
        bytes
    };
    assert!(!verify_with_ed25519(
        &wrong_public_blob,
        &openssh_record.signature,
        &build_signed_data("git", b"", "sha512", MESSAGE).unwrap(),
    ));

    // A supported OpenSSH signature has the canonical 70-column armor form;
    // our decoder also accepts the same form without the final LF.
    assert_eq!(
        decode_armor(our_armor.trim_end_matches('\n')).unwrap(),
        our_binary
    );
}

fn ssh_keygen_fingerprint(private_path: &std::path::Path) -> String {
    let public_path = private_path.with_extension("pub");
    let output = Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f"])
        .arg(public_path)
        .output()
        .expect("run ssh-keygen fingerprint");
    assert!(
        output.status.success(),
        "ssh-keygen fingerprint failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("ssh-keygen fingerprint output is UTF-8")
        .split_whitespace()
        .nth(1)
        .expect("OpenSSH fingerprint field")
        .to_owned()
}
