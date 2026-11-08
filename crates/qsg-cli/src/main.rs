#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use qsg_keystore::{Passphrase, default_config_dir, generate};
use std::path::PathBuf;
use zeroize::Zeroize;

mod doctor;
mod public_key;
mod trust;
mod verify;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Keygen {
        name: String,
        dir: Option<PathBuf>,
        comment: String,
        no_passphrase: bool,
    },
    Pubkey(PathBuf),
    Verify {
        allowed: PathBuf,
        revoked: Option<PathBuf>,
        namespace: String,
        verify_time: Option<String>,
        source: VerifySource,
    },
    VerifyRange {
        range: String,
        allowed: PathBuf,
        revoked: Option<PathBuf>,
        format: String,
        trust_from_head: bool,
        fail_on_empty: bool,
    },
    Trust(Vec<String>),
    Doctor,
    HelpText(String),
    Help,
}

#[derive(Debug, PartialEq, Eq)]
enum VerifySource {
    Commit(String),
    Tag(String),
    Files(PathBuf, PathBuf),
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("qsg: {e}");
            std::process::exit(2);
        }
    };
    let trust_command = matches!(&command, Command::Trust(_));
    if let Err(e) = run(command) {
        eprintln!("qsg: {e}");
        std::process::exit(if trust_command && trust::is_usage_error(&e) {
            2
        } else {
            1
        });
    }
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    match args.first().map(String::as_str) {
        Some("keygen") => {
            if args.len() == 2 && matches!(args[1].as_str(), "--help" | "-h") {
                return Ok(Command::HelpText(
                    "qsg keygen [--name NAME] [--dir DIR] [--comment TEXT] [--no-passphrase]"
                        .into(),
                ));
            }
            let mut name = "id_mldsa65".to_owned();
            let mut dir = None;
            let mut comment = String::new();
            let mut no_passphrase = false;
            let mut seen_name = false;
            let mut seen_dir = false;
            let mut seen_comment = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--name" | "--dir" | "--comment" => {
                        let flag = args[i].as_str();
                        let seen = match flag {
                            "--name" => &mut seen_name,
                            "--dir" => &mut seen_dir,
                            _ => &mut seen_comment,
                        };
                        if *seen {
                            return Err(format!("duplicate keygen argument {flag}"));
                        }
                        *seen = true;
                        let value = args
                            .get(i + 1)
                            .ok_or_else(|| format!("missing value for {flag}"))?
                            .clone();
                        match flag {
                            "--name" => name = value,
                            "--dir" => dir = Some(PathBuf::from(value)),
                            _ => comment = value,
                        }
                        i += 2;
                    }
                    "--no-passphrase" if !no_passphrase => {
                        no_passphrase = true;
                        i += 1;
                    }
                    x => {
                        return Err(format!(
                            "unknown or duplicate keygen argument {x}; run `qsg help`"
                        ));
                    }
                }
            }
            Ok(Command::Keygen {
                name,
                dir,
                comment,
                no_passphrase,
            })
        }
        Some("pubkey") if args.len() == 2 && matches!(args[1].as_str(), "--help" | "-h") => {
            Ok(Command::HelpText("qsg pubkey <public-key-file>".into()))
        }
        Some("pubkey") if args.len() == 2 => Ok(Command::Pubkey(PathBuf::from(&args[1]))),
        Some("verify") => parse_verify(&args[1..]),
        Some("verify-range") => parse_verify_range(&args[1..]),
        Some("trust") => Ok(Command::Trust(args[1..].to_vec())),
        Some("doctor") if args.len() == 1 => Ok(Command::Doctor),
        Some("doctor") if args.len() == 2 && matches!(args[1].as_str(), "--help" | "-h") => {
            Ok(Command::HelpText("qsg doctor".into()))
        }
        Some("help") | Some("--help") | Some("-h") => Ok(Command::Help),
        Some("pubkey") => Err("usage: qsg pubkey <path>".into()),
        Some(x) => Err(format!("unknown command {x}; run `qsg help`")),
        None => Err("usage: qsg <keygen|pubkey|verify|verify-range|trust|doctor|help>".into()),
    }
}

fn parse_verify(args: &[String]) -> Result<Command, String> {
    let mut allowed = None;
    let mut revoked = None;
    let mut namespace = "git".to_owned();
    let mut namespace_seen = false;
    let mut time = None;
    let mut commit = None;
    let mut tag = None;
    let mut signature = None;
    let mut message = None;
    let mut i = 0;
    while i < args.len() {
        let option = args[i].as_str();
        if option == "--help" || option == "-h" {
            return Ok(Command::HelpText("qsg verify --allowed-signers <file> [--revoked-keys <file>] [--namespace git] [--verify-time YYYYMMDDHHMMSS] (--commit <rev> | --tag <name> | --signature <file> --message <file>)".into()));
        }
        if matches!(
            option,
            "--allowed-signers"
                | "--revoked-keys"
                | "--namespace"
                | "--verify-time"
                | "--commit"
                | "--tag"
                | "--signature"
                | "--message"
        ) {
            let value = args
                .get(i + 1)
                .ok_or_else(|| format!("missing value for {option}"))?
                .clone();
            if option == "--namespace" {
                if namespace_seen {
                    return Err("duplicate option --namespace".into());
                }
                namespace_seen = true;
                namespace = value;
                i += 2;
                continue;
            }
            let slot = match option {
                "--allowed-signers" => &mut allowed,
                "--revoked-keys" => &mut revoked,
                "--verify-time" => &mut time,
                "--commit" => &mut commit,
                "--tag" => &mut tag,
                "--signature" => &mut signature,
                _ => &mut message,
            };
            if slot.replace(value.clone()).is_some() {
                return Err(format!("duplicate option {option}"));
            }
            if option == "--verify-time"
                && (value.len() != 14 || !value.bytes().all(|b| b.is_ascii_digit()))
            {
                return Err("--verify-time must be exactly YYYYMMDDHHMMSS (14 digits)".into());
            }
            if option == "--verify-time" {
                qsg_trust::parse_verify_time(&value)
                    .map_err(|e| format!("invalid --verify-time: {e}"))?;
            }
            if matches!(option, "--commit" | "--tag") && value.starts_with('-') {
                return Err(format!("{option} value may not start with '-'"));
            }
            i += 2;
        } else {
            return Err(format!("unknown verify option {option}"));
        }
    }
    if namespace != "git" {
        return Err("only namespace git is supported".into());
    }
    let source_count = usize::from(commit.is_some())
        + usize::from(tag.is_some())
        + usize::from(signature.is_some() || message.is_some());
    if source_count != 1 {
        return Err("choose exactly one of --commit, --tag, or --signature with --message".into());
    }
    if signature.is_some() != message.is_some() {
        return Err("--signature and --message must be used together".into());
    }
    Ok(Command::Verify {
        allowed: PathBuf::from(allowed.ok_or("--allowed-signers is required")?),
        revoked: revoked.map(PathBuf::from),
        namespace,
        verify_time: time,
        source: if let Some(v) = commit {
            VerifySource::Commit(v)
        } else if let Some(v) = tag {
            VerifySource::Tag(v)
        } else {
            VerifySource::Files(
                PathBuf::from(signature.ok_or("--signature is required")?),
                PathBuf::from(message.ok_or("--message is required")?),
            )
        },
    })
}

fn parse_verify_range(args: &[String]) -> Result<Command, String> {
    if args.len() == 1 && matches!(args[0].as_str(), "--help" | "-h") {
        return Ok(Command::HelpText("qsg verify-range <base>..<head> --allowed-signers <file> [--revoked-keys <file>] [--format text|json] [--trust-file-from-head] [--fail-on-empty]".into()));
    }
    let range = args
        .first()
        .ok_or("usage: qsg verify-range <base>..<head> --allowed-signers <file>")?
        .clone();
    if range.starts_with('-') {
        return Err("range may not start with '-'".into());
    }
    let (base, head) = range
        .split_once("..")
        .ok_or("range must be <base>..<head>")?;
    if base.is_empty() || head.is_empty() || head.contains("..") {
        return Err("range must be <base>..<head>".into());
    }
    let mut allowed = None;
    let mut revoked = None;
    let mut format = "text".to_owned();
    let mut format_seen = false;
    let mut trust_from_head = false;
    let mut fail_on_empty = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--allowed-signers" | "--revoked-keys" | "--format" => {
                let flag = args[i].as_str();
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value for {flag}"))?
                    .clone();
                if flag == "--format" {
                    if format_seen {
                        return Err("duplicate option --format".into());
                    }
                    format_seen = true;
                    format = value;
                    i += 2;
                    continue;
                }
                let slot = match flag {
                    "--allowed-signers" => &mut allowed,
                    "--revoked-keys" => &mut revoked,
                    _ => return Err(format!("unknown option {flag}")),
                };
                if slot.replace(value).is_some() {
                    return Err(format!("duplicate option {flag}"));
                }
                i += 2;
            }
            "--trust-file-from-head" if !trust_from_head => {
                trust_from_head = true;
                i += 1;
            }
            "--fail-on-empty" if !fail_on_empty => {
                fail_on_empty = true;
                i += 1;
            }
            option => return Err(format!("unknown or duplicate verify-range option {option}")),
        }
    }
    if !matches!(format.as_str(), "text" | "json") {
        return Err("--format must be text or json".into());
    }
    Ok(Command::VerifyRange {
        range,
        allowed: PathBuf::from(allowed.ok_or("--allowed-signers is required")?),
        revoked: revoked.map(PathBuf::from),
        format,
        trust_from_head,
        fail_on_empty,
    })
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!(
                "qsg keygen [--name NAME] [--dir DIR] [--comment TEXT] [--no-passphrase]\nqsg pubkey <path>\nqsg verify --allowed-signers <file> [--revoked-keys <file>] [--namespace git] [--verify-time YYYYMMDDHHMMSS] (--commit <rev> | --tag <name> | --signature <file> --message <file>)\nqsg verify-range <base>..<head> --allowed-signers <file> [--revoked-keys <file>] [--format text|json] [--trust-file-from-head] [--fail-on-empty]\nqsg trust <add|list|revoke> ...\nqsg doctor"
            );
            Ok(())
        }
        Command::HelpText(text) => {
            println!("{text}");
            Ok(())
        }
        Command::Pubkey(path) => {
            let info = public_key::read_public(path)?;
            let line = format!(
                "ssh-mldsa65@qsgit {}{}",
                STANDARD.encode(info.blob),
                if info.comment.is_empty() {
                    String::new()
                } else {
                    format!(" {}", info.comment)
                }
            );
            println!("{line}");
            Ok(())
        }
        Command::Verify {
            allowed,
            revoked,
            namespace,
            verify_time,
            source,
        } => {
            let source = match source {
                VerifySource::Commit(v) => verify::Source::Commit(v),
                VerifySource::Tag(v) => verify::Source::Tag(v),
                VerifySource::Files(s, m) => verify::Source::Files(s, m),
            };
            let result = verify::verify_one(
                source,
                &allowed,
                revoked.as_deref(),
                &namespace,
                verify_time.as_deref(),
            )?;
            println!("verified {} {}", result.id, result.fingerprint);
            Ok(())
        }
        Command::VerifyRange {
            range,
            allowed,
            revoked,
            format,
            trust_from_head,
            fail_on_empty,
        } => verify::run_range(
            &range,
            &allowed,
            revoked.as_deref(),
            &format,
            trust_from_head,
            fail_on_empty,
        ),
        Command::Trust(args) => trust::run(&args),
        Command::Doctor => doctor::run(),
        Command::Keygen {
            name,
            dir,
            comment,
            no_passphrase,
        } => keygen(name, dir, comment, no_passphrase),
    }
}

fn keygen(
    name: String,
    dir: Option<PathBuf>,
    comment: String,
    no_passphrase: bool,
) -> Result<(), String> {
    let dir = match dir {
        Some(d) => d,
        None => {
            default_config_dir().map_err(|e| format!("cannot determine config directory: {e}"))?
        }
    };
    let passphrase = if no_passphrase {
        eprintln!(
            "WARNING: creating an unencrypted private key. Anyone who can read this file can sign as you."
        );
        None
    } else {
        let mut first = rpassword::prompt_password("New key passphrase (minimum 12 characters): ")
            .map_err(|_| "could not read passphrase from terminal".to_owned())?;
        let mut second = rpassword::prompt_password("Repeat passphrase: ").map_err(|_| {
            first.zeroize();
            "could not read passphrase from terminal".to_owned()
        })?;
        if first.chars().count() < 12 {
            first.zeroize();
            second.zeroize();
            return Err("passphrase must contain at least 12 characters".into());
        }
        if first != second {
            first.zeroize();
            second.zeroize();
            return Err("passphrases do not match".into());
        }
        second.zeroize();
        let value = match Passphrase::new(first.as_bytes()) {
            Ok(value) => value,
            Err(_) => {
                first.zeroize();
                return Err("invalid passphrase".to_owned());
            }
        };
        first.zeroize();
        Some(value)
    };
    let info = generate(
        &dir,
        &name,
        passphrase.as_ref(),
        &comment,
        false,
        no_passphrase,
    )
    .map_err(|e| format!("key generation failed: {e}"))?;
    let pubinfo = public_key::read_public(&info.public_path)
        .map_err(|e| format!("key created but public key could not be read: {e}"))?;
    println!("Public key: {}", info.public_path.display());
    println!("Fingerprint: {}", info.fingerprint);
    println!("Add this exact line to allowed_signers (replace the principal):");
    println!(
        "you@example.org namespaces=\"git\" ssh-mldsa65@qsgit {}",
        STANDARD.encode(pubinfo.blob)
    );
    println!("Configure Git (adjust paths if needed):");
    println!("git config --global gpg.format ssh");
    println!("git config --global gpg.ssh.program qsg-ssh-keygen");
    println!(
        "git config --global user.signingkey {}",
        info.public_path.display()
    );
    println!(
        "git config --global gpg.ssh.allowedSignersFile {}/allowed_signers",
        dir.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keygen_output_options_parse_and_invalid_shapes_reject() {
        assert_eq!(
            parse_args(&["keygen".into()]).unwrap(),
            Command::Keygen {
                name: "id_mldsa65".into(),
                dir: None,
                comment: String::new(),
                no_passphrase: false
            }
        );
        assert!(
            parse_args(&[
                "keygen".into(),
                "--no-passphrase".into(),
                "--no-passphrase".into()
            ])
            .is_err()
        );
        assert!(parse_args(&["keygen".into(), "--surprise".into()]).is_err());
        assert!(parse_args(&["pubkey".into()]).is_err());
        assert!(parse_args(&["pubkey".into(), "a".into(), "extra".into()]).is_err());
    }
}
