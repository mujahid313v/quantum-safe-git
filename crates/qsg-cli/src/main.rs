#![forbid(unsafe_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use qsg_keystore::{Passphrase, default_config_dir, generate, read_public};
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Keygen {
        name: String,
        dir: Option<PathBuf>,
        comment: String,
        no_passphrase: bool,
    },
    Pubkey(PathBuf),
    Help,
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
    if let Err(e) = run(command) {
        eprintln!("qsg: {e}");
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    match args.first().map(String::as_str) {
        Some("keygen") => {
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
        Some("pubkey") if args.len() == 2 => Ok(Command::Pubkey(PathBuf::from(&args[1]))),
        Some("help") | Some("--help") | Some("-h") => Ok(Command::Help),
        Some("pubkey") => Err("usage: qsg pubkey <path>".into()),
        Some(x) => Err(format!("unknown command {x}; run `qsg help`")),
        None => Err("usage: qsg <keygen|pubkey|help>".into()),
    }
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Help => {
            println!(
                "qsg keygen [--name NAME] [--dir DIR] [--comment TEXT] [--no-passphrase]\nqsg pubkey <path>\n\nTrust management, verification commands, verify-range, and doctor are planned for M5b."
            );
            Ok(())
        }
        Command::Pubkey(path) => {
            let info = read_public(path).map_err(|e| format!("could not read public key: {e}"))?;
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
    let pubinfo = read_public(&info.public_path)
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
