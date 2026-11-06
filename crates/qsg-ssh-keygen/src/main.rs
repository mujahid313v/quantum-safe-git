#![forbid(unsafe_code)]

use qsg_keystore::{KeyKind, Passphrase};
use qsg_sshsig::sign_ml_dsa65;
use qsg_trust::{UtcOffset, parse_verify_time};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const MAX_MESSAGE: u64 = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Sign {
        key: PathBuf,
        buffer: PathBuf,
    },
    Find {
        allowed: PathBuf,
        signature: PathBuf,
        verify_time: String,
    },
    Verify {
        allowed: PathBuf,
        principal: String,
        signature: PathBuf,
        verify_time: String,
    },
}

fn main() {
    let result = (|| {
        let os_args = env::args_os().skip(1).collect::<Vec<_>>();
        let args = os_args
            .iter()
            .map(|a| a.to_str().ok_or("arguments must be valid UTF-8"))
            .collect::<Result<Vec<_>, _>>()?;
        let command = parse_args(&args)?;
        let offset = match &command {
            Command::Find { verify_time, .. } | Command::Verify { verify_time, .. } => {
                parse_verify_time(verify_time)
                    .map_err(|e| format!("invalid verify-time: {e}"))
                    .and_then(qsg_verify::system_local_offset)
            }
            Command::Sign { .. } => Ok(None),
        };
        execute(command, offset)
    })();
    if let Err(error) = result {
        if error == "No principal matched." {
            println!("{error}");
        } else {
            eprintln!("{error}");
        }
        std::process::exit(255);
    }
}

fn execute(command: Command, offset: Result<Option<UtcOffset>, String>) -> Result<(), String> {
    match command {
        Command::Sign { key, buffer } => sign(&key, &buffer),
        Command::Find {
            allowed,
            signature,
            verify_time,
        } => find(&allowed, &signature, &verify_time, offset),
        Command::Verify {
            allowed,
            principal,
            signature,
            verify_time,
        } => verify(&allowed, &principal, &signature, &verify_time, offset),
    }
}

fn parse_args(args: &[&str]) -> Result<Command, String> {
    if args.first() != Some(&"-Y") || args.len() < 2 {
        return Err("usage: qsg-ssh-keygen -Y {sign|find-principals|verify} ...".into());
    }
    let sub = args[1];
    let mut namespace: Option<String> = None;
    let mut key = None;
    let mut allowed = None;
    let mut signature = None;
    let mut principal = None;
    let mut verify_time = None;
    let mut positional = Vec::new();
    let mut i = 2;
    while i < args.len() {
        let arg = args[i];
        match arg {
            "-U" => {
                return Err(
                    "ssh-agent key form (-U) is not supported; use a QSGit key file".into(),
                );
            }
            "-n" | "-f" | "-s" | "-I" => {
                let val = args
                    .get(i + 1)
                    .ok_or_else(|| format!("missing value after {arg}"))?;
                let slot = match arg {
                    "-n" => &mut namespace,
                    "-f" if sub == "sign" => &mut key,
                    "-f" => &mut allowed,
                    "-s" => &mut signature,
                    _ => &mut principal,
                };
                if slot.replace((*val).to_owned()).is_some() {
                    return Err(format!("duplicate {arg}"));
                }
                i += 2;
            }
            a if a.starts_with("-Overify-time=") => {
                if verify_time.replace(a[14..].to_owned()).is_some() {
                    return Err("duplicate verify-time option".into());
                }
                i += 1;
            }
            "-O" => {
                let val = args.get(i + 1).ok_or("missing value after -O")?;
                let value = val
                    .strip_prefix("verify-time=")
                    .ok_or_else(|| format!("unsupported option -O {val}"))?;
                if verify_time.replace(value.to_owned()).is_some() {
                    return Err("duplicate verify-time option".into());
                }
                i += 2;
            }
            a if a.starts_with('-') => return Err(format!("unsupported flag {a}")),
            _ => {
                positional.push(arg.to_owned());
                i += 1;
            }
        }
    }
    match sub {
        "sign" => {
            if namespace.as_deref() != Some("git") {
                return Err("sign requires exactly -n git".into());
            }
            if allowed.is_some()
                || signature.is_some()
                || principal.is_some()
                || verify_time.is_some()
                || positional.len() != 1
            {
                return Err("usage: -Y sign -n git -f <keyfile> <buffer>".into());
            }
            Ok(Command::Sign {
                key: PathBuf::from(key.ok_or("sign requires -f <keyfile>")?),
                buffer: PathBuf::from(positional.remove(0)),
            })
        }
        "find-principals" => {
            if namespace.is_some() || key.is_some() || principal.is_some() || !positional.is_empty()
            {
                return Err("find-principals does not accept -n or positional arguments".into());
            }
            Ok(Command::Find {
                allowed: PathBuf::from(
                    allowed.ok_or("find-principals requires -f <allowed_signers>")?,
                ),
                signature: PathBuf::from(
                    signature.ok_or("find-principals requires -s <signature>")?,
                ),
                verify_time: verify_time
                    .ok_or("find-principals requires -Overify-time or -O verify-time")?,
            })
        }
        "verify" => {
            if namespace.as_deref() != Some("git") {
                return Err("verify requires exactly -n git".into());
            }
            if key.is_some() || !positional.is_empty() {
                return Err("verify does not accept positional arguments".into());
            }
            Ok(Command::Verify {
                allowed: PathBuf::from(allowed.ok_or("verify requires -f <allowed_signers>")?),
                principal: principal.ok_or("verify requires -I <principal>")?,
                signature: PathBuf::from(signature.ok_or("verify requires -s <signature>")?),
                verify_time: verify_time
                    .ok_or("verify requires -Overify-time or -O verify-time")?,
            })
        }
        _ => Err(format!("unsupported -Y subcommand: {sub}")),
    }
}

fn sign(key_path: &Path, buffer_path: &Path) -> Result<(), String> {
    let loaded = qsg_keystore::load_secret(key_path, None, true);
    let (public, secret, kind) = match loaded {
        Ok(v) => v,
        Err(qsg_keystore::Error::PassphraseRequired) => {
            let mut value = rpassword::prompt_password("QSGit key passphrase: ")
                .map_err(|_| "could not read passphrase from terminal".to_owned())?;
            let passphrase = match Passphrase::new(value.as_bytes()) {
                Ok(passphrase) => passphrase,
                Err(_) => {
                    value.zeroize();
                    return Err("invalid passphrase".to_owned());
                }
            };
            value.zeroize();
            qsg_keystore::load_secret(key_path, Some(&passphrase), false)
                .map_err(|e| format!("could not load QSGit key: {e}"))?
        }
        Err(e) => return Err(format!("could not load QSGit key: {e}")),
    };
    if kind == KeyKind::Unencrypted {
        eprintln!("qsg-ssh-keygen: warning: using an unencrypted private key");
    }
    let data = read_limited(
        fs::File::open(buffer_path).map_err(|e| format!("could not read signing buffer: {e}"))?,
        MAX_MESSAGE as usize,
        "signing buffer",
    )?;
    let record =
        sign_ml_dsa65(&public, &secret, &data).map_err(|e| format!("signing failed: {e}"))?;
    let blob = qsg_sshsig::encode_blob(&record).map_err(|e| e.to_string())?;
    let armor = qsg_sshsig::encode_armor(&blob).map_err(|e| e.to_string())?;
    let mut out = buffer_path.as_os_str().to_os_string();
    out.push(".sig");
    fs::write(PathBuf::from(out), armor.as_bytes())
        .map_err(|e| format!("could not write signature: {e}"))
}

fn find(
    allowed_path: &Path,
    sig_path: &Path,
    time_text: &str,
    offset: Result<Option<UtcOffset>, String>,
) -> Result<(), String> {
    let principals = qsg_verify::find_principals(allowed_path, sig_path, time_text, offset)?;
    for p in principals {
        println!("{p}");
    }
    Ok(())
}

fn verify(
    allowed_path: &Path,
    principal: &str,
    sig_path: &Path,
    time_text: &str,
    offset: Result<Option<UtcOffset>, String>,
) -> Result<(), String> {
    let fp = qsg_verify::verify_message(
        allowed_path,
        principal,
        sig_path,
        time_text,
        io::stdin(),
        offset,
    )
    .map_err(|failure| {
        if let Some(output) = failure.stdout_message {
            println!("{output}");
        }
        failure.message
    })?;
    println!("Good \"git\" signature for {principal} with MLDSA65 key {fp}");
    Ok(())
}

fn read_limited(mut reader: impl Read, limit: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read {label}: {e}"))?;
    if bytes.len() > limit {
        return Err(format!("{label} exceeds {limit} byte limit"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_git_call_shapes() {
        assert!(parse_args(&["-Y", "sign", "-n", "git", "-f", "k", "b"]).is_ok());
        assert!(
            parse_args(&[
                "-Y",
                "find-principals",
                "-f",
                "a",
                "-s",
                "s",
                "-Overify-time=20250101000000"
            ])
            .is_ok()
        );
        assert!(
            parse_args(&[
                "-Y",
                "verify",
                "-n",
                "git",
                "-f",
                "a",
                "-I",
                "p",
                "-s",
                "s",
                "-O",
                "verify-time=20250101000000"
            ])
            .is_ok()
        );
        for shape in [
            vec!["-Y", "sign", "-f", "k", "b"],
            vec!["-Y", "check-novalidate", "-n", "git", "-s", "s"],
            vec![
                "-Y",
                "find-principals",
                "-n",
                "git",
                "-f",
                "a",
                "-s",
                "s",
                "-Overify-time=20250101000000",
            ],
            vec!["-Y", "verify", "-n", "git", "-f", "a", "-I", "p", "-s", "s"],
            vec!["-Y", "sign", "-n", "git", "-f", "k", "-U", "b"],
            vec!["-Y", "sign", "-n", "git", "-f", "k", "-X", "b"],
        ] {
            assert!(parse_args(&shape).is_err(), "accepted {shape:?}");
        }
    }

    #[test]
    fn external_inputs_are_bounded() {
        assert_eq!(read_limited(&b"1234"[..], 4, "input").unwrap(), b"1234");
        assert!(
            read_limited(&b"12345"[..], 4, "input")
                .unwrap_err()
                .contains("4 byte limit")
        );
    }

    #[test]
    fn signing_buffer_read_is_limited_to_16_mib() {
        let error =
            read_limited(io::repeat(b'x'), MAX_MESSAGE as usize, "signing buffer").unwrap_err();
        assert!(error.contains("signing buffer exceeds 16777216 byte limit"));
    }
}
