use crate::public_key::read_public;
use qsg_trust::{parse_allowed_signers, parse_verify_time};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run() -> Result<(), String> {
    let mut errors = false;
    let mut report = |level: &str, message: String| {
        println!("{level}: {message}");
        if level == "ERROR" {
            errors = true;
        }
    };

    let git_version = command_output("git", &["--version"]);
    match git_version {
        None => report("ERROR", "git was not found on PATH".into()),
        Some(version) => {
            println!("INFO: {version}");
            if let Some((major, minor)) = version.split_whitespace().last().and_then(parse_version)
            {
                if (major, minor) < (2, 34) {
                    report(
                        "WARN",
                        "Git is older than 2.34; SSH signing is unavailable".into(),
                    );
                } else if !matches!((major, minor), (2, 55) | (2, 56)) {
                    report(
                        "WARN",
                        "Git version is not among the tested versions 2.55.0 and 2.56.0".into(),
                    );
                }
            } else {
                report("WARN", "could not parse Git version".into());
            }
        }
    }

    let keys = [
        "gpg.format",
        "gpg.ssh.program",
        "user.signingkey",
        "gpg.ssh.allowedSignersFile",
        "gpg.ssh.revocationFile",
    ];
    let mut values = std::collections::HashMap::new();
    for key in keys {
        let local = git_config(key, false);
        let global = git_config(key, true);
        println!(
            "INFO: config {key}: repo={} global={}",
            local.as_deref().unwrap_or("<unset>"),
            global.as_deref().unwrap_or("<unset>")
        );
        values.insert(key, local.or(global));
    }
    if let Some(value) = &values["gpg.format"] {
        if value != "ssh" {
            report(
                "ERROR",
                format!("gpg.format is {value}; QSGit requires ssh"),
            );
        }
    } else {
        report(
            "WARN",
            "gpg.format is unset; configure gpg.format=ssh for QSGit signing".into(),
        );
    }
    if let Some(value) = &values["gpg.ssh.revocationFile"] {
        report(
            "ERROR",
            format!(
                "gpg.ssh.revocationFile is set to {value}; unset it and use QSG_REVOKED_KEYS or revoked_keys"
            ),
        );
    }

    let program = values.get("gpg.ssh.program").and_then(Clone::clone);
    match program.as_deref().and_then(resolve_executable) {
        None => report(
            "ERROR",
            "gpg.ssh.program is unset or does not resolve on PATH".into(),
        ),
        Some(path) => {
            let sibling = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(Path::to_path_buf))
                .map(|p| {
                    p.join(if cfg!(windows) {
                        "qsg-ssh-keygen.exe"
                    } else {
                        "qsg-ssh-keygen"
                    })
                });
            let is_ours =
                sibling.as_ref().and_then(|p| p.canonicalize().ok()) == path.canonicalize().ok();
            if !is_ours {
                report(
                    "ERROR",
                    format!(
                        "gpg.ssh.program resolves to {}, not this QSGit installation",
                        path.display()
                    ),
                );
            } else {
                println!("INFO: QSGit shim: {}", path.display());
            }
        }
    }

    let signing_key = values.get("user.signingkey").and_then(Clone::clone);
    let allowed = values
        .get("gpg.ssh.allowedSignersFile")
        .and_then(Clone::clone)
        .map(PathBuf::from);
    if let Some(path) = &allowed {
        match read_bounded(path, 1024 * 1024) {
            Ok(bytes) => match std::str::from_utf8(&bytes)
                .ok()
                .and_then(|t| parse_allowed_signers(t).ok())
            {
                Some(parsed) => {
                    if let Some(key_path) = &signing_key {
                        match read_public(key_path) {
                            Ok(key) => {
                                if parsed.entries.iter().any(|e| e.key_blob == key.blob) {
                                    println!(
                                        "INFO: signing key {} is listed in allowed_signers",
                                        key.fingerprint
                                    );
                                } else {
                                    report(
                                        "WARN",
                                        format!(
                                            "signing key {} is not listed in allowed_signers",
                                            key.fingerprint
                                        ),
                                    );
                                }
                                #[cfg(unix)]
                                check_key_file(key_path, &mut report);
                            }
                            Err(_) => report(
                                "ERROR",
                                format!("signing key {} is not a readable QSGit key", key_path),
                            ),
                        }
                    } else {
                        report("WARN", "user.signingkey is unset".into());
                    }
                }
                None => report(
                    "ERROR",
                    format!("allowed_signers {} is malformed", path.display()),
                ),
            },
            Err(e) => report(
                "ERROR",
                format!("allowed_signers {} cannot be read: {e}", path.display()),
            ),
        }
    } else {
        report("ERROR", "gpg.ssh.allowedSignersFile is unset".into());
    }

    if let Some(path) = signing_key {
        if path.starts_with("key::") {
            report(
                "ERROR",
                "ssh-agent/literal key signing is not supported by QSGit".into(),
            );
        } else if !path.is_empty() {
            let private = if path.ends_with(".pub") {
                PathBuf::from(path.trim_end_matches(".pub"))
            } else {
                PathBuf::from(&path)
            };
            match read_bounded(&private, 108) {
                Ok(bytes) if bytes.len() == 107 && bytes.get(8) == Some(&0) => report(
                    "WARN",
                    format!(
                        "private key {} has no passphrase encryption",
                        private.display()
                    ),
                ),
                _ => {}
            }
        }
    }

    if let Some(value) = std::env::var_os("QSG_REVOKED_KEYS") {
        let path = PathBuf::from(value);
        if !path.is_file() {
            report(
                "WARN",
                format!("QSG_REVOKED_KEYS points to missing file {}", path.display()),
            );
        }
    }
    if parse_verify_time("20250101000000Z")
        .ok()
        .and_then(|t| qsg_verify::system_local_offset(t).ok())
        .flatten()
        .is_none()
    {
        report("WARN", "machine UTC-offset lookup is unavailable".into());
    }
    if cfg!(windows) {
        println!("INFO: Windows private-key file permissions are not enforced");
    }
    if errors {
        Err("doctor found ERROR conditions".into())
    } else {
        Ok(())
    }
}

fn command_output(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn read_bounded(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds size limit",
        ));
    }
    Ok(bytes)
}

fn git_config(key: &str, global: bool) -> Option<String> {
    if global {
        command_output("git", &["config", "--global", "--path", "--get", key])
    } else {
        command_output("git", &["config", "--path", "--get", key])
    }
}

fn parse_version(text: &str) -> Option<(u32, u32)> {
    let mut parts = text.split('.');
    Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
}

fn resolve_executable(program: &str) -> Option<PathBuf> {
    let path = PathBuf::from(program);
    if path.components().count() > 1 || path.is_absolute() {
        return path.is_file().then_some(path);
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| {
            dir.join(
                if cfg!(windows) && !program.to_ascii_lowercase().ends_with(".exe") {
                    format!("{program}.exe")
                } else {
                    program.to_owned()
                },
            )
        })
        .find(|p| p.is_file())
}

#[cfg(unix)]
fn check_key_file(key: &str, report: &mut impl FnMut(&str, String)) {
    let private = if key.ends_with(".pub") {
        PathBuf::from(key.trim_end_matches(".pub"))
    } else {
        PathBuf::from(key)
    };
    {
        use std::os::unix::fs::PermissionsExt;
        match fs::metadata(&private) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o600 {
                    report(
                        "ERROR",
                        format!(
                            "private key {} has mode {:04o}; run: chmod 600 '{}'",
                            private.display(),
                            mode,
                            private.display()
                        ),
                    );
                }
            }
            Err(e) => report(
                "ERROR",
                format!("private key {} is unavailable: {e}", private.display()),
            ),
        }
        if let Some(parent) = private.parent() {
            match fs::metadata(parent) {
                Ok(meta) => {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode != 0o700 {
                        report(
                            "ERROR",
                            format!(
                                "key directory {} has mode {:04o}; run: chmod 700 '{}'",
                                parent.display(),
                                mode,
                                parent.display()
                            ),
                        );
                    }
                }
                Err(e) => report(
                    "ERROR",
                    format!("key directory {} is unavailable: {e}", parent.display()),
                ),
            }
        }
    }
}
