#![forbid(unsafe_code)]

use qsg_keystore::{KeyKind, Passphrase};
use qsg_sshsig::{decode_armor, decode_blob, fingerprint, sign_ml_dsa65, verify_ml_dsa65};
use qsg_trust::{
    AllowedSigners, Revocations, TimeBasis, UtcOffset, parse_allowed_signers, parse_verify_time,
};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use time::{Date, Month, OffsetDateTime, UtcOffset as TimeOffset};
use zeroize::Zeroize;

const MAX_SIGNATURE: u64 = 128 * 1024;
const MAX_ALLOWED_SIGNERS: u64 = 1024 * 1024;
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
                    .and_then(system_local_offset)
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
    let record = load_signature(sig_path)?;
    if record.namespace != "git" {
        return Err("signature namespace is not git".into());
    }
    let time = parse_verify_time(time_text).map_err(|e| format!("invalid verify-time: {e}"))?;
    let allowed = load_allowed(allowed_path)?;
    let offset = offset_if_needed(
        &allowed,
        &record.public_key,
        None,
        &record.namespace,
        time_text,
        offset,
    )?;
    let principals = allowed
        .find_principals(&record.public_key, &record.namespace, time, offset)
        .map_err(|e| e.to_string())?;
    if principals.is_empty() {
        return Err("No principal matched.".into());
    }
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
    let record = load_signature(sig_path)?;
    if record.namespace != "git" {
        return Err("signature namespace does not match -n git".into());
    }
    let time = parse_verify_time(time_text).map_err(|e| format!("invalid verify-time: {e}"))?;
    let allowed = load_allowed(allowed_path)?;
    let revocations = load_revocations(allowed_path)?;
    let offset = offset_if_needed(
        &allowed,
        &record.public_key,
        Some(principal),
        "git",
        time_text,
        offset,
    )?;
    let _trusted = allowed
        .check(
            principal,
            &record.public_key,
            "git",
            time,
            offset,
            &revocations,
        )
        .map_err(|e| format!("Could not verify signature.\n{e}"))?;
    let message = read_limited(io::stdin(), MAX_MESSAGE as usize, "signed message")?;
    if verify_ml_dsa65(&record, &message).is_err() {
        println!("Could not verify signature.");
        return Err("Signature verification failed: incorrect signature".into());
    }
    let fp = fingerprint(&record.public_key).map_err(|e| e.to_string())?;
    println!("Good \"git\" signature for {principal} with MLDSA65 key {fp}");
    Ok(())
}

fn load_signature(path: &Path) -> Result<qsg_sshsig::SshSignature, String> {
    let bytes = read_limited(
        fs::File::open(path).map_err(|e| format!("could not read signature file: {e}"))?,
        MAX_SIGNATURE as usize,
        "signature file",
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "signature armor is not UTF-8")?;
    let blob = decode_armor(text).map_err(|e| format!("invalid signature armor: {e}"))?;
    decode_blob(&blob).map_err(|e| format!("invalid signature: {e}"))
}

fn load_allowed(path: &Path) -> Result<AllowedSigners, String> {
    let bytes = read_limited(
        fs::File::open(path).map_err(|e| format!("could not read allowed_signers: {e}"))?,
        MAX_ALLOWED_SIGNERS as usize,
        "allowed_signers",
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "allowed_signers is not UTF-8")?;
    parse_allowed_signers(text).map_err(|e| e.to_string())
}

fn load_revocations(allowed_path: &Path) -> Result<Revocations, String> {
    let path = match env::var_os("QSG_REVOKED_KEYS") {
        Some(value) => PathBuf::from(value),
        None => allowed_path
            .parent()
            .unwrap_or(Path::new("."))
            .join("revoked_keys"),
    };
    if env::var_os("QSG_REVOKED_KEYS").is_none() && !path.exists() {
        return Ok(Revocations::default());
    }
    let bytes = read_limited(
        fs::File::open(&path).map_err(|e| format!("could not read revocation file: {e}"))?,
        MAX_ALLOWED_SIGNERS as usize,
        "revocation file",
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "revocation file is not UTF-8")?;
    Revocations::parse(text).map_err(|e| e.to_string())
}

fn offset_if_needed(
    allowed: &AllowedSigners,
    key: &[u8],
    principal: Option<&str>,
    namespace: &str,
    time_text: &str,
    offset: Result<Option<UtcOffset>, String>,
) -> Result<Option<UtcOffset>, String> {
    let parsed = parse_verify_time(time_text).map_err(|e| e.to_string())?;
    let mismatch = allowed.entries.iter().any(|entry| {
        entry.key_blob == key
            && entry.namespaces.iter().any(|n| n == namespace)
            && principal.is_none_or(|p| entry.principals.iter().any(|v| v == p))
            && [entry.valid_after, entry.valid_before]
                .into_iter()
                .flatten()
                .any(|bound| bound.basis != parsed.basis)
    });
    if !mismatch {
        return Ok(None);
    }
    offset?
        .ok_or_else(|| "machine UTC offset unavailable; UTC validity check failed closed".into())
        .map(Some)
}

fn civil_seconds(c: qsg_trust::CivilDateTime) -> Result<i64, String> {
    let month = Month::try_from(c.month).map_err(|_| "invalid verify-time month")?;
    let date = Date::from_calendar_date(c.year as i32, month, c.day)
        .map_err(|_| "invalid verify-time date")?;
    let wall = date
        .with_hms(c.hour, c.minute, c.second)
        .map_err(|_| "invalid verify-time clock")?
        .assume_utc();
    Ok(wall.unix_timestamp())
}

fn local_civil_to_utc_seconds(
    parsed: qsg_trust::VerifyTime,
    offset: UtcOffset,
) -> Result<i64, String> {
    let wall_seconds = civil_seconds(parsed.civil)?;
    if parsed.basis == TimeBasis::Utc {
        return Ok(wall_seconds);
    }
    Ok(wall_seconds - i64::from(offset.minutes_east) * 60)
}

fn system_local_offset(parsed: qsg_trust::VerifyTime) -> Result<Option<UtcOffset>, String> {
    let wall_seconds = civil_seconds(parsed.civil)?;
    if parsed.basis == TimeBasis::Utc {
        return offset_at(wall_seconds).map(Some);
    }

    // Solve local wall time = UTC instant + offset. Sampling nearby instants
    // discovers candidate offsets across DST transitions without a tz database.
    let mut candidates = std::collections::BTreeSet::new();
    for hours in (-48..=48).step_by(3) {
        let probe = wall_seconds + i64::from(hours) * 3600;
        let candidate_offset = offset_at_seconds(probe)?;
        if candidate_offset.whole_seconds() % 60 != 0 {
            return Err(
                "machine UTC offset is not minute-aligned; UTC validity check failed closed".into(),
            );
        }
        let candidate_offset =
            UtcOffset::new(candidate_offset.whole_minutes()).map_err(|e| e.to_string())?;
        let utc_seconds = local_civil_to_utc_seconds(parsed, candidate_offset)?;
        let actual = offset_at_seconds(utc_seconds)?;
        if actual.whole_seconds() == i32::from(candidate_offset.minutes_east) * 60 {
            candidates.insert(actual.whole_seconds());
        }
    }
    if candidates.len() != 1 {
        let reason = if candidates.is_empty() {
            "does not map to a local machine time"
        } else {
            "is ambiguous during a daylight-saving transition"
        };
        return Err(format!(
            "verify-time {reason}; UTC validity check failed closed"
        ));
    }
    let minutes = i16::try_from(*candidates.first().expect("one candidate") / 60)
        .map_err(|_| "machine UTC offset is out of range")?;
    UtcOffset::new(minutes).map(Some).map_err(|e| e.to_string())
}

fn offset_at(seconds: i64) -> Result<UtcOffset, String> {
    let offset = offset_at_seconds(seconds)?;
    if offset.whole_seconds() % 60 != 0 {
        return Err(
            "machine UTC offset is not minute-aligned; UTC validity check failed closed".into(),
        );
    }
    UtcOffset::new(offset.whole_minutes()).map_err(|e| e.to_string())
}

fn offset_at_seconds(seconds: i64) -> Result<TimeOffset, String> {
    let instant =
        OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| "verify-time is out of range")?;
    TimeOffset::local_offset_at(instant).map_err(|_| {
        "cannot determine machine UTC offset for verify-time; UTC validity check failed closed"
            .into()
    })
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
    fn local_to_utc_conversion_uses_explicit_offsets_at_dst_boundaries() {
        let before_spring = parse_verify_time("20250309013000").unwrap();
        let after_spring = parse_verify_time("20250309033000").unwrap();
        let spring_before = UtcOffset::new(-300).unwrap();
        let spring_after = UtcOffset::new(-240).unwrap();
        let before_utc = local_civil_to_utc_seconds(before_spring, spring_before).unwrap();
        let after_utc = local_civil_to_utc_seconds(after_spring, spring_after).unwrap();
        assert_eq!(after_utc - before_utc, 60 * 60);

        // The repeated fall-back wall time maps to two possible UTC instants;
        // Git's timestamp does not say which offset was intended.
        let repeated = parse_verify_time("20251102013000").unwrap();
        let daylight_utc = local_civil_to_utc_seconds(repeated, spring_after).unwrap();
        let standard_utc = local_civil_to_utc_seconds(repeated, spring_before).unwrap();
        assert_eq!(standard_utc - daylight_utc, 60 * 60);
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
