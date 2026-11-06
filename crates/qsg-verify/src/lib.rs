#![forbid(unsafe_code)]

//! Shared trust and cryptographic verification used by the Git shim and `qsg`.

use qsg_sshsig::{decode_armor, decode_blob, fingerprint, verify_ml_dsa65};
use qsg_trust::{
    AllowedSigners, Revocations, TimeBasis, UtcOffset, parse_allowed_signers, parse_verify_time,
};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use time::{Date, Month, OffsetDateTime, UtcOffset as TimeOffset};

const MAX_SIGNATURE: u64 = 128 * 1024;
const MAX_ALLOWED_SIGNERS: u64 = 1024 * 1024;
const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// Error details needed by the shim to preserve its established stdout/stderr split.
#[derive(Debug)]
pub struct VerifyFailure {
    pub message: String,
    pub stdout_message: Option<&'static str>,
}

impl From<String> for VerifyFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            stdout_message: None,
        }
    }
}

/// Find principals trusted for the signature and verification time.
pub fn find_principals(
    allowed_path: &Path,
    sig_path: &Path,
    time_text: &str,
    offset: Result<Option<UtcOffset>, String>,
) -> Result<Vec<String>, String> {
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
    let principals = find_principals_record(&allowed, &record, time, offset)?;
    if principals.is_empty() {
        return Err("No principal matched.".into());
    }
    Ok(principals)
}

/// Find allowed principals for a decoded SSHSIG record.
pub fn find_principals_record(
    allowed: &AllowedSigners,
    record: &qsg_sshsig::SshSignature,
    time: qsg_trust::VerifyTime,
    offset: Option<UtcOffset>,
) -> Result<Vec<String>, String> {
    allowed
        .find_principals(&record.public_key, &record.namespace, time, offset)
        .map_err(|e| e.to_string())
}

/// Parse an allowed-signers file with the same limit and parser used by the shim.
pub fn read_allowed(path: &Path) -> Result<AllowedSigners, String> {
    load_allowed(path)
}

/// Verify a signature over supplied bytes against trust, validity, and revocation policy.
/// Returns the key fingerprint after the complete verification chain succeeds.
pub fn verify_message(
    allowed_path: &Path,
    principal: &str,
    sig_path: &Path,
    time_text: &str,
    message: impl Read,
    offset: Result<Option<UtcOffset>, String>,
) -> Result<String, VerifyFailure> {
    let record = load_signature(sig_path).map_err(VerifyFailure::from)?;
    verify_record_message(
        allowed_path,
        principal,
        &record,
        time_text,
        message,
        offset,
        None,
    )
}

/// Verify an already-decoded record. Used by standalone object verification.
pub fn verify_record_message(
    allowed_path: &Path,
    principal: &str,
    record: &qsg_sshsig::SshSignature,
    time_text: &str,
    message: impl Read,
    offset: Result<Option<UtcOffset>, String>,
    revoked_path: Option<&Path>,
) -> Result<String, VerifyFailure> {
    if record.namespace != "git" {
        return Err(VerifyFailure::from(
            "signature namespace does not match -n git".to_owned(),
        ));
    }
    let time = parse_verify_time(time_text)
        .map_err(|e| VerifyFailure::from(format!("invalid verify-time: {e}")))?;
    let allowed = load_allowed(allowed_path).map_err(VerifyFailure::from)?;
    let revocations = load_revocations(allowed_path, revoked_path).map_err(VerifyFailure::from)?;
    let offset = offset_if_needed(
        &allowed,
        &record.public_key,
        Some(principal),
        "git",
        time_text,
        offset,
    )
    .map_err(VerifyFailure::from)?;
    allowed
        .check(
            principal,
            &record.public_key,
            "git",
            time,
            offset,
            &revocations,
        )
        .map_err(|e| VerifyFailure::from(format!("Could not verify signature.\n{e}")))?;
    let message = read_message(message).map_err(VerifyFailure::from)?;
    if verify_ml_dsa65(&record, &message).is_err() {
        return Err(VerifyFailure {
            message: "Signature verification failed: incorrect signature".into(),
            stdout_message: Some("Could not verify signature."),
        });
    }
    fingerprint(&record.public_key).map_err(|e| VerifyFailure::from(e.to_string()))
}

/// Decode a bounded canonical SSHSIG armor block.
pub fn decode_signature(bytes: &[u8]) -> Result<qsg_sshsig::SshSignature, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "signature armor is not UTF-8")?;
    let blob = decode_armor(text).map_err(|e| format!("invalid signature armor: {e}"))?;
    decode_blob(&blob).map_err(|e| format!("invalid signature: {e}"))
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

fn load_revocations(
    allowed_path: &Path,
    override_path: Option<&Path>,
) -> Result<Revocations, String> {
    let configured = override_path
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("QSG_REVOKED_KEYS").map(PathBuf::from));
    let path = configured.as_ref().cloned().unwrap_or_else(|| {
        allowed_path
            .parent()
            .unwrap_or(Path::new("."))
            .join("revoked_keys")
    });
    if configured.is_none() && !path.exists() {
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

/// Resolve Git's local civil verify time to the unique machine UTC offset, if any.
pub fn system_local_offset(parsed: qsg_trust::VerifyTime) -> Result<Option<UtcOffset>, String> {
    let wall_seconds = civil_seconds(parsed.civil)?;
    if parsed.basis == TimeBasis::Utc {
        return offset_at(wall_seconds).map(Some);
    }
    // Solve local wall time = UTC instant + offset by sampling nearby instants.
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
    let minutes = i16::try_from(
        *candidates
            .first()
            .ok_or("no machine UTC offset candidate")?
            / 60,
    )
    .map_err(|_| "machine UTC offset is out of range")?;
    UtcOffset::new(minutes).map(Some).map_err(|e| e.to_string())
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

/// Bounded stdin reader shared by the shim and standalone verifier.
pub fn read_message(reader: impl Read) -> Result<Vec<u8>, String> {
    read_limited(reader, MAX_MESSAGE, "signed message")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_to_utc_conversion_uses_explicit_offsets_at_dst_boundaries() {
        let before_spring = parse_verify_time("20250309013000").unwrap();
        let after_spring = parse_verify_time("20250309033000").unwrap();
        let spring_before = UtcOffset::new(-300).unwrap();
        let spring_after = UtcOffset::new(-240).unwrap();
        let before_utc = local_civil_to_utc_seconds(before_spring, spring_before).unwrap();
        let after_utc = local_civil_to_utc_seconds(after_spring, spring_after).unwrap();
        assert_eq!(after_utc - before_utc, 60 * 60);
        let repeated = parse_verify_time("20251102013000").unwrap();
        let daylight_utc = local_civil_to_utc_seconds(repeated, spring_after).unwrap();
        let standard_utc = local_civil_to_utc_seconds(repeated, spring_before).unwrap();
        assert_eq!(standard_utc - daylight_utc, 60 * 60);
    }
}
