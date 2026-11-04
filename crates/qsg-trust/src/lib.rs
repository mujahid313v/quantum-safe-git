#![forbid(unsafe_code)]

//! Strict local trust data parsing and validity evaluation. No Git or network I/O.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use std::collections::HashSet;
use thiserror::Error;

pub const MAX_FILE_SIZE: usize = 1024 * 1024;
pub const MAX_LINE_LENGTH: usize = 16 * 1024;
pub const MAX_ENTRIES: usize = 10_000;
const KEY_TYPE: &str = qsg_sshsig::ML_DSA_65_KEY_TYPE;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrustError {
    #[error("input exceeds the 1 MiB limit")]
    FileTooLarge,
    #[error("line {line}: line exceeds the 16 KiB limit")]
    LineTooLong { line: usize },
    #[error("input exceeds the 10,000 entry limit")]
    TooManyEntries,
    #[error("line {line}: malformed allowed_signers entry: {reason}")]
    MalformedLine { line: usize, reason: String },
    #[error("line {line}: unsupported principal pattern; wildcards and negation are not supported")]
    UnsupportedPrincipalPattern { line: usize },
    #[error("line {line}: namespaces option is required and must include git")]
    MissingGitNamespace { line: usize },
    #[error("line {line}: cert-authority is not supported")]
    CertificateAuthority { line: usize },
    #[error("line {line}: unknown allowed_signers option '{option}'")]
    UnknownOption { line: usize, option: String },
    #[error("line {line}: duplicate allowed_signers option '{option}'")]
    DuplicateOption { line: usize, option: String },
    #[error("line {line}: invalid timestamp '{value}'")]
    InvalidTimestamp { line: usize, value: String },
    #[error("line {line}: invalid public key blob")]
    InvalidPublicKey { line: usize },
    #[error("line {line}: invalid base64 public key blob")]
    InvalidBase64 { line: usize },
    #[error(
        "verification and validity timestamps use different UTC/local bases; provide an explicit UTC offset"
    )]
    MixedTimeBasis,
    #[error("verification time is outside this key's validity window")]
    OutsideValidity,
    #[error("key is revoked: {0}")]
    Revoked(String),
    #[error("no trusted key matches the principal, key, namespace, and verification time")]
    NotTrusted,
    #[error("line {line}: invalid revocation fingerprint")]
    InvalidRevocation { line: usize },
    #[error("invalid civil date-time")]
    InvalidCivilDateTime,
    #[error("UTC offset minutes must be between -1439 and 1439")]
    InvalidUtcOffset,
}

pub type Result<T> = std::result::Result<T, TrustError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CivilDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeBasis {
    Utc,
    Local,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyTime {
    pub civil: CivilDateTime,
    pub basis: TimeBasis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtcOffset {
    /// Minutes east of UTC, e.g. +330 for +0530.
    pub minutes_east: i16,
}

impl UtcOffset {
    pub fn new(minutes_east: i16) -> Result<Self> {
        if !(-1439..=1439).contains(&minutes_east) {
            return Err(TrustError::InvalidUtcOffset);
        }
        Ok(Self { minutes_east })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedSignerEntry {
    pub line: usize,
    pub principals: Vec<String>,
    pub namespaces: Vec<String>,
    pub valid_after: Option<VerifyTime>,
    pub valid_before: Option<VerifyTime>,
    pub key_blob: Vec<u8>,
    pub fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedEntry {
    pub line: usize,
    pub key_type: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AllowedSigners {
    pub entries: Vec<AllowedSignerEntry>,
    pub skipped: Vec<SkippedEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedKey {
    pub principal: String,
    pub fingerprint: String,
    pub key_blob: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Revocations {
    fingerprints: HashSet<String>,
}

pub fn parse_allowed_signers(text: &str) -> Result<AllowedSigners> {
    if text.len() > MAX_FILE_SIZE {
        return Err(TrustError::FileTooLarge);
    }
    let mut allowed = AllowedSigners::default();
    let mut count = 0usize;
    for (index, raw) in text.split('\n').enumerate() {
        let line_number = index + 1;
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.len() > MAX_LINE_LENGTH {
            return Err(TrustError::LineTooLong { line: line_number });
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.chars().any(|ch| ch.is_control() && ch != '\t') {
            return Err(malformed(line_number, "control character in line"));
        }
        count += 1;
        if count > MAX_ENTRIES {
            return Err(TrustError::TooManyEntries);
        }
        let tokens = split_words(line).map_err(|reason| malformed(line_number, reason))?;
        if tokens.len() < 3 {
            return Err(malformed(
                line_number,
                "expected principals, options, and key type",
            ));
        }
        if tokens[1] == KEY_TYPE {
            return Err(TrustError::MissingGitNamespace { line: line_number });
        }
        if looks_like_key_type(&tokens[1]) {
            allowed.skipped.push(SkippedEntry {
                line: line_number,
                key_type: tokens[1].clone(),
            });
            continue;
        }
        let key_type = &tokens[2];
        if key_type != KEY_TYPE {
            allowed.skipped.push(SkippedEntry {
                line: line_number,
                key_type: key_type.clone(),
            });
            continue;
        }
        if tokens.len() < 4 {
            return Err(malformed(line_number, "missing public key blob"));
        }
        let principals = parse_principals(&tokens[0], line_number)?;
        let (namespaces, valid_after, valid_before) = parse_options(&tokens[1], line_number)?;
        let blob = STANDARD
            .decode(&tokens[3])
            .map_err(|_| TrustError::InvalidBase64 { line: line_number })?;
        let _public = qsg_sshsig::decode_ml_dsa65_public_key_blob(&blob)
            .map_err(|_| TrustError::InvalidPublicKey { line: line_number })?;
        let fingerprint = qsg_sshsig::fingerprint(&blob)
            .map_err(|_| TrustError::InvalidPublicKey { line: line_number })?;
        allowed.entries.push(AllowedSignerEntry {
            line: line_number,
            principals,
            namespaces,
            valid_after,
            valid_before,
            key_blob: blob,
            fingerprint,
        });
    }
    Ok(allowed)
}

impl AllowedSignerEntry {
    pub fn is_valid_at(&self, verify_time: VerifyTime, offset: Option<UtcOffset>) -> Result<bool> {
        if !valid_civil(verify_time.civil) {
            return Err(TrustError::InvalidCivilDateTime);
        }
        if self
            .valid_after
            .map(|after| compare_times(verify_time, after, offset))
            .transpose()?
            == Some(std::cmp::Ordering::Less)
        {
            return Ok(false);
        }
        if self
            .valid_before
            .map(|before| compare_times(verify_time, before, offset))
            .transpose()?
            == Some(std::cmp::Ordering::Greater)
        {
            return Ok(false);
        }
        Ok(true)
    }
}

impl AllowedSigners {
    pub fn find_principals(
        &self,
        key_blob: &[u8],
        namespace: &str,
        verify_time: VerifyTime,
        offset: Option<UtcOffset>,
    ) -> Result<Vec<String>> {
        let mut principals = Vec::new();
        for entry in &self.entries {
            if entry.key_blob != key_blob || !entry.namespaces.iter().any(|n| n == namespace) {
                continue;
            }
            if entry.is_valid_at(verify_time, offset)? {
                for principal in &entry.principals {
                    if !principals.contains(principal) {
                        principals.push(principal.clone());
                    }
                }
            }
        }
        Ok(principals)
    }

    pub fn check(
        &self,
        principal: &str,
        key_blob: &[u8],
        namespace: &str,
        verify_time: VerifyTime,
        offset: Option<UtcOffset>,
        revocations: &Revocations,
    ) -> Result<TrustedKey> {
        let fingerprint = qsg_sshsig::fingerprint(key_blob).map_err(|_| TrustError::NotTrusted)?;
        if revocations.is_revoked(&fingerprint) {
            return Err(TrustError::Revoked(fingerprint));
        }
        let mut matching_entry_outside_window = false;
        for entry in &self.entries {
            if entry.fingerprint == fingerprint
                && entry.key_blob == key_blob
                && entry.principals.iter().any(|p| p == principal)
                && entry.namespaces.iter().any(|n| n == namespace)
            {
                if !entry.is_valid_at(verify_time, offset)? {
                    matching_entry_outside_window = true;
                    continue;
                }
                return Ok(TrustedKey {
                    principal: principal.to_owned(),
                    fingerprint,
                    key_blob: key_blob.to_vec(),
                });
            }
        }
        if matching_entry_outside_window {
            Err(TrustError::OutsideValidity)
        } else {
            Err(TrustError::NotTrusted)
        }
    }
}

impl Revocations {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > MAX_FILE_SIZE {
            return Err(TrustError::FileTooLarge);
        }
        let mut fingerprints = HashSet::new();
        let mut count = 0usize;
        for (index, raw) in text.split('\n').enumerate() {
            let line_number = index + 1;
            let raw = raw.strip_suffix('\r').unwrap_or(raw);
            if raw.len() > MAX_LINE_LENGTH {
                return Err(TrustError::LineTooLong { line: line_number });
            }
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.chars().any(char::is_control) {
                return Err(TrustError::InvalidRevocation { line: line_number });
            }
            count += 1;
            if count > MAX_ENTRIES {
                return Err(TrustError::TooManyEntries);
            }
            let encoded = line
                .strip_prefix("SHA256:")
                .ok_or(TrustError::InvalidRevocation { line: line_number })?;
            let decoded = STANDARD_NO_PAD
                .decode(encoded)
                .map_err(|_| TrustError::InvalidRevocation { line: line_number })?;
            if decoded.len() != 32 || STANDARD_NO_PAD.encode(&decoded) != encoded {
                return Err(TrustError::InvalidRevocation { line: line_number });
            }
            fingerprints.insert(line.to_owned());
        }
        Ok(Self { fingerprints })
    }

    pub fn is_revoked(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }
}

/// Parse OpenSSH's YYYYMMDD[Z] or YYYYMMDDHHMM[SS][Z] syntax.
/// Missing `Z` is local civil time, matching ssh-keygen's default interpretation.
pub fn parse_verify_time(input: &str) -> Result<VerifyTime> {
    parse_timestamp(input, 0)
}

fn parse_timestamp(input: &str, line: usize) -> Result<VerifyTime> {
    let (digits, basis) = if let Some(value) = input.strip_suffix('Z') {
        (value, TimeBasis::Utc)
    } else {
        (input, TimeBasis::Local)
    };
    let invalid = || {
        if line == 0 {
            TrustError::InvalidCivilDateTime
        } else {
            TrustError::InvalidTimestamp {
                line,
                value: input.to_owned(),
            }
        }
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) || !matches!(digits.len(), 8 | 12 | 14) {
        return Err(invalid());
    }
    let number = |start: usize, end: usize| -> Result<u16> {
        digits[start..end].parse().map_err(|_| invalid())
    };
    let year = number(0, 4)?;
    let month = number(4, 6)? as u8;
    let day = number(6, 8)? as u8;
    let hour = if digits.len() >= 12 {
        number(8, 10)? as u8
    } else {
        0
    };
    let minute = if digits.len() >= 12 {
        number(10, 12)? as u8
    } else {
        0
    };
    let second = if digits.len() == 14 {
        number(12, 14)? as u8
    } else {
        0
    };
    let civil = CivilDateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
    };
    if !valid_civil(civil) {
        return Err(invalid());
    }
    Ok(VerifyTime { civil, basis })
}

fn parse_principals(input: &str, line: usize) -> Result<Vec<String>> {
    let principals: Vec<String> = input.split(',').map(str::to_owned).collect();
    if principals.is_empty() || principals.iter().any(|p| p.is_empty()) {
        return Err(malformed(line, "empty principal"));
    }
    if principals.iter().any(|p| p.contains(['*', '?', '!'])) {
        return Err(TrustError::UnsupportedPrincipalPattern { line });
    }
    Ok(principals)
}

fn parse_options(
    input: &str,
    line: usize,
) -> Result<(Vec<String>, Option<VerifyTime>, Option<VerifyTime>)> {
    let items = split_commas(input).map_err(|reason| malformed(line, reason))?;
    let mut namespaces = None;
    let mut after = None;
    let mut before = None;
    for item in items {
        if item.eq_ignore_ascii_case("cert-authority") {
            return Err(TrustError::CertificateAuthority { line });
        }
        let (key, raw_value) = item
            .split_once('=')
            .ok_or_else(|| TrustError::UnknownOption {
                line,
                option: item.clone(),
            })?;
        let key = key.to_ascii_lowercase();
        let value =
            unquote(raw_value).ok_or_else(|| malformed(line, "invalid quoted option value"))?;
        match key.as_str() {
            "namespaces" => {
                if namespaces.is_some() {
                    return Err(TrustError::DuplicateOption { line, option: key });
                }
                let values: Vec<String> = value.split(',').map(str::to_owned).collect();
                if values.is_empty()
                    || values
                        .iter()
                        .any(|v| v.is_empty() || v.contains(['*', '?', '!']))
                {
                    return Err(malformed(line, "unsupported namespace pattern"));
                }
                if !values.iter().any(|v| v == "git") {
                    return Err(TrustError::MissingGitNamespace { line });
                }
                namespaces = Some(values);
            }
            "valid-after" => {
                if after.is_some() {
                    return Err(TrustError::DuplicateOption { line, option: key });
                }
                after = Some(parse_timestamp(&value, line)?);
            }
            "valid-before" => {
                if before.is_some() {
                    return Err(TrustError::DuplicateOption { line, option: key });
                }
                before = Some(parse_timestamp(&value, line)?);
            }
            _ => return Err(TrustError::UnknownOption { line, option: key }),
        }
    }
    let namespaces = namespaces.ok_or(TrustError::MissingGitNamespace { line })?;
    Ok((namespaces, after, before))
}

fn split_words(line: &str) -> std::result::Result<Vec<String>, &'static str> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in line.chars() {
        if ch == '"' {
            quoted = !quoted;
            current.push(ch);
        } else if ch.is_whitespace() && !quoted {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
                if words.len() == 4 {
                    return Ok(words);
                }
            }
        } else if ch.is_control() {
            return Err("control character in line");
        } else {
            current.push(ch);
        }
    }
    if quoted {
        return Err("unterminated quote");
    }
    if !current.is_empty() {
        words.push(current);
    }
    Ok(words)
}

fn split_commas(input: &str) -> std::result::Result<Vec<String>, &'static str> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in input.chars() {
        if ch == '"' {
            quoted = !quoted;
            current.push(ch);
        } else if ch == ',' && !quoted {
            items.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if quoted {
        return Err("unterminated option quote");
    }
    items.push(current);
    if items.iter().any(|i| i.is_empty()) {
        return Err("empty option");
    }
    Ok(items)
}

fn unquote(value: &str) -> Option<String> {
    if let Some(inner) = value.strip_prefix('"') {
        let inner = inner.strip_suffix('"')?;
        if inner.contains('"') {
            return None;
        }
        Some(inner.to_owned())
    } else if value.contains('"') {
        None
    } else {
        Some(value.to_owned())
    }
}

fn malformed(line: usize, reason: impl Into<String>) -> TrustError {
    TrustError::MalformedLine {
        line,
        reason: reason.into(),
    }
}

fn looks_like_key_type(value: &str) -> bool {
    value.starts_with("ssh-")
        || value.starts_with("ecdsa-")
        || value.starts_with("sk-")
        || value.starts_with("rsa-")
}

#[allow(clippy::manual_is_multiple_of)] // Keep compatibility with the workspace MSRV.
fn valid_civil(t: CivilDateTime) -> bool {
    if t.year == 0 || !(1..=12).contains(&t.month) || t.hour > 23 || t.minute > 59 || t.second > 59
    {
        return false;
    }
    let leap = t.year % 4 == 0 && (t.year % 100 != 0 || t.year % 400 == 0);
    let days = match t.month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days).contains(&t.day)
}

fn compare_times(
    a: VerifyTime,
    b: VerifyTime,
    offset: Option<UtcOffset>,
) -> Result<std::cmp::Ordering> {
    if !valid_civil(a.civil) || !valid_civil(b.civil) {
        return Err(TrustError::InvalidCivilDateTime);
    }
    if a.basis == b.basis {
        return Ok(a.civil.cmp(&b.civil));
    }
    let offset = offset.ok_or(TrustError::MixedTimeBasis)?;
    UtcOffset::new(offset.minutes_east)?;
    let a_seconds = epoch_seconds(a.civil)?
        - if a.basis == TimeBasis::Local {
            i64::from(offset.minutes_east) * 60
        } else {
            0
        };
    let b_seconds = epoch_seconds(b.civil)?
        - if b.basis == TimeBasis::Local {
            i64::from(offset.minutes_east) * 60
        } else {
            0
        };
    Ok(a_seconds.cmp(&b_seconds))
}

fn epoch_seconds(t: CivilDateTime) -> Result<i64> {
    let mut year = i64::from(t.year);
    let month = i64::from(t.month);
    year -= i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * adjusted_month + 2) / 5 + i64::from(t.day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days.checked_mul(86400)
        .and_then(|v| {
            v.checked_add(i64::from(t.hour) * 3600 + i64::from(t.minute) * 60 + i64::from(t.second))
        })
        .ok_or(TrustError::InvalidCivilDateTime)
}

#[cfg(test)]
mod tests;
