use qsg_sshsig::SshSignature;
use qsg_trust::{TimeBasis, UtcOffset, parse_verify_time};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use time::{OffsetDateTime, UtcOffset as TimeOffset};

const MAX_OBJECT: usize = 32 * 1024 * 1024;
const MAX_LIST: usize = 64 * 1024 * 1024;

pub enum Source {
    Commit(String),
    Tag(String),
    Files(PathBuf, PathBuf),
}

pub struct Verified {
    pub id: String,
    pub fingerprint: String,
}

pub fn verify_one(
    source: Source,
    allowed: &Path,
    revoked: Option<&Path>,
    namespace: &str,
    verify_time: Option<&str>,
) -> Result<Verified, String> {
    if namespace != "git" {
        return Err("only namespace git is supported".into());
    }
    match source {
        Source::Commit(rev) => {
            reject_option(&rev)?;
            let oid = resolve(&rev, "commit")?;
            let raw = git_limited(&["cat-file", "commit", &oid], MAX_OBJECT)?;
            let (record, payload) = extract_commit(
                &raw,
                &git_limited(&["rev-parse", "--show-object-format"], 128)?,
            )?;
            let time = match verify_time {
                Some(v) => v.to_owned(),
                None => object_time(&raw, b"committer ")?,
            };
            verify_record(&oid, &record, &payload, allowed, revoked, &time)
        }
        Source::Tag(tag) => {
            reject_option(&tag)?;
            let oid = resolve(&tag, "tag")?;
            let raw = git_limited(&["cat-file", "tag", &oid], MAX_OBJECT)?;
            let (record, payload) = extract_tag(&raw)?;
            let time = match verify_time {
                Some(v) => v.to_owned(),
                None => object_time(&raw, b"tagger ")?,
            };
            verify_record(&oid, &record, &payload, allowed, revoked, &time)
        }
        Source::Files(signature, message) => {
            let signature_bytes = read_file(&signature, 128 * 1024)?;
            let record = qsg_verify::decode_signature(&signature_bytes)?;
            let payload = read_file(&message, 16 * 1024 * 1024)?;
            let current;
            let time = match verify_time {
                Some(v) => v,
                None => {
                    current = now_time()?;
                    &current
                }
            };
            verify_record("file", &record, &payload, allowed, revoked, time)
        }
    }
}

fn verify_record(
    id: &str,
    record: &SshSignature,
    payload: &[u8],
    allowed: &Path,
    revoked: Option<&Path>,
    time: &str,
) -> Result<Verified, String> {
    let parsed = parse_verify_time(time).map_err(|e| format!("invalid verify-time: {e}"))?;
    let offset = match parsed.basis {
        TimeBasis::Local => local_offset(time)?,
        TimeBasis::Utc => None,
    };
    let trust = qsg_verify::read_allowed(allowed)?;
    let mut principals = qsg_verify::find_principals_record(&trust, record, parsed, offset)?;
    if principals.is_empty() {
        // Retain matching principals whose entries are outside their time
        // window so the shared trust check can report the expiry precisely.
        for entry in &trust.entries {
            if entry.key_blob == record.public_key && entry.namespaces.iter().any(|n| n == "git") {
                for principal in &entry.principals {
                    if !principals.contains(principal) {
                        principals.push(principal.clone());
                    }
                }
            }
        }
    }
    if principals.is_empty() {
        return Err("Could not verify signature.\nno trusted principal matched".into());
    }
    let mut last_error = "Could not verify signature.\nno trusted principal matched".to_owned();
    for principal in principals {
        match qsg_verify::verify_record_message(
            allowed,
            &principal,
            record,
            time,
            Cursor::new(payload),
            Ok(offset),
            revoked,
        ) {
            Ok(fingerprint) => {
                return Ok(Verified {
                    id: id.to_owned(),
                    fingerprint,
                });
            }
            Err(failure) => last_error = failure.message,
        }
    }
    Err(last_error)
}

fn local_offset(time: &str) -> Result<Option<UtcOffset>, String> {
    let parsed = parse_verify_time(time).map_err(|e| format!("invalid verify-time: {e}"))?;
    qsg_verify::system_local_offset(parsed)
}

fn now_time() -> Result<String, String> {
    let now = OffsetDateTime::now_utc();
    let offset =
        TimeOffset::local_offset_at(now).map_err(|_| "cannot determine machine UTC offset")?;
    let local = now.to_offset(offset);
    Ok(format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        local.year(),
        u8::from(local.month()),
        local.day(),
        local.hour(),
        local.minute(),
        local.second()
    ))
}

fn resolve(rev: &str, kind: &str) -> Result<String, String> {
    reject_option(rev)?;
    let expr = match kind {
        "commit" => format!("{rev}^{{commit}}"),
        _ => format!("{rev}^{{tag}}"),
    };
    let output = git_limited(&["rev-parse", "--verify", "--end-of-options", &expr], 1024)?;
    let oid = String::from_utf8(output)
        .map_err(|_| "git returned a non-UTF-8 object id")?
        .trim()
        .to_owned();
    if oid.is_empty() || !oid.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("could not resolve {kind} {rev}"));
    }
    Ok(oid)
}

fn reject_option(value: &str) -> Result<(), String> {
    if value.starts_with('-') {
        Err("revision, tag, and range arguments may not start with '-'".into())
    } else {
        Ok(())
    }
}

fn git_limited(args: &[&str], limit: usize) -> Result<Vec<u8>, String> {
    let mut child = Command::new("git")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not run git: {e}"))?;
    let mut output = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout
            .by_ref()
            .take(limit as u64 + 1)
            .read_to_end(&mut output)
            .map_err(|e| format!("could not read git output: {e}"))?;
    }
    let oversized = output.len() > limit;
    if oversized {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|e| format!("could not wait for git: {e}"))?;
    if oversized {
        return Err(format!("git output exceeds {limit} byte limit"));
    }
    if !status.success() {
        return Err(format!(
            "git {} failed ({status})",
            args.first().unwrap_or(&"command")
        ));
    }
    Ok(output)
}

fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read {}: {e}", path.display()))?;
    if bytes.len() > limit {
        return Err(format!("{} exceeds {limit} byte limit", path.display()));
    }
    Ok(bytes)
}

fn extract_commit(raw: &[u8], format: &[u8]) -> Result<(SshSignature, Vec<u8>), String> {
    // Git v2.55.0 commit.c:parse_buffer_signed_by_header selects the hash-indexed
    // `gpgsig`/`gpgsig-sha256` header; its source checks `in_signature &&
    // line[0] == ' '` for folds and, at `*line == '\n'`, dumps the remainder.
    // The signature fields are omitted from payload, but the blank line/message
    // are kept verbatim, so scan only through the header separator here.
    let sha256 = format.starts_with(b"sha256");
    let sig_key: &[u8] = if sha256 {
        b"gpgsig-sha256 "
    } else {
        b"gpgsig "
    };
    let split = raw
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or("commit has no header/message separator")?;
    let header = &raw[..split + 1];
    let message = &raw[split + 2..];
    let mut payload = Vec::with_capacity(raw.len());
    let mut signature = Vec::new();
    let mut skip_continuation = false;
    let mut collect_signature = false;
    for line in header.split_inclusive(|b| *b == b'\n') {
        if skip_continuation && line.first() == Some(&b' ') {
            if collect_signature {
                signature.extend_from_slice(&line[1..]);
            }
            continue;
        }
        skip_continuation = false;
        collect_signature = false;
        if line.starts_with(sig_key) {
            signature.extend_from_slice(&line[sig_key.len()..]);
            skip_continuation = true;
            collect_signature = true;
        } else if line.starts_with(b"gpgsig") {
            skip_continuation = true;
        } else {
            payload.extend_from_slice(line);
        }
    }
    payload.extend_from_slice(b"\n");
    payload.extend_from_slice(message);
    if signature.is_empty() {
        return Err("commit is unsigned (no Git signature header)".into());
    }
    let record = qsg_verify::decode_signature(&signature)?;
    Ok((record, payload))
}

fn extract_tag(raw: &[u8]) -> Result<(SshSignature, Vec<u8>), String> {
    // Git v2.55.0 gpg-interface.c:parse_signed_buffer assigns `match = len`
    // whenever `get_format_by_sig(buf + len)` matches, so the last marker wins.
    // parse_signature copies the prefix as payload then calls remove_signature;
    // remove_signature strips gpgsig headers/folds and preserves the tail.
    let index = locate_tag_signature(raw)?;
    let record = qsg_verify::decode_signature(&raw[index..])?;
    Ok((record, remove_tag_header_signatures(&raw[..index])))
}

fn locate_tag_signature(raw: &[u8]) -> Result<usize, String> {
    let marker = b"-----BEGIN SSH SIGNATURE-----";
    let mut found = None;
    let mut start = 0;
    while start < raw.len() {
        let end = raw[start..]
            .iter()
            .position(|b| *b == b'\n')
            .map(|n| start + n + 1)
            .unwrap_or(raw.len());
        if raw[start..end].starts_with(marker) {
            found = Some(start);
        }
        start = end;
    }
    found.ok_or_else(|| "annotated tag is unsigned (no SSH signature marker)".into())
}

fn remove_tag_header_signatures(prefix: &[u8]) -> Vec<u8> {
    // Git v2.55.0 gpg-interface.c:remove_signature removes gpgsig header fields
    // and their continuation lines; it stops treating lines as headers at the
    // first empty line, preserving message text containing "gpgsig".
    let Some(end) = prefix.windows(2).position(|w| w == b"\n\n") else {
        return prefix.to_vec();
    };
    let header_end = end + 1;
    let mut result = Vec::with_capacity(prefix.len());
    let mut skip = false;
    for line in prefix[..header_end].split_inclusive(|b| *b == b'\n') {
        if skip && line.first() == Some(&b' ') {
            continue;
        }
        skip = false;
        if line.starts_with(b"gpgsig ") || line.starts_with(b"gpgsig-sha256 ") {
            skip = true;
        } else {
            result.extend_from_slice(line);
        }
    }
    result.extend_from_slice(&prefix[header_end..]);
    result
}

fn object_time(raw: &[u8], key: &[u8]) -> Result<String, String> {
    let header_end = raw
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or("object has no header/message separator")?;
    let line = raw[..header_end]
        .split(|b| *b == b'\n')
        .find(|l| l.starts_with(key))
        .ok_or_else(|| {
            format!(
                "object is missing {} timestamp",
                String::from_utf8_lossy(key).trim()
            )
        })?;
    let text = std::str::from_utf8(line).map_err(|_| "object timestamp header is not UTF-8")?;
    let fields: Vec<_> = text.split_ascii_whitespace().collect();
    let epoch = fields
        .get(fields.len().saturating_sub(2))
        .ok_or("object timestamp is malformed")?
        .parse::<i64>()
        .map_err(|_| "object timestamp is malformed")?;
    let instant = OffsetDateTime::from_unix_timestamp(epoch)
        .map_err(|_| "object timestamp is out of range")?;
    let offset = TimeOffset::local_offset_at(instant)
        .map_err(|_| "cannot determine machine UTC offset for object timestamp")?;
    let local = instant.to_offset(offset);
    Ok(format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        local.year(),
        u8::from(local.month()),
        local.day(),
        local.hour(),
        local.minute(),
        local.second()
    ))
}

pub fn range_commits(range: &str) -> Result<(String, String, Vec<String>), String> {
    reject_option(range)?;
    let (base, head) = range
        .split_once("..")
        .ok_or("range must be <base>..<head>")?;
    if base.is_empty() || head.is_empty() || head.contains("..") {
        return Err("range must be <base>..<head>".into());
    }
    let base_oid =
        resolve(base, "commit").map_err(|e| format!("could not resolve base {base}: {e}"))?;
    let head_oid =
        resolve(head, "commit").map_err(|e| format!("could not resolve head {head}: {e}"))?;
    let expression = format!("{base_oid}..{head_oid}");
    let output = git_limited(&["rev-list", "--reverse", &expression], MAX_LIST)
        .map_err(|e| format!("could not enumerate {range}; the range may be unresolved, shallow, or missing objects: {e}"))?;
    let list = String::from_utf8(output).map_err(|_| "git returned non-UTF-8 commit ids")?;
    let commits = list.lines().map(str::to_owned).collect();
    Ok((base_oid, head_oid, commits))
}

pub fn run_range(
    range: &str,
    allowed: &Path,
    revoked: Option<&Path>,
    format: &str,
    trust_from_head: bool,
    fail_on_empty: bool,
) -> Result<(), String> {
    let (base, head, commits) = range_commits(range)?;
    if format != "text" && format != "json" {
        return Err("--format must be text or json".into());
    }
    if let Some(warning) = trust_file_warning(allowed, &base, &head)? {
        eprintln!("WARNING: {warning}");
        if !trust_from_head {
            return Err("allowed_signers differs from the base trust file; use a base-branch/pipeline file or pass --trust-file-from-head explicitly".into());
        }
    }
    if commits.is_empty() {
        if format == "json" {
            println!(
                "{{\"schema_version\":1,\"range\":{},\"commits\":[]}}",
                json_escape(range)
            );
        } else {
            println!("0 commits in range");
        }
        return if fail_on_empty {
            Err("range is empty (--fail-on-empty)".into())
        } else {
            Ok(())
        };
    }
    let mut results = Vec::with_capacity(commits.len());
    for oid in &commits {
        let result = verify_one(Source::Commit(oid.clone()), allowed, revoked, "git", None);
        results.push((oid.clone(), result.map(|v| v.fingerprint)));
    }
    if format == "json" {
        print!(
            "{{\"schema_version\":1,\"range\":{},\"commits\":[",
            json_escape(range)
        );
        for (i, (oid, result)) in results.iter().enumerate() {
            if i != 0 {
                print!(",");
            }
            match result {
                Ok(fp) => print!(
                    "{{\"commit\":{},\"status\":\"verified\",\"fingerprint\":{},\"reason\":null}}",
                    json_escape(oid),
                    json_escape(fp)
                ),
                Err(reason) => print!(
                    "{{\"commit\":{},\"status\":\"failed\",\"fingerprint\":null,\"reason\":{}}}",
                    json_escape(oid),
                    json_escape(reason)
                ),
            }
        }
        println!("]}}");
    } else {
        for (oid, result) in &results {
            match result {
                Ok(fp) => println!("{oid}: verified ({fp})"),
                Err(reason) => println!("{oid}: FAILED: {reason}"),
            }
        }
    }
    if results.iter().any(|(_, r)| r.is_err()) {
        Err("one or more commits failed verification".into())
    } else {
        Ok(())
    }
}

fn trust_file_warning(allowed: &Path, base: &str, head: &str) -> Result<Option<String>, String> {
    let root = match git_limited(&["rev-parse", "--show-toplevel"], 4096) {
        Ok(v) => PathBuf::from(
            String::from_utf8(v)
                .map_err(|_| "git returned non-UTF-8 repository path")?
                .trim(),
        ),
        Err(_) => return Ok(None),
    };
    let absolute = if allowed.is_absolute() {
        allowed.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(allowed)
    };
    let canonical_root = root.canonicalize().unwrap_or(root);
    let normalized_file = match (absolute.parent(), absolute.file_name()) {
        (Some(parent), Some(name)) => parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf())
            .join(name),
        _ => normalize_absolute(&absolute),
    };
    let Ok(relative) = normalized_file.strip_prefix(&canonical_root) else {
        return Ok(None);
    };
    let path = relative.to_string_lossy().replace('\\', "/");
    let base_blob = git_blob(base, &path)?;
    let head_blob = git_blob(head, &path)?;
    let actual = read_file(allowed, 1024 * 1024)?;
    match (base_blob, head_blob) {
        (Some(bytes), _) if bytes != actual => Ok(Some(format!(
            "trust file {} differs byte-for-byte from {base}:{path}",
            allowed.display()
        ))),
        (None, Some(_)) => Ok(Some(format!(
            "trust file {path} is tracked at range head but not at base {base}"
        ))),
        _ => Ok(None),
    }
}

fn normalize_absolute(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                output.pop();
            }
            other => output.push(other.as_os_str()),
        }
    }
    output
}

fn git_blob(rev: &str, path: &str) -> Result<Option<Vec<u8>>, String> {
    // ls-tree distinguishes a path absent from the tree from a tracked path
    // whose blob is unavailable (for example, in an incomplete object store).
    let tree_path = git_limited(&["ls-tree", "-r", "-z", rev, "--", path], 1024 * 1024)?;
    if tree_path.is_empty() {
        return Ok(None);
    }
    let expression = format!("{rev}:{path}");
    let mut child = Command::new("git")
        .args(["cat-file", "blob", &expression])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("could not run git: {e}"))?;
    let mut bytes = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        stdout
            .by_ref()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("could not read trust blob: {e}"))?;
    }
    let oversized = bytes.len() > 1024 * 1024;
    if oversized {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|e| format!("could not wait for git: {e}"))?;
    if oversized {
        return Err("tracked trust file exceeds 1 MiB limit".into());
    }
    if !status.success() {
        return Err(format!(
            "tracked trust blob {rev}:{path} is missing or unreadable"
        ));
    }
    Ok(Some(bytes))
}

fn json_escape(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
