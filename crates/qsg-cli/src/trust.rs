use base64::{Engine as _, engine::general_purpose::STANDARD};
use qsg_keystore::default_config_dir;
use qsg_trust::{Revocations, parse_allowed_signers, parse_verify_time};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::public_key;

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

pub fn run(args: &[String]) -> Result<(), String> {
    if args.len() == 2 && matches!(args[1].as_str(), "--help" | "-h") {
        let usage = match args[0].as_str() {
            "add" => {
                "qsg trust add <principal> <pubkey-file> [--allowed-signers <file>] [--valid-after <date>] [--valid-before <date>]"
            }
            "list" => "qsg trust list [--allowed-signers <file>]",
            "revoke" => "qsg trust revoke <fingerprint> [--revoked-keys <file>]",
            _ => return Err("usage: qsg trust <add|list|revoke> ...".into()),
        };
        println!("{usage}");
        return Ok(());
    }
    match args.first().map(String::as_str) {
        Some("add") => add(&args[1..]),
        Some("list") => list(&args[1..]),
        Some("revoke") => revoke(&args[1..]),
        Some("--help") | Some("-h") => {
            println!(
                "qsg trust add <principal> <pubkey-file> [--allowed-signers <file>] [--valid-after <date>] [--valid-before <date>]\nqsg trust list [--allowed-signers <file>]\nqsg trust revoke <fingerprint> [--revoked-keys <file>]"
            );
            Ok(())
        }
        _ => Err("usage: qsg trust <add|list|revoke> ...".into()),
    }
}

pub fn is_usage_error(message: &str) -> bool {
    [
        "usage:",
        "usage option:",
        "invalid principal:",
        "principal list contains",
        "unknown trust add option",
        "duplicate option",
        "missing value for",
        "fingerprint may not start",
        "invalid fingerprint:",
        "invalid validity date:",
        "invalid public key:",
        "public key ",
        "unknown or duplicate",
    ]
    .iter()
    .any(|prefix| message.starts_with(prefix))
}

fn add(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: qsg trust add <principal> <pubkey-file> [options]".into());
    }
    let principal = &args[0];
    validate_principals(principal)?;
    let pubkey = PathBuf::from(&args[1]);
    let mut allowed = None;
    let mut after = None;
    let mut before = None;
    let mut i = 2;
    while i < args.len() {
        let flag = args[i].as_str();
        if !matches!(
            flag,
            "--allowed-signers" | "--valid-after" | "--valid-before"
        ) {
            return Err(format!("unknown trust add option {flag}"));
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?
            .clone();
        let slot = match flag {
            "--allowed-signers" => &mut allowed,
            "--valid-after" => &mut after,
            _ => &mut before,
        };
        if slot.replace(value).is_some() {
            return Err(format!("duplicate option {flag}"));
        }
        i += 2;
    }
    let allowed = allowed.map(PathBuf::from).unwrap_or(default_allowed()?);
    if let Some(value) = &after {
        parse_verify_time(value).map_err(|e| format!("invalid validity date: {e}"))?;
    }
    if let Some(value) = &before {
        parse_verify_time(value).map_err(|e| format!("invalid validity date: {e}"))?;
    }
    ensure_config_dir(&allowed)?;
    let key = public_key::read_public(pubkey)?;
    let mut options = "namespaces=\"git\"".to_owned();
    if let Some(v) = after {
        options.push_str(&format!(",valid-after={v}"));
    }
    if let Some(v) = before {
        options.push_str(&format!(",valid-before={v}"));
    }
    let entry = format!(
        "{principal} {options} ssh-mldsa65@qsgit {}",
        STANDARD.encode(&key.blob)
    );
    let current = read_optional(&allowed)?;
    let parsed = parse_allowed_signers(
        std::str::from_utf8(&current).map_err(|_| "allowed_signers is not UTF-8")?,
    )
    .map_err(|e| e.to_string())?;
    if parsed.entries.iter().any(|e| {
        e.key_blob == key.blob
            && principal
                .split(',')
                .any(|p| e.principals.iter().any(|old| old == p))
    }) {
        return Err("duplicate principal and key already exists".into());
    }
    let candidate = append_line(&current, entry.as_bytes());
    parse_allowed_signers(
        std::str::from_utf8(&candidate).map_err(|_| "generated allowed_signers is not UTF-8")?,
    )
    .map_err(|e| e.to_string())?;
    atomic_write(&allowed, &candidate)?;
    println!("added {principal} {}", key.fingerprint);
    Ok(())
}

fn list(args: &[String]) -> Result<(), String> {
    let allowed =
        parse_single_path_option(args, "--allowed-signers")?.unwrap_or(default_allowed()?);
    let bytes = read_optional(&allowed)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "allowed_signers is not UTF-8")?;
    let parsed = parse_allowed_signers(text).map_err(|e| e.to_string())?;
    for entry in parsed.entries {
        println!(
            "{} {} valid-after={} valid-before={}",
            entry.principals.join(","),
            entry.fingerprint,
            entry
                .valid_after
                .map(format_time)
                .unwrap_or_else(|| "never".into()),
            entry
                .valid_before
                .map(format_time)
                .unwrap_or_else(|| "never".into())
        );
    }
    for entry in parsed.skipped {
        println!("skipped line {} key type {}", entry.line, entry.key_type);
    }
    Ok(())
}

fn revoke(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err("usage: qsg trust revoke <fingerprint> [--revoked-keys <file>]".into());
    }
    if args[0].starts_with('-') {
        return Err("fingerprint may not start with '-'".into());
    }
    let fp = &args[0];
    Revocations::parse(&format!("{fp}\n")).map_err(|e| format!("invalid fingerprint: {e}"))?;
    let explicit = parse_single_path_option(&args[1..], "--revoked-keys")?;
    let allowed = default_allowed()?;
    let path = explicit.unwrap_or_else(|| {
        allowed
            .parent()
            .unwrap_or(Path::new("."))
            .join("revoked_keys")
    });
    ensure_config_dir(&path)?;
    let current = read_optional(&path)?;
    let parsed = Revocations::parse(
        std::str::from_utf8(&current).map_err(|_| "revocation file is not UTF-8")?,
    )
    .map_err(|e| e.to_string())?;
    if parsed.is_revoked(fp) {
        return Err("fingerprint is already revoked".into());
    }
    let candidate = append_line(&current, fp.as_bytes());
    Revocations::parse(
        std::str::from_utf8(&candidate).map_err(|_| "generated revocation file is not UTF-8")?,
    )
    .map_err(|e| e.to_string())?;
    atomic_write(&path, &candidate)?;
    println!("revoked {fp}");
    println!(
        "Reminder: revocation invalidates ALL signatures by this key, including old signatures (v0.1 limitation)."
    );
    Ok(())
}

fn validate_principals(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '*' | '?' | '!' | '"'))
    {
        return Err("invalid principal: whitespace, wildcard, negation, and quote characters are not supported".into());
    }
    if value.split(',').any(str::is_empty) {
        return Err("principal list contains an empty item".into());
    }
    Ok(())
}

fn default_allowed() -> Result<PathBuf, String> {
    default_config_dir()
        .map(|dir| dir.join("allowed_signers"))
        .map_err(|e| e.to_string())
}

fn parse_single_path_option(args: &[String], flag: &str) -> Result<Option<PathBuf>, String> {
    if args.is_empty() {
        return Ok(None);
    }
    if args.len() != 2 || args[0] != flag {
        return Err(format!("usage option: {flag} <file>"));
    }
    Ok(Some(PathBuf::from(&args[1])))
}

fn read_optional(path: &Path) -> Result<Vec<u8>, String> {
    match fs::File::open(path) {
        Ok(file) => {
            use std::io::Read;
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| format!("could not read {}: {e}", path.display()))?;
            if bytes.len() > 1024 * 1024 {
                Err("trust file exceeds 1 MiB limit".into())
            } else {
                Ok(bytes)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("could not read {}: {e}", path.display())),
    }
}

fn ensure_config_dir(path: &Path) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let _existed = dir.exists();
    fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !_existed {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("could not secure {}: {e}", dir.display()))?;
        }
        let metadata =
            fs::metadata(dir).map_err(|e| format!("could not inspect {}: {e}", dir.display()))?;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(format!(
                "unsafe permissions on {}; run: chmod 700 '{}'",
                dir.display(),
                dir.display()
            ));
        }
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let _old_mode: Option<u32> = if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Some(
                fs::metadata(path)
                    .map_err(|e| e.to_string())?
                    .permissions()
                    .mode()
                    & 0o777,
            )
        }
        #[cfg(not(unix))]
        {
            None
        }
    } else {
        None
    };
    for _ in 0..32 {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".qsg-trust-{}-{id}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(_old_mode.unwrap_or(0o600));
        }
        let mut file = match options.open(&temp) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("could not create temporary file: {e}")),
        };
        let result = (|| {
            file.write_all(bytes)
                .map_err(|e| format!("could not write temporary file: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("could not sync temporary file: {e}"))?;
            drop(file);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &temp,
                    fs::Permissions::from_mode(_old_mode.unwrap_or(0o600)),
                )
                .map_err(|e| format!("could not preserve trust file permissions: {e}"))?;
            }
            fs::rename(&temp, path)
                .map_err(|e| format!("could not atomically replace {}: {e}", path.display()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        return result;
    }
    Err("could not allocate temporary trust file".into())
}

fn format_time(time: qsg_trust::VerifyTime) -> String {
    let c = time.civil;
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}{}",
        c.year,
        c.month,
        c.day,
        c.hour,
        c.minute,
        c.second,
        if time.basis == qsg_trust::TimeBasis::Utc {
            "Z"
        } else {
            ""
        }
    )
}

fn append_line(current: &[u8], line: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(current.len() + line.len() + 2);
    output.extend_from_slice(current);
    if !current.is_empty() && !current.ends_with(b"\n") {
        output.push(b'\n');
    }
    output.extend_from_slice(line);
    output.push(b'\n');
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_trust_text_editor_inputs_never_panic(text in any::<String>(), entry in any::<String>()) {
            let candidate = append_line(text.as_bytes(), entry.as_bytes());
            if let Ok(decoded) = std::str::from_utf8(&candidate) {
                let _ = parse_allowed_signers(decoded);
            }
        }
    }

    #[test]
    fn atomic_replace_preserves_existing_unix_mode_and_new_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowed_signers");
        fs::write(&path, b"# original\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        }
        atomic_write(&path, b"# original\n# retained\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"# original\n# retained\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o640
            );
            let private = dir.path().join("revoked_keys");
            atomic_write(
                &private,
                b"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            )
            .unwrap();
            assert_eq!(
                fs::metadata(private).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
