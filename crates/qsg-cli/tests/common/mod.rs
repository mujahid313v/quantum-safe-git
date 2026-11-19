use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

static SHIM_PATH: OnceLock<Result<PathBuf, String>> = OnceLock::new();

/// Locate the Git shim regardless of Cargo's artifact directory layout.
pub fn shim_path() -> PathBuf {
    match SHIM_PATH.get_or_init(resolve_shim) {
        Ok(path) => path.clone(),
        Err(error) => panic!("{error}"),
    }
}

fn resolve_shim() -> Result<PathBuf, String> {
    let executable = if cfg!(windows) {
        "qsg-ssh-keygen.exe"
    } else {
        "qsg-ssh-keygen"
    };
    let current_exe = env::current_exe().ok();
    let cargo_bin_qsg = option_env!("CARGO_BIN_EXE_qsg")
        .map(PathBuf::from)
        .or_else(|| env::var_os("CARGO_BIN_EXE_qsg").map(PathBuf::from));
    let mut tried = Vec::new();

    if let Some(override_path) = env::var_os("QSG_SSH_KEYGEN_BIN") {
        let path = PathBuf::from(override_path);
        if let Some(found) = existing_candidate(path, &mut tried) {
            return Ok(found);
        }
    }

    if let Some(qsg) = cargo_bin_qsg.as_deref()
        && let Some(parent) = qsg.parent()
        && let Some(found) = existing_candidate(parent.join(executable), &mut tried)
    {
        return Ok(found);
    }

    let profile_candidate = current_exe
        .as_deref()
        .and_then(profile_dir_from_current_exe)
        .map(|profile| profile.join(executable));
    if let Some(path) = profile_candidate
        && let Some(found) = existing_candidate(path, &mut tried)
    {
        return Ok(found);
    }

    let build_output = build_shim();
    match build_output {
        Ok(path) => {
            let found = existing_candidate(path.clone(), &mut tried);
            found.ok_or_else(|| {
                diagnostic(
                    &tried,
                    cargo_bin_qsg.as_deref(),
                    current_exe.as_deref(),
                    &format!(
                        "cargo reported a shim executable that is not a file: {}",
                        path.display()
                    ),
                )
            })
        }
        Err(error) => Err(diagnostic(
            &tried,
            cargo_bin_qsg.as_deref(),
            current_exe.as_deref(),
            &error,
        )),
    }
}

fn existing_candidate(path: PathBuf, tried: &mut Vec<PathBuf>) -> Option<PathBuf> {
    tried.push(path.clone());
    path.is_file().then_some(path)
}

fn profile_dir_from_current_exe(executable: &Path) -> Option<PathBuf> {
    let deps = executable.parent()?;
    (deps.file_name()? == "deps").then(|| deps.parent().map(Path::to_path_buf))?
}

fn build_shim() -> Result<PathBuf, String> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| format!("cannot find workspace root from {}", manifest.display()))?;
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(&cargo);
    command
        .args(["build", "-p", "qsg-ssh-keygen", "--message-format=json"])
        .current_dir(workspace);
    if !cfg!(debug_assertions) {
        command.arg("--release");
    }
    let output = command.output().map_err(|error| {
        format!(
            "could not run {} build for qsg-ssh-keygen: {error}",
            PathBuf::from(&cargo).display()
        )
    })?;
    if !output.status.success() {
        return Err(format!(
            "cargo build -p qsg-ssh-keygen failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if json_string_field(line, "reason").as_deref() != Some("compiler-artifact")
            || json_string_field(line, "name").as_deref() != Some("qsg-ssh-keygen")
        {
            continue;
        }
        if let Some(executable) = json_string_field(line, "executable") {
            return Ok(PathBuf::from(executable));
        }
    }
    Err(format!(
        "cargo build succeeded but emitted no compiler-artifact executable for qsg-ssh-keygen\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    ))
}

fn json_string_field(input: &str, field: &str) -> Option<String> {
    let mut offset = 0;
    while let Some(relative) = input.get(offset..)?.find('"') {
        let start = offset + relative;
        let (key, after_key) = parse_json_string(input, start)?;
        let mut value_start = skip_json_whitespace(input, after_key);
        if input.as_bytes().get(value_start) != Some(&b':') {
            offset = after_key;
            continue;
        }
        value_start = skip_json_whitespace(input, value_start + 1);
        if key == field {
            return parse_json_string(input, value_start).map(|(value, _)| value);
        }
        if let Some((_, after_value)) = parse_json_string(input, value_start) {
            offset = after_value;
        } else {
            offset = value_start.saturating_add(1);
        }
    }
    None
}

fn skip_json_whitespace(input: &str, mut offset: usize) -> usize {
    while input
        .as_bytes()
        .get(offset)
        .is_some_and(u8::is_ascii_whitespace)
    {
        offset += 1;
    }
    offset
}

fn parse_json_string(input: &str, start: usize) -> Option<(String, usize)> {
    let bytes = input.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut result = String::new();
    let mut offset = start + 1;
    while offset < bytes.len() {
        match bytes[offset] {
            b'"' => return Some((result, offset + 1)),
            b'\\' => {
                offset += 1;
                match *bytes.get(offset)? {
                    b'"' => result.push('"'),
                    b'\\' => result.push('\\'),
                    b'/' => result.push('/'),
                    b'b' => result.push('\u{0008}'),
                    b'f' => result.push('\u{000c}'),
                    b'n' => result.push('\n'),
                    b'r' => result.push('\r'),
                    b't' => result.push('\t'),
                    b'u' => {
                        offset += 1;
                        let high = parse_hex_quad(bytes, offset)?;
                        offset += 4;
                        let scalar = if (0xd800..=0xdbff).contains(&high) {
                            if bytes.get(offset..offset + 2)? != b"\\u" {
                                return None;
                            }
                            let low = parse_hex_quad(bytes, offset + 2)?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return None;
                            }
                            offset += 6;
                            0x10000 + ((u32::from(high) - 0xd800) << 10) + (u32::from(low) - 0xdc00)
                        } else {
                            if (0xdc00..=0xdfff).contains(&high) {
                                return None;
                            }
                            u32::from(high)
                        };
                        result.push(char::from_u32(scalar)?);
                        continue;
                    }
                    _ => return None,
                }
                offset += 1;
            }
            byte if byte < 0x20 => return None,
            _ => {
                let character = input.get(offset..)?.chars().next()?;
                result.push(character);
                offset += character.len_utf8();
            }
        }
    }
    None
}

fn parse_hex_quad(bytes: &[u8], start: usize) -> Option<u16> {
    let digits = std::str::from_utf8(bytes.get(start..start + 4)?).ok()?;
    u16::from_str_radix(digits, 16).ok()
}

fn diagnostic(
    tried: &[PathBuf],
    cargo_bin_qsg: Option<&Path>,
    current_exe: Option<&Path>,
    reason: &str,
) -> String {
    let mut message = format!("could not resolve qsg-ssh-keygen: {reason}\npaths tried:");
    if tried.is_empty() {
        message.push_str("\n  (none)");
    } else {
        for path in tried {
            message.push_str(&format!("\n  {}", path.display()));
        }
    }
    message.push_str(&format!(
        "\nCARGO_BIN_EXE_qsg: {}\ncurrent_exe: {}",
        cargo_bin_qsg.map_or_else(|| "<unset>".to_owned(), |path| path.display().to_string()),
        current_exe.map_or_else(
            || "<unavailable>".to_owned(),
            |path| path.display().to_string()
        )
    ));
    message
}

#[test]
fn resolved_qsg_ssh_keygen_exists_and_is_a_file() {
    let path = shim_path();
    assert!(
        path.is_file(),
        "resolved shim path is not a file: {}",
        path.display()
    );
}
