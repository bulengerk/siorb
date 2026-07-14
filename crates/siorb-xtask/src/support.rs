use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{DynError, Result};

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn repository_root() -> Result<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("../..")
        .canonicalize()
        .map_err(|error| message(format!("cannot locate repository root: {error}")))
}

pub fn message(value: impl Into<String>) -> DynError {
    io::Error::other(value.into()).into()
}

pub fn command_label(program: &OsStr, arguments: &[OsString]) -> String {
    std::iter::once(program.to_string_lossy().into_owned())
        .chain(
            arguments
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned()),
        )
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn run<I, S>(root: &Path, program: &str, arguments: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let arguments: Vec<OsString> = arguments
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect();
    let label = command_label(OsStr::new(program), &arguments);
    println!("+ {label}");
    let status = Command::new(program)
        .args(&arguments)
        .current_dir(root)
        .status()
        .map_err(|error| message(format!("cannot run `{label}`: {error}")))?;
    if !status.success() {
        return Err(message(format!(
            "`{label}` failed with {}",
            status
                .code()
                .map_or_else(|| "a signal".to_owned(), |code| format!("exit code {code}"))
        )));
    }
    Ok(())
}

pub fn capture<I, S>(root: &Path, program: &Path, arguments: I) -> Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let arguments: Vec<OsString> = arguments
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect();
    let label = command_label(program.as_os_str(), &arguments);
    let output = Command::new(program)
        .args(&arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| message(format!("cannot run `{label}`: {error}")))?;
    if !output.status.success() {
        return Err(message(format!(
            "`{label}` failed with {}\nstdout:\n{}\nstderr:\n{}",
            output
                .status
                .code()
                .map_or_else(|| "a signal".to_owned(), |code| format!("exit code {code}")),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output)
}

pub fn target_directory(root: &Path) -> Result<PathBuf> {
    let output = capture(
        root,
        Path::new("cargo"),
        ["metadata", "--locked", "--format-version", "1", "--no-deps"],
    )?;
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| message(format!("cargo metadata returned invalid JSON: {error}")))?;
    metadata["target_directory"]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| message("cargo metadata omitted target_directory"))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| message(format!("cannot hash {}: {error}", path.display())))
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        message(format!(
            "output has no parent directory: {}",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        message(format!(
            "cannot create output directory {}: {error}",
            parent.display()
        ))
    })?;
    if path.is_symlink() {
        return Err(message(format!(
            "refusing to replace symlink {}",
            path.display()
        )));
    }
    let sequence = TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.tmp-{}-{sequence}",
        path.file_name()
            .and_then(OsStr::to_str)
            .unwrap_or("siorb-output"),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| {
            message(format!(
                "cannot create temporary output {}: {error}",
                temporary.display()
            ))
        })?;
    let result = (|| -> io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        // Windows rename does not replace an existing file. The temporary file is
        // already complete and durable before the old generated output is removed.
        #[cfg(windows)]
        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|error| message(format!("cannot write {}: {error}", path.display())))
}

pub fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| message(format!("cannot encode {}: {error}", path.display())))?;
    bytes.push(b'\n');
    atomic_write(path, &bytes)?;
    Ok(bytes)
}

pub fn prepare_empty_directory(path: &Path) -> Result<()> {
    if path.is_symlink() {
        return Err(message(format!(
            "output directory cannot be a symlink: {}",
            path.display()
        )));
    }
    if path.exists() {
        let mut entries = fs::read_dir(path).map_err(|error| {
            message(format!(
                "cannot inspect output directory {}: {error}",
                path.display()
            ))
        })?;
        if entries.next().transpose()?.is_some() {
            return Err(message(format!(
                "output directory is not empty: {}; choose a new path",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path).map_err(|error| {
            message(format!(
                "cannot create output directory {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

pub fn copy_regular_file(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| message(format!("cannot inspect {}: {error}", source.display())))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(message(format!(
            "input must be a regular non-symlink file: {}",
            source.display()
        )));
    }
    let bytes = fs::read(source)
        .map_err(|error| message(format!("cannot read {}: {error}", source.display())))?;
    atomic_write(destination, &bytes)
}

pub fn source_epoch() -> Result<u64> {
    match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value.parse::<u64>().map_err(|error| {
            message(format!(
                "SOURCE_DATE_EPOCH must be a non-negative integer: {error}"
            ))
        }),
        Err(std::env::VarError::NotPresent) => Ok(0),
        Err(error) => Err(message(format!("cannot read SOURCE_DATE_EPOCH: {error}"))),
    }
}

pub fn host_target(root: &Path) -> Result<String> {
    let output = capture(root, Path::new("rustc"), ["-vV"])?;
    String::from_utf8(output.stdout)
        .map_err(|error| message(format!("rustc emitted non-UTF-8 output: {error}")))?
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| message("rustc -vV did not report a host target"))
}

#[cfg(windows)]
pub fn executable_name(name: &str) -> String {
    format!("{name}.exe")
}

#[cfg(not(windows))]
pub fn executable_name(name: &str) -> String {
    name.to_owned()
}
