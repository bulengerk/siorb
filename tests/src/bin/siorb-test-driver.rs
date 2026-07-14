use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

const FAKE_BACKEND_FLAG: &str = "--fake-native-backend";

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new(FAKE_BACKEND_FLAG)) {
        let code = run_fake_backend(arguments).unwrap_or(74);
        std::process::exit(code);
    }
    std::process::exit(siorb_cli::main_entry());
}

fn run_fake_backend(mut arguments: impl Iterator<Item = OsString>) -> io::Result<i32> {
    let Some(root) = arguments.next().map(PathBuf::from) else {
        return Ok(64);
    };
    let Some(action) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return Ok(64);
    };
    let metadata = fs::symlink_metadata(&root)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Ok(64);
    }

    let log_path = root.join("fake-backend-invocations.log");
    if let Ok(metadata) = fs::symlink_metadata(&log_path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Ok(64);
        }
    }
    let mut log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    writeln!(log, "{action}")?;
    log.sync_all()?;

    let installed_marker = root.join("fake-native-package.installed");
    match action.as_str() {
        "install" => {
            let mut marker = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(installed_marker)?;
            marker.write_all(b"installed\n")?;
            marker.sync_all()?;
            Ok(0)
        }
        "query" => {
            let Ok(metadata) = fs::symlink_metadata(installed_marker) else {
                return Ok(1);
            };
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Ok(1);
            }
            let Some(output) = arguments.next().and_then(|value| value.into_string().ok()) else {
                return Ok(64);
            };
            io::stdout().write_all(output.as_bytes())?;
            Ok(0)
        }
        _ => Ok(64),
    }
}
