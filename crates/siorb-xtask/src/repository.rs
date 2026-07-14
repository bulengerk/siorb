use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{CommandFactory, Parser};
use walkdir::WalkDir;

use crate::support::{atomic_write, capture, message, run};
use crate::{Result, Xtask};

const GENERATED_DOC: &str = "docs/generated/cli-reference.md";
const SESSION_HEADING: &str = "## Codex Work Sessions";
const SESSION_PLACEHOLDER: &str = "Not exposed by the current Codex surface";
const SESSION_FIELDS: [&str; 7] = [
    "Objective",
    "Work completed",
    "Key files changed",
    "Decisions",
    "Validation",
    "Known limitations or blockers",
    "Next starting point",
];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SessionTimestamp {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
}

#[derive(Clone, Copy, Debug)]
struct ReadmeLog<'a> {
    raw_entries: &'a str,
    entry_count: usize,
}

pub fn verify(root: &Path) -> Result<()> {
    println!("repository verification: {}", root.display());
    verify_required_files(root)?;
    verify_readme_contract(root)?;
    verify_scripts(root)?;
    test_schemas(root)?;
    verify_generated(root)?;
    generate_docs(root, true)?;
    verify_test_workspace(root)?;
    verify_fuzz_workspace(root)?;
    run(
        root,
        "scripts/release/test-packaging.sh",
        std::iter::empty::<&str>(),
    )?;
    println!("repository verification passed");
    Ok(())
}

fn verify_required_files(root: &Path) -> Result<()> {
    const REQUIRED: &[&str] = &[
        "AGENTS.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "FINAL_CHECKLIST.md",
        "LICENSE",
        "PLANS.md",
        "README.md",
        "SECURITY.md",
        "Cargo.lock",
        "Cargo.toml",
        "deny.toml",
        "release.toml",
        "rust-toolchain.toml",
        "schemas/README.md",
        "tests/Cargo.toml",
        "fuzz/Cargo.toml",
        "website/build.mjs",
        "website/validate.mjs",
        "catalog/validate.mjs",
        "catalog/build-index.mjs",
    ];
    let missing: Vec<_> = REQUIRED
        .iter()
        .filter(|relative| !root.join(relative).is_file())
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(message(format!(
            "required repository files are missing: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

pub fn test_schemas(root: &Path) -> Result<()> {
    run(root, "python3", ["tests/schema_contract.py"])?;
    let schemas: Vec<_> = WalkDir::new(root.join("schemas"))
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|value| value == "json")
        })
        .map(walkdir::DirEntry::into_path)
        .collect();
    if schemas.is_empty() {
        return Err(message("schemas/ contains no JSON schemas"));
    }
    for path in schemas {
        let bytes = fs::read(&path)
            .map_err(|error| message(format!("cannot read schema {}: {error}", path.display())))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| message(format!("invalid JSON schema {}: {error}", path.display())))?;
        if value
            .get("$id")
            .and_then(serde_json::Value::as_str)
            .is_none()
        {
            return Err(message(format!(
                "schema has no string $id: {}",
                path.display()
            )));
        }
    }
    println!("schema gate passed");
    Ok(())
}

pub fn test_catalog(root: &Path) -> Result<()> {
    run(root, "node", ["catalog/validate.mjs"])?;
    run(root, "node", ["catalog/build-index.mjs", "--check"])?;
    run(
        root,
        "node",
        ["catalog/fixtures/runtime-tuf/generate.mjs", "--check"],
    )?;
    run(root, "node", ["catalog/verify-fixtures.mjs"])?;
    run(root, "node", ["catalog/verify-runtime-fixtures.mjs"])?;
    run(root, "python3", ["tests/fixture_integrity.py"])?;
    run(
        root,
        "cargo",
        [
            "test",
            "--locked",
            "-p",
            "siorb-catalog",
            "-p",
            "siorb-update",
        ],
    )?;
    println!("catalog gate passed");
    Ok(())
}

pub fn generate_catalog(root: &Path) -> Result<()> {
    run(root, "node", ["catalog/validate.mjs"])?;
    run(root, "node", ["catalog/build-index.mjs"])?;
    run(root, "node", ["catalog/fixtures/runtime-tuf/generate.mjs"])?;
    run(root, "node", ["catalog/build-index.mjs", "--check"])?;
    build_site(root)?;
    println!("catalog indexes, update fixtures, and static website generated");
    Ok(())
}

pub fn build_site(root: &Path) -> Result<()> {
    run(root, "node", ["catalog/validate.mjs"])?;
    run(root, "node", ["website/build.mjs"])?;
    run(root, "node", ["website/build.mjs", "--check"])?;
    run(root, "node", ["website/validate.mjs"])?;
    println!("static website generated and validated");
    Ok(())
}

pub fn generate_docs(root: &Path, check: bool) -> Result<()> {
    let expected = render_cli_reference();
    let path = root.join(GENERATED_DOC);
    if check {
        let actual = fs::read_to_string(&path).map_err(|error| {
            message(format!(
                "generated CLI reference is missing (run `cargo xtask generate-docs`): {}: {error}",
                path.display()
            ))
        })?;
        if actual != expected {
            return Err(message(format!(
                "generated CLI reference is stale: {}; run `cargo xtask generate-docs`",
                path.display()
            )));
        }
        println!("generated CLI reference is current");
    } else {
        atomic_write(&path, expected.as_bytes())?;
        println!("generated {}", path.display());
    }
    Ok(())
}

pub fn test_docs(root: &Path) -> Result<()> {
    generate_docs(root, true)?;
    validate_markdown_links(root)?;
    validate_documented_commands(root)?;
    println!("documentation gate passed");
    Ok(())
}

fn verify_generated(root: &Path) -> Result<()> {
    run(root, "node", ["catalog/validate.mjs"])?;
    run(root, "node", ["catalog/build-index.mjs", "--check"])?;
    run(
        root,
        "node",
        ["catalog/fixtures/runtime-tuf/generate.mjs", "--check"],
    )?;
    run(root, "node", ["website/build.mjs", "--check"])?;
    run(root, "node", ["website/validate.mjs"])?;
    Ok(())
}

fn verify_scripts(root: &Path) -> Result<()> {
    run(root, "python3", ["scripts/check_action_pins.py"])?;
    run(root, "python3", ["scripts/check_secrets.py"])?;
    run(
        root,
        "python3",
        ["-m", "compileall", "-q", "scripts", "tests"],
    )?;

    let mut shell_scripts: Vec<PathBuf> = WalkDir::new(root.join("scripts"))
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .filter(|path| path.extension().is_some_and(|extension| extension == "sh"))
        .collect();
    shell_scripts.sort();
    if shell_scripts.is_empty() {
        return Err(message("scripts/ contains no shell scripts to validate"));
    }
    for script in shell_scripts {
        run(
            root,
            "bash",
            [OsString::from("-n"), script.into_os_string()],
        )?;
    }
    Ok(())
}

fn verify_test_workspace(root: &Path) -> Result<()> {
    run(
        root,
        "cargo",
        [
            "metadata",
            "--locked",
            "--manifest-path",
            "tests/Cargo.toml",
            "--format-version",
            "1",
            "--no-deps",
        ],
    )?;
    run(
        root,
        "cargo",
        [
            "check",
            "--locked",
            "--manifest-path",
            "tests/Cargo.toml",
            "--all-targets",
        ],
    )?;
    Ok(())
}

fn verify_fuzz_workspace(root: &Path) -> Result<()> {
    let fuzz_manifest = root.join("fuzz/Cargo.toml");
    let manifest = fs::read_to_string(&fuzz_manifest)
        .map_err(|error| message(format!("cannot read {}: {error}", fuzz_manifest.display())))?;
    let mut target_count = 0_usize;
    for line in manifest.lines() {
        let Some(raw_path) = line.trim().strip_prefix("path = \"") else {
            continue;
        };
        let Some(relative) = raw_path.strip_suffix('"') else {
            continue;
        };
        if !relative.starts_with("fuzz_targets/") {
            continue;
        }
        target_count += 1;
        let target = root.join("fuzz").join(relative);
        let source = fs::read_to_string(&target).map_err(|error| {
            message(format!(
                "cannot read fuzz target {}: {error}",
                target.display()
            ))
        })?;
        if !source.contains("fuzz_target!") || !source.contains("siorb_") {
            return Err(message(format!(
                "fuzz target must invoke a production Siorb parser and cannot be a no-op: {}",
                target.display()
            )));
        }
    }
    if target_count == 0 {
        return Err(message("fuzz/Cargo.toml declares no fuzz targets"));
    }
    run(
        root,
        "cargo",
        [
            "check",
            "--locked",
            "--manifest-path",
            "fuzz/Cargo.toml",
            "--all-targets",
        ],
    )?;
    println!("fuzz gate checked {target_count} production-parser targets");
    Ok(())
}

fn render_cli_reference() -> String {
    let mut output = String::from(
        "<!-- Generated by `cargo xtask generate-docs`; DO NOT EDIT. -->\n\n# Siorb CLI reference\n\nThis reference is generated from the compiled Clap command model. The canonical automation surface uses explicit subcommands.\n\n",
    );
    render_command(
        &siorb_cli::Cli::command(),
        &["siorb".to_owned()],
        &mut output,
    );
    let trimmed_len = output.trim_end().len();
    output.truncate(trimmed_len);
    output.push('\n');
    output
}

fn render_command(command: &clap::Command, path: &[String], output: &mut String) {
    let mut help_command = command.clone();
    help_command = help_command.bin_name(path.join(" "));
    let help = help_command
        .render_long_help()
        .to_string()
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n");
    output.push_str(&format!(
        "## `{}`\n\n```text\n{}\n```\n\n",
        path.join(" "),
        help.trim_end()
    ));
    let children: Vec<_> = command
        .get_subcommands()
        .filter(|child| !child.is_hide_set())
        .cloned()
        .collect();
    for child in children {
        let mut child_path = path.to_vec();
        child_path.push(child.get_name().to_owned());
        render_command(&child, &child_path, output);
    }
}

fn markdown_paths(root: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<_> = WalkDir::new(root)
        .max_depth(5)
        .into_iter()
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !matches!(name.as_ref(), ".git" | "target" | "dist" | "website/public")
        })
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
        .collect();
    paths.sort();
    paths
}

fn validate_markdown_links(root: &Path) -> Result<()> {
    let mut failures = Vec::new();
    let paths = markdown_paths(root);
    for path in &paths {
        let content = fs::read_to_string(path).map_err(|error| {
            message(format!("cannot read Markdown {}: {error}", path.display()))
        })?;
        for (line_number, line) in content.lines().enumerate() {
            let mut remaining = line;
            while let Some(start) = remaining.find("](") {
                let target_start = start + 2;
                let Some(end) = remaining[target_start..].find(')') else {
                    break;
                };
                let raw = remaining[target_start..target_start + end].trim();
                let raw = raw.trim_matches(['<', '>']);
                let target = raw.split_whitespace().next().unwrap_or_default();
                let target = target.split('#').next().unwrap_or_default();
                if !target.is_empty()
                    && !target.starts_with('#')
                    && !target.contains("://")
                    && !target.starts_with("mailto:")
                {
                    let base = path.parent().unwrap_or(root);
                    if !base.join(target).exists() {
                        failures.push(format!(
                            "{}:{}: missing local link `{raw}`",
                            path.strip_prefix(root).unwrap_or(path).display(),
                            line_number + 1
                        ));
                    }
                }
                remaining = &remaining[target_start + end + 1..];
            }
        }
    }
    if !failures.is_empty() {
        return Err(message(format!(
            "documentation link validation failed:\n{}",
            failures.join("\n")
        )));
    }
    println!("validated local links in {} Markdown files", paths.len());
    Ok(())
}

fn validate_documented_commands(root: &Path) -> Result<()> {
    let mut checked = 0_usize;
    let mut failures = Vec::new();
    for path in markdown_paths(root) {
        let content = fs::read_to_string(&path).map_err(|error| {
            message(format!("cannot read Markdown {}: {error}", path.display()))
        })?;
        for (line_number, line) in content.lines().enumerate() {
            let line = line.trim().strip_prefix("$ ").unwrap_or(line.trim());
            let kind = if line == "siorb" || line.starts_with("siorb ") {
                Some("siorb")
            } else if line == "cargo xtask" || line.starts_with("cargo xtask ") {
                Some("xtask")
            } else {
                None
            };
            let Some(kind) = kind else { continue };
            let tokens = match shell_words(line) {
                Ok(tokens) => tokens,
                Err(error) => {
                    failures.push(format!(
                        "{}:{}: {error}",
                        path.strip_prefix(root).unwrap_or(&path).display(),
                        line_number + 1
                    ));
                    continue;
                }
            };
            checked += 1;
            let parse_result = if kind == "siorb" {
                siorb_cli::Cli::try_parse_from(tokens).map(|_| ())
            } else {
                let arguments =
                    std::iter::once("xtask".to_owned()).chain(tokens.into_iter().skip(2));
                Xtask::try_parse_from(arguments).map(|_| ())
            };
            if let Err(error) = parse_result {
                failures.push(format!(
                    "{}:{}: documented command does not parse: {}",
                    path.strip_prefix(root).unwrap_or(&path).display(),
                    line_number + 1,
                    error.render().ansi().to_string().trim()
                ));
            }
        }
    }
    if checked == 0 {
        return Err(message("documentation contains no command examples"));
    }
    if !failures.is_empty() {
        return Err(message(format!(
            "documentation command validation failed:\n{}",
            failures.join("\n")
        )));
    }
    println!("validated {checked} documented command lines against compiled parsers");
    Ok(())
}

fn shell_words(line: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match (quote, character) {
            (_, '\\') => escaped = true,
            (Some(expected), value) if value == expected => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, value) if value.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if escaped || quote.is_some() {
        return Err(message(format!("unclosed quote or escape in `{line}`")));
    }
    if !current.is_empty() {
        words.push(current);
    }
    Ok(words)
}

fn verify_readme_contract(root: &Path) -> Result<()> {
    let path = root.join("README.md");
    let current = fs::read_to_string(&path)
        .map_err(|error| message(format!("cannot read {}: {error}", path.display())))?;
    let current_log = parse_readme_log(&current)?;
    let base_ref = readme_base_ref();
    let base = git_show_readme(root, &base_ref)?;
    let base_log = base.as_deref().and_then(extract_log_without_validation);

    if let Some(base_log) = base_log {
        if !current_log.raw_entries.starts_with(base_log.raw_entries) {
            return Err(message(format!(
                "README Codex log is not append-only: entries from `{base_ref}` must remain an unchanged prefix"
            )));
        }
    }

    let baseline_count = base_log.map_or(0, |log| log.entry_count);
    if repository_changed(root, &base_ref)? && current_log.entry_count <= baseline_count {
        return Err(message(format!(
            "project changes require one new README Codex session entry; append the exact seven-field entry after `{SESSION_HEADING}` before rerunning `cargo xtask verify`"
        )));
    }
    println!(
        "README Codex log valid: {} entries, {} unchanged base entries",
        current_log.entry_count, baseline_count
    );
    Ok(())
}

fn parse_readme_log(content: &str) -> Result<ReadmeLog<'_>> {
    let occurrences: Vec<_> = content.match_indices(SESSION_HEADING).collect();
    if occurrences.len() != 1 {
        return Err(message(format!(
            "README must contain `{SESSION_HEADING}` exactly once; found {}",
            occurrences.len()
        )));
    }
    let (offset, _) = occurrences[0];
    if offset > 0 && content.as_bytes().get(offset - 1) != Some(&b'\n') {
        return Err(message(format!(
            "`{SESSION_HEADING}` must occupy its own Markdown heading line"
        )));
    }
    let before = &content[..offset];
    if before.trim().is_empty() {
        return Err(message(
            "README must contain project documentation before its session log",
        ));
    }
    let heading_end = offset + SESSION_HEADING.len();
    let after = content.get(heading_end..).unwrap_or_default();
    if !after.is_empty() && !after.starts_with('\n') {
        return Err(message(format!(
            "`{SESSION_HEADING}` must be an exact heading with no trailing text"
        )));
    }
    if after.lines().any(|line| line.starts_with("## ")) {
        return Err(message(
            "README Codex session log must be the physically final level-two section",
        ));
    }
    let normalized = after.strip_prefix('\n').unwrap_or(after);
    let raw_entries = normalized;
    let mut lines = normalized.lines().peekable();
    while lines.peek().is_some_and(|line| line.trim().is_empty()) {
        lines.next();
    }
    let mut previous: Option<SessionTimestamp> = None;
    let mut entry_count = 0_usize;
    while let Some(heading) = lines.next() {
        if heading.trim().is_empty() {
            continue;
        }
        let timestamp = parse_session_heading(heading)?;
        if previous.as_ref().is_some_and(|value| timestamp < *value) {
            return Err(message(format!(
                "README session timestamp is earlier than its predecessor: `{heading}`"
            )));
        }
        previous = Some(timestamp);
        if lines.next().is_none_or(|line| !line.trim().is_empty()) {
            return Err(message(format!(
                "README session `{heading}` must have one blank line before its fields"
            )));
        }
        for field in SESSION_FIELDS {
            let expected = format!("- **{field}:** ");
            let Some(line) = lines.next() else {
                return Err(message(format!(
                    "README session `{heading}` is missing `{field}`"
                )));
            };
            let Some(value) = line.strip_prefix(&expected) else {
                return Err(message(format!(
                    "README session `{heading}` expected field `{expected}<value>`, observed `{line}`"
                )));
            };
            if value.trim().is_empty() {
                return Err(message(format!(
                    "README session `{heading}` has an empty `{field}` value"
                )));
            }
        }
        entry_count += 1;
        if lines.peek().is_some_and(|line| !line.trim().is_empty()) {
            return Err(message(format!(
                "README session `{heading}` contains content outside the exact seven fields"
            )));
        }
        while lines.peek().is_some_and(|line| line.trim().is_empty()) {
            lines.next();
        }
    }
    Ok(ReadmeLog {
        raw_entries,
        entry_count,
    })
}

fn parse_session_heading(heading: &str) -> Result<SessionTimestamp> {
    let Some(value) = heading.strip_prefix("### ") else {
        return Err(message(format!(
            "content after `{SESSION_HEADING}` must start with a level-three session heading, observed `{heading}`"
        )));
    };
    let Some((timestamp, session_id)) = value.split_once(" — ") else {
        return Err(message(format!(
            "session heading must use `### YYYY-MM-DD HH:MM UTC — <session id>`, observed `{heading}`"
        )));
    };
    if session_id.trim().is_empty()
        || (session_id.to_ascii_lowercase().contains("not exposed")
            && session_id != SESSION_PLACEHOLDER)
    {
        return Err(message(format!(
            "session ID is empty or uses an inexact placeholder in `{heading}`"
        )));
    }
    let Some(timestamp) = timestamp.strip_suffix(" UTC") else {
        return Err(message(format!(
            "session timestamp is not UTC in `{heading}`"
        )));
    };
    if timestamp.len() != 16 || !timestamp.is_ascii() {
        return Err(message(format!(
            "session timestamp must be `YYYY-MM-DD HH:MM` in `{heading}`"
        )));
    }
    let bytes = timestamp.as_bytes();
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b' ')
        || bytes.get(13) != Some(&b':')
    {
        return Err(message(format!("invalid session timestamp in `{heading}`")));
    }
    let number = |range: std::ops::Range<usize>| -> Result<u32> {
        timestamp[range]
            .parse::<u32>()
            .map_err(|error| message(format!("invalid session timestamp in `{heading}`: {error}")))
    };
    let value = SessionTimestamp {
        year: number(0..4)?,
        month: number(5..7)?,
        day: number(8..10)?,
        hour: number(11..13)?,
        minute: number(14..16)?,
    };
    let maximum_day = days_in_month(value.year, value.month)
        .ok_or_else(|| message(format!("invalid session month in `{heading}`")))?;
    if value.day == 0 || value.day > maximum_day || value.hour > 23 || value.minute > 59 {
        return Err(message(format!(
            "invalid session date or time in `{heading}`"
        )));
    }
    Ok(value)
}

const fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

fn extract_log_without_validation(content: &str) -> Option<ReadmeLog<'_>> {
    let offset = content.find(SESSION_HEADING)?;
    let heading_end = offset + SESSION_HEADING.len();
    let after = content
        .get(heading_end..)?
        .strip_prefix('\n')
        .unwrap_or_default();
    Some(ReadmeLog {
        raw_entries: after,
        entry_count: after
            .lines()
            .filter(|line| line.starts_with("### "))
            .count(),
    })
}

fn readme_base_ref() -> String {
    if let Ok(value) = std::env::var("SIORB_README_BASE_REF") {
        return value;
    }
    std::env::var("GITHUB_BASE_REF")
        .ok()
        .filter(|value| !value.is_empty())
        .map_or_else(|| "HEAD".to_owned(), |value| format!("origin/{value}"))
}

fn git_show_readme(root: &Path, reference: &str) -> Result<Option<String>> {
    let specification = format!("{reference}:README.md");
    let output = Command::new("git")
        .args(["show", &specification])
        .current_dir(root)
        .output()
        .map_err(|error| message(format!("cannot inspect README at `{reference}`: {error}")))?;
    if output.status.success() {
        return String::from_utf8(output.stdout)
            .map(Some)
            .map_err(|error| message(format!("README at `{reference}` is not UTF-8: {error}")));
    }
    if reference == "HEAD" {
        return Ok(None);
    }
    Err(message(format!(
        "cannot inspect target-branch README at `{reference}`: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

fn repository_changed(root: &Path, base_ref: &str) -> Result<bool> {
    if base_ref != "HEAD" {
        let range = format!("{base_ref}...HEAD");
        let status = Command::new("git")
            .args(["diff", "--quiet", &range, "--", "."])
            .current_dir(root)
            .status()
            .map_err(|error| message(format!("cannot compare project changes: {error}")))?;
        return match status.code() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(message(format!(
                "git diff failed while comparing `{range}`"
            ))),
        };
    }
    let output = capture(
        root,
        Path::new("git"),
        ["status", "--porcelain", "--untracked-files=all"],
    )?;
    Ok(!output.stdout.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_log() -> String {
        format!(
            "# Siorb\n\n{SESSION_HEADING}\n\n### 2026-07-13 12:34 UTC — {SESSION_PLACEHOLDER}\n\n- **Objective:** Test the contract\n- **Work completed:** Added validation\n- **Key files changed:** README.md\n- **Decisions:** Strict structure\n- **Validation:** cargo test passed\n- **Known limitations or blockers:** None known\n- **Next starting point:** Continue\n"
        )
    }

    #[test]
    fn accepts_exact_session_shape() -> Result<()> {
        let value = valid_log();
        let parsed = parse_readme_log(&value)?;
        assert_eq!(parsed.entry_count, 1);
        Ok(())
    }

    #[test]
    fn rejects_content_after_fields() {
        let value = format!("{}unexpected\n", valid_log());
        assert!(parse_readme_log(&value).is_err());
    }

    #[test]
    fn rejects_non_monotonic_timestamps() {
        let first = valid_log();
        let value = format!(
            "{}\n### 2026-07-13 12:33 UTC — {SESSION_PLACEHOLDER}\n\n- **Objective:** Test\n- **Work completed:** Test\n- **Key files changed:** None\n- **Decisions:** None\n- **Validation:** None\n- **Known limitations or blockers:** None\n- **Next starting point:** Test\n",
            first.trim_end()
        );
        assert!(parse_readme_log(&value).is_err());
    }

    #[test]
    fn tokenizer_preserves_quoted_values() -> Result<()> {
        assert_eq!(
            shell_words("siorb info 'visual studio code'")?,
            ["siorb", "info", "visual studio code"]
        );
        Ok(())
    }
}
