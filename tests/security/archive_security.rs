use std::io::{Cursor, Write};

use serde::Deserialize;
use siorb_executor::{ArchiveLimits, inspect_tar, inspect_zip};
use tar::{Builder, EntryType, Header};
use zip::write::SimpleFileOptions;

#[derive(Debug, Deserialize)]
struct ArchiveCase {
    path: String,
    kind: String,
    target: Option<String>,
    compressed_bytes: Option<u64>,
    expanded_bytes: Option<u64>,
    entries: Option<usize>,
    valid: bool,
    reason_code: Option<String>,
}

fn cases() -> Vec<ArchiveCase> {
    serde_json::from_str(include_str!("archive-paths.json")).expect("archive security fixture")
}

#[test]
fn archive_link_rows_are_rejected_by_the_tar_inspector() {
    let mut exercised = 0;
    for case in cases()
        .into_iter()
        .filter(|case| matches!(case.kind.as_str(), "symlink" | "hardlink"))
    {
        exercised += 1;
        assert!(!case.valid);
        let entry_type = if case.kind == "symlink" {
            EntryType::Symlink
        } else {
            EntryType::Link
        };
        let bytes = tar_link(
            &case.path,
            case.target.as_deref().unwrap_or("../../outside"),
            entry_type,
        );
        let error = inspect_tar(Cursor::new(bytes), &ArchiveLimits::default())
            .expect_err("archive link must be rejected");
        assert_eq!(Some(error.reason_code), case.reason_code, "{:?}", case.path);
    }
    assert_eq!(exercised, 2);
}

#[test]
fn archive_bomb_and_entry_count_rows_hit_real_zip_limits() {
    let rows = cases();
    let ratio = rows
        .iter()
        .find(|case| case.compressed_bytes.is_some() && case.expanded_bytes.is_some())
        .expect("compression-ratio fixture");
    assert!(!ratio.valid);
    assert!(ratio.expanded_bytes > ratio.compressed_bytes);
    let bytes = zip_bytes(&[(ratio.path.as_str(), vec![0_u8; 1024 * 1024])], true);
    let limits = ArchiveLimits {
        max_entries: 10,
        max_uncompressed_bytes: 2 * 1024 * 1024,
        max_single_file_bytes: 2 * 1024 * 1024,
        max_compression_ratio: 2,
    };
    let error = inspect_zip(Cursor::new(bytes), &limits)
        .expect_err("high-ratio ZIP member must be rejected");
    assert_eq!(Some(error.reason_code), ratio.reason_code);

    let entries = rows
        .iter()
        .find(|case| case.entries.is_some())
        .expect("entry-count fixture");
    assert!(!entries.valid);
    assert!(entries.entries.is_some_and(|count| count > 1));
    let bytes = zip_bytes(&[("one", Vec::new()), ("two", Vec::new())], false);
    let limits = ArchiveLimits {
        max_entries: 1,
        ..ArchiveLimits::default()
    };
    let error = inspect_zip(Cursor::new(bytes), &limits)
        .expect_err("ZIP with too many entries must be rejected");
    assert_eq!(Some(error.reason_code), entries.reason_code);
}

fn tar_link(path: &str, target: &str, entry_type: EntryType) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_size(0);
    header.set_mode(0o777);
    header
        .set_link_name(target)
        .expect("safe fixture link target");
    header.set_cksum();
    builder
        .append_data(&mut header, path, std::io::empty())
        .expect("build link fixture");
    builder.into_inner().expect("finish TAR fixture")
}

fn zip_bytes(entries: &[(&str, Vec<u8>)], compress: bool) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let method = if compress {
        zip::CompressionMethod::Deflated
    } else {
        zip::CompressionMethod::Stored
    };
    let options = SimpleFileOptions::default().compression_method(method);
    for (name, bytes) in entries {
        writer.start_file(*name, options).expect("start ZIP entry");
        writer.write_all(bytes).expect("write ZIP entry");
    }
    writer.finish().expect("finish ZIP fixture").into_inner()
}
