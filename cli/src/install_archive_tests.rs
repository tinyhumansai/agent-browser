use super::*;

#[test]
fn extract_zip_strips_chrome_root_and_preserves_regular_files_and_directories() {
    let temp = tempfile::tempdir().unwrap();
    let dest = temp.path().join("chrome");

    extract_zip(
        include_bytes!("testdata/installer-valid.zip").to_vec(),
        &dest,
    )
    .unwrap();

    assert!(dest.join("nested").is_dir());
    assert!(dest.join("empty").is_dir());
    assert_eq!(
        fs::read(dest.join("nested/chrome")).unwrap(),
        b"#!/bin/sh\necho chrome\n"
    );
    assert_eq!(
        fs::read_to_string(dest.join("nested/data.txt")).unwrap(),
        "deflated payload"
    );
}

#[cfg(unix)]
#[test]
fn extract_zip_preserves_executable_mode_and_clears_privileged_bits() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let dest = temp.path().join("chrome");

    extract_zip(
        include_bytes!("testdata/installer-valid.zip").to_vec(),
        &dest,
    )
    .unwrap();

    let executable = fs::metadata(dest.join("nested/chrome")).unwrap();
    assert_eq!(executable.permissions().mode() & 0o7777, 0o755);
    let privileged = fs::metadata(dest.join("nested/privileged")).unwrap();
    assert_eq!(privileged.permissions().mode() & 0o7777, 0o755);
}

#[test]
fn extract_zip_normalizes_parent_paths_without_escaping_destination() {
    let temp = tempfile::tempdir().unwrap();
    let dest = temp.path().join("chrome");
    let sentinel = temp.path().join("outside.txt");
    fs::write(&sentinel, b"sentinel").unwrap();

    extract_zip(
        include_bytes!("testdata/installer-unsafe-paths.zip").to_vec(),
        &dest,
    )
    .unwrap();

    assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
    assert_eq!(fs::read(dest.join("escape.txt")).unwrap(), b"inside");
}

#[test]
fn extract_zip_rejects_corrupt_crc_and_truncated_archive() {
    let temp = tempfile::tempdir().unwrap();

    let corrupt = extract_zip(
        include_bytes!("testdata/installer-corrupt-crc.zip").to_vec(),
        &temp.path().join("corrupt"),
    );
    assert!(corrupt.is_err());

    let truncated = extract_zip(
        include_bytes!("testdata/installer-truncated.zip").to_vec(),
        &temp.path().join("truncated"),
    );
    assert!(truncated.is_err());
}
