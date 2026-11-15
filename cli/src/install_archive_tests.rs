use super::*;
use std::io::Write;

#[cfg(unix)]
#[test]
fn extract_zip_clears_privileged_bits_and_preserves_executable_mode() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let dest = temp.path().join("chrome");

    let mut archive = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
    archive
        .start_file(
            "chrome-linux64/chrome",
            zip::write::SimpleFileOptions::default().external_attributes(0o100755 << 16),
        )
        .unwrap();
    archive.write_all(b"executable").unwrap();
    archive
        .start_file(
            "chrome-linux64/privileged",
            zip::write::SimpleFileOptions::default().external_attributes(0o104755 << 16),
        )
        .unwrap();
    archive.write_all(b"privileged").unwrap();
    archive
        .start_file(
            "chrome-linux64/group-privileged",
            zip::write::SimpleFileOptions::default().external_attributes(0o102755 << 16),
        )
        .unwrap();
    archive.write_all(b"group privileged").unwrap();
    let bytes = archive.finish().unwrap().into_inner();

    assert_eq!(
        zip_entry_unix_mode(&bytes, "chrome-linux64/chrome"),
        Some(0o100755)
    );
    assert_eq!(
        zip_entry_unix_mode(&bytes, "chrome-linux64/privileged"),
        Some(0o104755)
    );
    assert_eq!(
        zip_entry_unix_mode(&bytes, "chrome-linux64/group-privileged"),
        Some(0o102755)
    );

    extract_zip(bytes, &dest).unwrap();

    let executable = fs::metadata(dest.join("chrome")).unwrap();
    assert_eq!(executable.permissions().mode() & 0o7777, 0o755);
    let privileged = fs::metadata(dest.join("privileged")).unwrap();
    assert_eq!(privileged.permissions().mode() & 0o7777, 0o755);
    let group_privileged = fs::metadata(dest.join("group-privileged")).unwrap();
    assert_eq!(group_privileged.permissions().mode() & 0o7777, 0o755);
}

#[cfg(unix)]
fn zip_entry_unix_mode(bytes: &[u8], entry_name: &str) -> Option<u32> {
    const CENTRAL_DIRECTORY_HEADER: u32 = 0x0201_4b50;
    for offset in 0..bytes.len().saturating_sub(46) {
        if u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?)
            != CENTRAL_DIRECTORY_HEADER
        {
            continue;
        }
        let made_by = u16::from_le_bytes(bytes[offset + 4..offset + 6].try_into().ok()?);
        if made_by >> 8 != 3 {
            continue;
        }
        let name_len =
            u16::from_le_bytes(bytes[offset + 28..offset + 30].try_into().ok()?) as usize;
        let extra_len =
            u16::from_le_bytes(bytes[offset + 30..offset + 32].try_into().ok()?) as usize;
        let comment_len =
            u16::from_le_bytes(bytes[offset + 32..offset + 34].try_into().ok()?) as usize;
        let name_start = offset + 46;
        let name_end = name_start.checked_add(name_len)?;
        if bytes.get(name_start..name_end)? != entry_name.as_bytes() {
            continue;
        }
        let end = name_end.checked_add(extra_len)?.checked_add(comment_len)?;
        if end > bytes.len() {
            return None;
        }
        let attrs = u32::from_le_bytes(bytes[offset + 38..offset + 42].try_into().ok()?);
        return Some(attrs >> 16);
    }
    None
}
