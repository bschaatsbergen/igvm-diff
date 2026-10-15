use std::{fs, path::PathBuf, process::Command};

use igvm_diff::{ChangeKind, diff};
use serde_json::Value;

fn fixtures() -> (PathBuf, Value) {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/openhcl");
    let manifest =
        serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap()).unwrap();
    (directory, manifest)
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn headers(bytes: &[u8]) -> Vec<(u32, usize)> {
    let mut offset = u32_at(bytes, 8) as usize;
    let end = offset + u32_at(bytes, 12) as usize;
    let mut headers = Vec::new();
    while offset < end {
        headers.push((u32_at(bytes, offset), offset + 8));
        offset = (offset + 8 + u32_at(bytes, offset + 4) as usize).next_multiple_of(8);
    }
    headers
}

fn checksum(bytes: &mut [u8]) {
    bytes[20..24].fill(0);
    let end = u32_at(bytes, 8) as usize + u32_at(bytes, 12) as usize;
    let checksum = crc32fast::hash(&bytes[..end]);
    bytes[20..24].copy_from_slice(&checksum.to_le_bytes());
}

#[test]
fn downloaded_openhcl_images_match_the_manifest_and_compare_identically() {
    let (directory, manifest) = fixtures();
    for entry in manifest["files"].as_array().unwrap() {
        let path = directory.join(entry["file"].as_str().unwrap());
        let bytes = fs::read(&path).unwrap();
        let report = diff(&bytes, &bytes).unwrap();
        assert!(!report.has_changes());
        assert!(report.findings.is_empty());
        assert!(report.diagnostics.is_empty());
        assert_eq!(
            serde_json::to_value(&report.inputs.before).unwrap(),
            serde_json::json!({
                "sha256": entry["sha256"], "size": entry["size"],
                "format_version": entry["format_version"], "record_count": entry["record_count"]
            })
        );
        let output = Command::new(env!("CARGO_BIN_EXE_igvm-diff"))
            .arg("diff")
            .arg(&path)
            .arg(&path)
            .args(["--format", "json"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            serde_json::to_value(&report).unwrap()
        );
    }
}

#[test]
fn a_changed_openhcl_payload_reports_every_aliased_page() {
    let (directory, manifest) = fixtures();
    for entry in manifest["files"].as_array().unwrap() {
        let before = fs::read(directory.join(entry["file"].as_str().unwrap())).unwrap();
        let pages: Vec<_> = headers(&before)
            .into_iter()
            .filter(|(typ, _)| *typ == 0x302)
            .map(|(_, body)| u32_at(&before, body + 12) as usize)
            .filter(|offset| *offset != 0)
            .collect();
        let position = pages[0] + 137;
        let expected = pages
            .iter()
            .filter(|&&offset| (offset..offset + 4096).contains(&position))
            .count();
        let mut after = before.clone();
        after[position] ^= 1;
        let report = diff(&before, &after).unwrap();
        assert_eq!(report.findings.len(), expected);
        assert!(report.diagnostics.is_empty());
        for change in report.findings {
            assert_eq!(change.kind, ChangeKind::Modified);
            assert_eq!(change.after.unwrap().kind, "page_data");
            assert_eq!(change.fields, ["payload_sha256"]);
        }
    }
}

#[test]
fn openhcl_configuration_and_endorsement_changes_are_localized() {
    let (directory, manifest) = fixtures();
    for entry in manifest["files"].as_array().unwrap() {
        let before = fs::read(directory.join(entry["file"].as_str().unwrap())).unwrap();
        for (typ, body) in headers(&before) {
            let (position, mask, kind, fields) = match typ {
                0x102 => (body + 7, 2, "relocatable_region", vec!["apply_rip_offset"]),
                0x103 => (body + 24, 0x10, "page_table_relocation", vec!["used_size"]),
                0x104 => (
                    u32_at(&before, body + 4) as usize,
                    1,
                    "corim_document",
                    vec!["payload_sha256"],
                ),
                0x304
                    if u32_at(&before, body + 8)
                        == if entry["artifact"] == "x64-openhcl-igvm" {
                            1
                        } else {
                            4
                        } =>
                {
                    let offset = u32_at(&before, body + 12) as usize;
                    let rip = (0..u32_at(&before, offset) as usize)
                        .map(|i| offset + 4 + 32 * i)
                        .find(|&reg| u32_at(&before, reg + 1) == 0x20010)
                        .unwrap();
                    (rip + 16, 1, "vp_context", vec!["payload_sha256", "rip"])
                }
                _ => continue,
            };
            let mut after = before.clone();
            if typ == 0x103 {
                // Reduce the used page-table size by one page.
                let used = u64::from_le_bytes(after[position..position + 8].try_into().unwrap());
                after[position..position + 8].copy_from_slice(&(used - 4096).to_le_bytes());
            } else {
                after[position] ^= mask;
            }
            checksum(&mut after);
            for (a, b) in [(&before, &after), (&after, &before)] {
                let report = diff(a, b).unwrap();
                assert_eq!(report.findings.len(), 1);
                let change = &report.findings[0];
                assert_eq!(change.kind, ChangeKind::Modified);
                assert_eq!(change.after.as_ref().unwrap().kind, kind);
                assert_eq!(change.fields, fields);
                assert!(!report.to_string().contains("Contents changed in"));
                assert!(report.diagnostics.is_empty());
                assert_eq!(report.measurement, "not_requested");
            }
        }
    }
}
