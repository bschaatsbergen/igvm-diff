use std::{fs, path::PathBuf, process::Command};

use igvm_diff::{ChangeKind, diff};
use serde_json::Value;

const DIRECTORY: &str = "tests/fixtures/gce-svsm";

fn fixtures() -> Vec<(Value, Vec<u8>)> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DIRECTORY);
    let manifest: Value =
        serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap()).unwrap();
    manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let bytes = fs::read(directory.join(entry["file"].as_str().unwrap())).unwrap();
            (entry.clone(), bytes)
        })
        .collect()
}

fn bytes(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(DIRECTORY)
            .join(name),
    )
    .unwrap()
}

#[test]
fn gce_svsm_images_match_the_manifest_and_compare_identically() {
    for (entry, bytes) in fixtures() {
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
    }
}

#[test]
fn consecutive_gce_svsm_releases_differ_only_in_page_contents() {
    // Ordered by GCS object creation time; counts are modified page records.
    for (before, after, expected) in [
        ("gce-svsm-0932e060.igvm", "gce-svsm-f6b450ad.igvm", 1050),
        ("gce-svsm-f6b450ad.igvm", "gce-svsm-4586baca.igvm", 521),
        ("gce-svsm-4586baca.igvm", "gce-svsm-d5341027.igvm", 1057),
        ("gce-svsm-0932e060.igvm", "gce-svsm-d5341027.igvm", 379),
    ] {
        let (a, b) = (bytes(before), bytes(after));
        for report in [diff(&a, &b).unwrap(), diff(&b, &a).unwrap()] {
            assert!(report.has_changes());
            assert_eq!(report.findings.len(), expected, "{before} -> {after}");
            assert!(report.diagnostics.is_empty(), "{report:#}");
            assert_eq!(report.measurement, "not_requested");
            for change in &report.findings {
                assert_eq!(change.kind, ChangeKind::Modified);
                assert!(!change.order_changed);
                assert_eq!(change.before.as_ref().unwrap().kind, "page_data");
                assert_eq!(change.after.as_ref().unwrap().kind, "page_data");
                assert_eq!(change.fields, ["payload_sha256"]);
            }
        }
    }
}

#[test]
fn gce_svsm_cli_localizes_a_firmware_only_update() {
    let output = Command::new(env!("CARGO_BIN_EXE_igvm-diff"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "diff",
            "tests/fixtures/gce-svsm/gce-svsm-0932e060.igvm",
            "tests/fixtures/gce-svsm/gce-svsm-d5341027.igvm",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "Files differ: 379 record changes",
        "Contents changed in 379 memory pages (4 KiB each).",
        "No changes found to page addresses, page attributes or boot-setting records.",
        "Memory pages (4 KiB each): 379 modified",
        "0xffe05000..0xfff6b000: 358 pages, contents changed [sev-snp]",
        "0xfffcc000..0xfffe0000: 20 pages, contents changed [sev-snp]",
        "0xffe00000..0xffe01000: 1 page, contents changed [sev-snp]",
        "Launch measurement: not computed",
    ] {
        assert!(text.contains(expected), "missing: {expected}\n{text}");
    }
    assert!(!text.contains("tdx"));
    assert!(!text.contains("more ranges"));
}
