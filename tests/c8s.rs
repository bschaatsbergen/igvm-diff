//! Release-to-release comparison of two published confidential-dot-ai (c8s) SEV-SNP images.
//! The files are too large to commit; set IGVM_DIFF_C8S_DIR to run (see the fixture manifest).

use std::{fs, path::PathBuf};

use igvm_diff::diff_platform;
use serde_json::Value;

#[test]
fn c8s_release_update_is_localized_to_the_kernel_command_line() {
    let Some(directory) = std::env::var_os("IGVM_DIFF_C8S_DIR").map(PathBuf::from) else {
        eprintln!("skipped: IGVM_DIFF_C8S_DIR is not set");
        return;
    };
    let manifest: Value = serde_json::from_slice(
        &fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/c8s/manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let files = manifest["files"].as_array().unwrap();
    let read = |entry: &Value| fs::read(directory.join(entry["file"].as_str().unwrap())).unwrap();
    let (before, after) = (read(&files[0]), read(&files[1]));
    let report = diff_platform(&before, &after, Some("sev-snp")).unwrap();
    assert_eq!(
        report.inputs.before.sha256,
        files[0]["sha256"].as_str().unwrap()
    );
    assert_eq!(
        report.inputs.after.sha256,
        files[1]["sha256"].as_str().unwrap()
    );
    // One measured page changed: the UKI's .cmdline, where only the dm-verity root hash moved.
    assert_eq!(report.findings.len(), 1);
    let component = &report.content.components[0];
    assert_eq!(
        component.changed_sections.as_deref(),
        Some(&[".cmdline".to_string()][..])
    );
    let change = &component.text_changes[0];
    assert_eq!(change.removed.len(), 1);
    assert!(change.removed[0].starts_with("roothash="));
    assert!(change.added[0].starts_with("roothash="));
    let text = report.to_string();
    assert!(
        text.contains("SEV-SNP values measure the file's VMSAs (2) as stored. QEMU/KVM does not"),
        "{text}"
    );
}
