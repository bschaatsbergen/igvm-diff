use std::{fs, path::PathBuf, process::Command};

use igvm_diff::{ChangeKind, Format, ModuleChangeKind, diff};
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
            assert_eq!(report.measurement, "computed");
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
        "Platforms: sev-snp, tdx. To review only the one you run, add --platform sev-snp.",
        "  Launch measurement changes [sev-snp]; unchanged [tdx] (from the computed digests below).\n  Measured page data changed: 379 pages [sev-snp].\n",
        "Changed pages (4 KiB): 379 modified",
        "  0xffe00000..0xfffac000: UEFI firmware volume [sev-snp], 359 pages\n",
        "  0xfffcc000..0x100000000: UEFI firmware volume [sev-snp], 20 pages\n",
        "  SEC (1): SecMain\n",
        "  sev-snp launch digest, igvmmeasure --native-zero (zero-filled pages as ZERO pages):\n    before: 0932e060edc03a9ce09630566d281b8c4cf54cceb445bd2f203f2182e15001dc7a5c7e9001d5e0e248f952c047d5175a\n    after:  d5341027d9eb3cfd8d4735d09b08830115199fed476acd7e1f3f9225e7d59f9c4ec1ae7bc1a3d2cf604a0b38a461ca72\n",
    ] {
        assert!(text.contains(expected), "missing: {expected}\n{text}");
    }
    // The file also defines a TDX platform, but no TDX page changed.
    assert!(
        !text.contains("pages [tdx]") && !text.contains("sev-snp, tdx]"),
        "{text}"
    );
    assert!(
        text.contains("  tdx MRTD, igvm crate:\n    unchanged: "),
        "{text}"
    );
    assert!(text.lines().count() < 40, "{text}");

    // --verbose keeps the page ranges.
    let verbose = Command::new(env!("CARGO_BIN_EXE_igvm-diff"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "diff",
            "--verbose",
            "tests/fixtures/gce-svsm/gce-svsm-0932e060.igvm",
            "tests/fixtures/gce-svsm/gce-svsm-d5341027.igvm",
        ])
        .output()
        .unwrap();
    let verbose = String::from_utf8(verbose.stdout).unwrap();
    for expected in [
        "0xffe05000..0xfff6b000: 358 pages, contents changed [sev-snp]",
        "0xfffcc000..0xfffe0000: 20 pages, contents changed [sev-snp]",
        "0xffe00000..0xffe01000: 1 page, contents changed [sev-snp]",
    ] {
        assert!(verbose.contains(expected), "missing: {expected}\n{verbose}");
    }
}

#[test]
fn platform_flag_focuses_the_report_on_one_platform() {
    let output = Command::new(env!("CARGO_BIN_EXE_igvm-diff"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "diff",
            "--platform",
            "sev-snp",
            "tests/fixtures/gce-svsm/gce-svsm-f6b450ad.igvm",
            "tests/fixtures/gce-svsm/gce-svsm-4586baca.igvm",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("Platform: sev-snp (other platforms left out)"),
        "{text}"
    );
    assert!(!text.contains("tdx"), "{text}");

    let unknown = Command::new(env!("CARGO_BIN_EXE_igvm-diff"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "diff",
            "--platform",
            "vbs",
            "tests/fixtures/gce-svsm/gce-svsm-f6b450ad.igvm",
            "tests/fixtures/gce-svsm/gce-svsm-4586baca.igvm",
        ])
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(2));
    let error = String::from_utf8(unknown.stderr).unwrap();
    assert!(
        error.contains("platform vbs is not defined in either file (defined: sev-snp, tdx)"),
        "{error}"
    );
}

#[test]
fn gce_svsm_firmware_update_is_attributed_to_modules() {
    let report = diff(
        &bytes("gce-svsm-0932e060.igvm"),
        &bytes("gce-svsm-d5341027.igvm"),
    )
    .unwrap();
    let content = &report.content;
    let components: Vec<_> = content
        .components
        .iter()
        .map(|c| {
            assert_eq!(c.platforms, ["sev-snp"]);
            assert_eq!(c.before_format, Some(Format::UefiFirmwareVolume));
            assert_eq!(c.after_format, Some(Format::UefiFirmwareVolume));
            (c.start.as_str(), c.end.as_str(), c.changed_pages)
        })
        .collect();
    // FVMAIN_COMPACT and SECFV: every changed page is inside one of the two volumes.
    assert_eq!(
        components,
        [
            ("0xffe00000", "0xfffac000", 359),
            ("0xfffcc000", "0x100000000", 20),
        ]
    );
    assert!(content.unidentified.is_empty());
    assert!(content.notes.is_empty());
    assert_eq!(content.firmware.len(), 1);
    let modules = content.firmware[0].modules.as_ref().unwrap();
    let count = |kind| modules.changes.iter().filter(|c| c.change == kind).count();
    assert_eq!(count(ModuleChangeKind::Modified), 58);
    assert_eq!(count(ModuleChangeKind::DebugDataOnly), 62);
    assert_eq!(count(ModuleChangeKind::Added), 0);
    assert_eq!(count(ModuleChangeKind::Removed), 0);
    // Includes each volume's data outside files.
    assert_eq!(modules.unchanged, 8);
    let modified = |name: &str| {
        modules
            .changes
            .iter()
            .any(|c| c.change == ModuleChangeKind::Modified && c.name.as_deref() == Some(name))
    };
    for name in ["SecMain", "PeiCore", "DxeCore", "Tcg2Pei", "Tcg2Dxe"] {
        assert!(modified(name), "{name} should be modified");
    }
}

/// GCE publishes each SVSM IGVM file under its SEV-SNP launch digest. The digest computed as
/// COCONUT-SVSM igvmmeasure --native-zero does must reproduce every published name.
#[test]
fn computed_snp_launch_digest_reproduces_the_gce_object_names() {
    for (entry, bytes) in fixtures() {
        let report = diff(&bytes, &bytes).unwrap();
        assert_eq!(report.measurement, "computed");
        let launch = report.launch_measurement.unwrap();
        let snp = launch.before.igvmmeasure.unwrap();
        let object = entry["object"].as_str().unwrap();
        let published = object.rsplit('/').next().unwrap().trim_end_matches(".igvm");
        assert_eq!(snp.native_zero, published, "{}", entry["file"]);
        assert_eq!(snp.vmsa_count, 1);
        assert_eq!(snp.shared_pages, 0);
    }
}

/// The SVSM kernel is an ELF file with a symbol table: the update between these releases is
/// attributed to functions, with compiler hash renames paired rather than reported as churn.
#[test]
fn svsm_kernel_changes_are_attributed_to_functions() {
    let report = igvm_diff::diff_platform(
        &bytes("gce-svsm-f6b450ad.igvm"),
        &bytes("gce-svsm-4586baca.igvm"),
        Some("sev-snp"),
    )
    .unwrap();
    let elf = report
        .content
        .components
        .iter()
        .find(|c| c.after_format == Some(Format::Elf))
        .unwrap();
    assert!(
        elf.changed_sections
            .as_ref()
            .unwrap()
            .contains(&".text".to_string())
    );
    let functions = elf.function_changes.as_ref().unwrap();
    assert!(functions.added.is_empty(), "{functions:?}");
    assert!(functions.removed.is_empty(), "{functions:?}");
    for name in ["CryptRsaSign", "CryptRsaDecrypt", "OaepDecode", "PssEncode"] {
        assert!(
            functions.changed.iter().any(|n| n == name),
            "{name}: {functions:?}"
        );
    }
    assert_eq!(functions.changed.len(), 21);
}
