use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use igvm::{
    Arch, IgvmDirectiveHeader as D, IgvmFile, IgvmInitializationHeader as I,
    IgvmPlatformHeader as P, IgvmRevision, snp_defs::SevVmsa,
};
use igvm_defs::*;
use igvm_diff::{ChangeKind, diff};
use zerocopy::{FromBytes, FromZeros};

fn page(gpa: u64, byte: u8) -> D {
    D::PageData {
        gpa,
        compatibility_mask: 1,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::NORMAL,
        data: vec![byte; 4096],
    }
}

fn platform(mask: u32, platform_type: IgvmPlatformType) -> P {
    P::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask: mask,
        highest_vtl: 0,
        platform_type,
        platform_version: 1,
        shared_gpa_boundary: 0,
    })
}

fn image(revision: IgvmRevision, platforms: Vec<P>, init: Vec<I>, directives: Vec<D>) -> Vec<u8> {
    let file = IgvmFile::new(revision, platforms, init, directives).unwrap();
    let mut bytes = Vec::new();
    file.serialize(&mut bytes).unwrap();
    bytes
}

fn fixture(directives: Vec<D>) -> Vec<u8> {
    image(
        IgvmRevision::V1,
        vec![platform(1, IgvmPlatformType::SEV_SNP)],
        vec![],
        directives,
    )
}

#[test]
fn identical_files_produce_an_empty_deterministic_report() {
    let bytes = fixture(vec![page(0x1000, 1)]);
    let a = diff(&bytes, &bytes).unwrap();
    let b = diff(&bytes, &bytes).unwrap();
    assert!(!a.has_changes());
    assert!(a.findings.is_empty());
    assert_eq!(a.measurement, "not_requested");
    assert!(!a.to_string().contains("References:"));
    assert!(
        a.to_string()
            .contains("No file differences to investigate.")
    );
    assert!(!a.to_string().contains("Next:"));
    assert_eq!(
        serde_json::to_vec(&a).unwrap(),
        serde_json::to_vec(&b).unwrap()
    );
}

#[test]
fn changed_page_is_localized_even_when_unmeasured() {
    let mut a = page(0x1000, 1);
    let D::PageData { flags, .. } = &mut a else {
        unreachable!()
    };
    *flags = flags.with_unmeasured(true);
    let mut b = a.clone();
    let D::PageData { data, .. } = &mut b else {
        unreachable!()
    };
    data[137] = 2;
    let report = diff(&fixture(vec![a]), &fixture(vec![b])).unwrap();
    assert!(report.has_changes());
    assert_eq!(report.findings.len(), 1);
    let change = &report.findings[0];
    assert_eq!(change.kind, ChangeKind::Modified);
    assert_eq!(change.fields, ["payload_sha256"]);
    assert_eq!(change.after.as_ref().unwrap().fields["gpa"], "0x1000");
    assert_eq!(change.after.as_ref().unwrap().fields["unmeasured"], true);
    assert!(!report.to_string().contains("References:"));
}

#[test]
fn page_flags_types_and_addresses_remain_visible() {
    let before = fixture(vec![page(0x1000, 1)]);
    let mut changed = page(0x1000, 1);
    let D::PageData {
        flags, data_type, ..
    } = &mut changed
    else {
        unreachable!()
    };
    *flags = flags.with_shared(true).with_unmeasured(true);
    *data_type = IgvmPageDataType::CPUID_DATA;
    let report = diff(&before, &fixture(vec![changed])).unwrap();
    assert_eq!(
        report.findings[0].fields,
        ["data_type", "shared", "unmeasured"]
    );
    let moved = diff(&before, &fixture(vec![page(0x2000, 1)])).unwrap();
    assert_eq!(
        moved
            .findings
            .iter()
            .map(|change| change.kind)
            .collect::<Vec<_>>(),
        [ChangeKind::Removed, ChangeKind::Added]
    );
}

#[test]
fn insertion_does_not_cascade_but_reordering_is_reported() {
    let a = page(0x1000, 1);
    let b = page(0x2000, 2);
    let before = fixture(vec![a.clone(), b.clone()]);
    let inserted = diff(
        &before,
        &fixture(vec![page(0x3000, 3), a.clone(), b.clone()]),
    )
    .unwrap();
    assert_eq!(inserted.findings.len(), 1);
    assert_eq!(inserted.findings[0].kind, ChangeKind::Added);
    assert!(!inserted.comparison.order_changed);
    let reordered = diff(&before, &fixture(vec![b, a])).unwrap();
    assert!(reordered.comparison.order_changed);
    assert_eq!(reordered.findings.len(), 2);
    assert!(
        reordered
            .findings
            .iter()
            .all(|change| change.kind == ChangeKind::Reordered)
    );
}

#[test]
fn duplicate_addresses_are_never_overwritten_or_paired_ambiguously() {
    let a = page(0x1000, 1);
    let b = page(0x1000, 2);
    let before = fixture(vec![a.clone(), b.clone()]);
    assert!(diff(&before, &before).unwrap().findings.is_empty());
    let report = diff(&before, &fixture(vec![b, a])).unwrap();
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|c| c.kind == ChangeKind::Added)
            .count(),
        2
    );
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|c| c.kind == ChangeKind::Removed)
            .count(),
        2
    );
    assert!(report.diagnostics[0].contains("Ambiguous alignment"));
}

#[test]
fn platform_masks_are_resolved_by_platform_meaning() {
    let make = |snp_mask, tdx_mask| {
        let mut p = page(0x1000, 1);
        let D::PageData {
            compatibility_mask, ..
        } = &mut p
        else {
            unreachable!()
        };
        *compatibility_mask = snp_mask;
        image(
            IgvmRevision::V1,
            vec![
                platform(snp_mask, IgvmPlatformType::SEV_SNP),
                platform(tdx_mask, IgvmPlatformType::TDX),
            ],
            vec![],
            vec![p],
        )
    };
    let report = diff(&make(1, 2), &make(2, 1)).unwrap();
    assert!(report.has_changes());
    assert_eq!(report.findings.len(), 3);
    assert!(
        report
            .findings
            .iter()
            .all(|change| change.kind == ChangeKind::MaskReassigned)
    );
    assert!(!report.comparison.order_changed);
    let page = &report.findings[2];
    assert_eq!(page.before.as_ref().unwrap().platforms, ["sev-snp"]);
    assert_eq!(page.after.as_ref().unwrap().platforms, ["sev-snp"]);
}

#[test]
fn mixed_platform_images_keep_platform_specific_changes_separate() {
    let make = |snp_byte, shared_mask| {
        let mut snp = page(0x1000, snp_byte);
        let mut tdx = page(0x1000, 2);
        let mut shared = page(0x2000, 3);
        for (record, mask) in [(&mut snp, 1), (&mut tdx, 2), (&mut shared, shared_mask)] {
            let D::PageData {
                compatibility_mask, ..
            } = record
            else {
                unreachable!()
            };
            *compatibility_mask = mask;
        }
        image(
            IgvmRevision::V2 {
                arch: Arch::X64,
                page_size: 4096,
            },
            vec![
                platform(1, IgvmPlatformType::SEV_SNP),
                platform(2, IgvmPlatformType::TDX),
                platform(4, IgvmPlatformType::VSM_ISOLATION),
            ],
            vec![],
            vec![snp, tdx, shared],
        )
    };
    let report = diff(&make(1, 7), &make(4, 3)).unwrap();
    assert_eq!(report.findings.len(), 3);
    let changed = &report.findings[0];
    assert_eq!(changed.kind, ChangeKind::Modified);
    assert_eq!(changed.after.as_ref().unwrap().platforms, ["sev-snp"]);
    assert_eq!(changed.fields, ["payload_sha256"]);
    let removed = &report.findings[1];
    assert_eq!(removed.kind, ChangeKind::Removed);
    assert_eq!(
        removed.before.as_ref().unwrap().platforms,
        ["sev-snp", "tdx", "vbs"]
    );
    let added = &report.findings[2];
    assert_eq!(added.kind, ChangeKind::Added);
    assert_eq!(added.after.as_ref().unwrap().platforms, ["sev-snp", "tdx"]);
    assert!(report.diagnostics.is_empty());
    assert!(report.to_string().contains("platform coverage"));
}

#[test]
fn snp_registers_and_other_vmsa_bytes_are_compared() {
    let context = |rip, reserved| {
        let mut vmsa = SevVmsa::new_box_zeroed().unwrap();
        vmsa.rip = rip;
        vmsa.vmsa_reserved2 = reserved;
        D::SnpVpContext {
            gpa: 0x3000,
            compatibility_mask: 1,
            vp_index: 0,
            vmsa,
        }
    };
    let before = fixture(vec![page(0x1000, 1), context(0x1000, 0)]);
    let report = diff(&before, &fixture(vec![page(0x1000, 1), context(0x2000, 0)])).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].fields, ["payload_sha256", "rip"]);
    let report = diff(&before, &fixture(vec![page(0x1000, 1), context(0x1000, 1)])).unwrap();
    assert_eq!(report.findings[0].fields, ["payload_sha256"]);
}

#[test]
fn parameter_payload_and_placement_are_compared() {
    let make = |byte, offset, gpa| {
        fixture(vec![
            D::ParameterArea {
                number_of_bytes: 4096,
                parameter_area_index: 3,
                initial_data: vec![byte; 4096],
            },
            D::VpCount(IGVM_VHS_PARAMETER {
                parameter_area_index: 3,
                byte_offset: offset,
            }),
            D::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
                gpa,
                compatibility_mask: 1,
                parameter_area_index: 3,
            }),
            page(0x1000, 1),
        ])
    };
    let report = diff(&make(0, 0, 0x2000), &make(1, 4, 0x3000)).unwrap();
    assert_eq!(report.findings.len(), 3);
    assert_eq!(report.findings[0].fields, ["payload_sha256"]);
    assert_eq!(report.findings[1].fields, ["byte_offset"]);
    assert_eq!(report.findings[2].fields, ["gpa"]);
    let text = report.to_string();
    assert!(text.contains("Boot configuration changed: boot parameters."));
    assert!(text.contains(
        "Next: check the image builder's memory requirements and boot-parameter layout."
    ));
}

#[test]
fn policy_and_memory_requirements_are_compared() {
    let make = |policy, number_of_bytes| {
        image(
            IgvmRevision::V1,
            vec![platform(1, IgvmPlatformType::SEV_SNP)],
            vec![I::GuestPolicy {
                policy,
                compatibility_mask: 1,
            }],
            vec![
                D::RequiredMemory {
                    gpa: 0x1000,
                    compatibility_mask: 1,
                    number_of_bytes,
                    vtl2_protectable: false,
                },
                page(0x1000, 1),
            ],
        )
    };
    let report = diff(&make(0, 4096), &make(1, 8192)).unwrap();
    assert_eq!(report.findings[0].fields, ["policy"]);
    assert_eq!(report.findings[1].fields, ["size"]);
    assert!(report.to_string().contains(
        "Next: compare the changed guest policy with the restrictions required by your verifier."
    ));
}

#[test]
fn version_two_and_native_context_are_supported() {
    let make = |rip| {
        let mut context = IgvmNativeVpContextX64::new_box_zeroed().unwrap();
        context.rip = rip;
        image(
            IgvmRevision::V2 {
                arch: Arch::X64,
                page_size: 4096,
            },
            vec![platform(1, IgvmPlatformType::NATIVE)],
            vec![],
            vec![
                D::X64NativeVpContext {
                    compatibility_mask: 1,
                    vp_index: 0,
                    context,
                },
                page(0x1000, 1),
            ],
        )
    };
    let report = diff(&make(0x1000), &make(0x2000)).unwrap();
    assert_eq!(report.inputs.before.format_version, 2);
    assert_eq!(report.findings[0].fields, ["payload_sha256"]);
    let text = report.to_string();
    assert!(text.contains("CPU state bytes changed outside the displayed register fields"));
    assert!(text.contains("Next: review startup configuration"));
}

fn checksum(bytes: &mut [u8]) {
    let h = IGVM_FIXED_HEADER::read_from_prefix(bytes).unwrap().0;
    let fixed_size = if h.format_version == 2 { 32 } else { 24 };
    bytes[20..24].fill(0);
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes[..fixed_size]);
    let start = h.variable_header_offset as usize;
    hasher.update(&bytes[start..start + h.variable_header_size as usize]);
    bytes[20..24].copy_from_slice(&hasher.finalize().to_le_bytes());
}

fn body_offset(bytes: &[u8], typ: IgvmVariableHeaderType) -> usize {
    let h = IGVM_FIXED_HEADER::read_from_prefix(bytes).unwrap().0;
    let mut cursor = h.variable_header_offset as usize;
    loop {
        let header = IGVM_VHS_VARIABLE_HEADER::read_from_prefix(&bytes[cursor..])
            .unwrap()
            .0;
        if header.typ == typ {
            return cursor + 8;
        }
        cursor += 8 + (header.length as usize).div_ceil(8) * 8;
    }
}

#[test]
fn unreferenced_bytes_are_not_declared_equivalent() {
    let before = fixture(vec![page(0x1000, 1)]);
    let mut after = before.clone();
    after.push(42);
    let size = after.len() as u32;
    after[16..20].copy_from_slice(&size.to_le_bytes());
    checksum(&mut after);
    let report = diff(&before, &after).unwrap();
    assert!(report.has_changes());
    assert!(report.findings.is_empty());
    assert!(report.diagnostics[0].contains("unreferenced data"));
}

#[test]
fn record_changes_do_not_hide_changes_to_unreferenced_data() {
    let mut before = fixture(vec![page(0x1000, 1)]);
    let mut after = fixture(vec![page(0x1000, 2)]);
    for (bytes, tail) in [(&mut before, 41), (&mut after, 42)] {
        bytes.push(tail);
        let size = bytes.len() as u32;
        bytes[16..20].copy_from_slice(&size.to_le_bytes());
        checksum(bytes);
    }
    for (a, b) in [(&before, &after), (&after, &before)] {
        let report = diff(a, b).unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].fields, ["payload_sha256"]);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.contains("unreferenced data"))
        );
        assert!(
            report
                .to_string()
                .contains("Some differences could not be matched or explained.")
        );
        assert!(
            !report
                .to_string()
                .contains("Contents changed in 1 memory page")
        );
    }
}

#[test]
fn header_gaps_are_checked_even_when_page_contents_change() {
    let mut before = fixture(vec![page(0x1000, 1)]);
    before.splice(24..24, [9; 8]);
    before[8..12].copy_from_slice(&32_u32.to_le_bytes());
    let body = body_offset(&before, IgvmVariableHeaderType::IGVM_VHT_PAGE_DATA);
    let offset = u32::from_le_bytes(before[body + 12..body + 16].try_into().unwrap()) + 8;
    before[body + 12..body + 16].copy_from_slice(&offset.to_le_bytes());
    let size = before.len() as u32;
    before[16..20].copy_from_slice(&size.to_le_bytes());
    checksum(&mut before);
    let mut after = before.clone();
    after[24] ^= 1;
    *after.last_mut().unwrap() ^= 1;
    let report = diff(&before, &after).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert!(report.diagnostics[0].contains("unreferenced data"));
}

#[test]
fn aliased_and_overlapping_payloads_do_not_create_spurious_diagnostics() {
    let before = fixture(vec![page(0x1000, 1), page(0x2000, 1)]);
    let mut after = before.clone();
    let first = body_offset(&after, IgvmVariableHeaderType::IGVM_VHT_PAGE_DATA);
    let second = first + 32;
    let offset = u32::from_le_bytes(after[first + 12..first + 16].try_into().unwrap());
    assert_eq!(&after[second + 12..second + 16], &offset.to_le_bytes());
    after[second + 16..second + 20].copy_from_slice(&2_u32.to_le_bytes());
    checksum(&mut after);
    assert!(diff(&before, &after).unwrap().diagnostics.is_empty());

    after[second + 12..second + 16].copy_from_slice(&(offset + 1).to_le_bytes());
    after.push(1);
    let size = after.len() as u32;
    after[16..20].copy_from_slice(&size.to_le_bytes());
    checksum(&mut after);
    let report = diff(&before, &after).unwrap();
    assert!(report.diagnostics.is_empty(), "{report:#}");
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].fields, ["unmeasured"]);
}

#[test]
fn explicit_and_implicit_zero_pages_remain_distinguishable() {
    let before = fixture(vec![page(0x1000, 1), page(0x2000, 0)]);
    let mut zero = page(0x2000, 0);
    let D::PageData { data, .. } = &mut zero else {
        unreachable!()
    };
    data.clear();
    let report = diff(&before, &fixture(vec![page(0x1000, 1), zero])).unwrap();
    assert!(report.findings[0].fields.contains(&"data_present".into()));
}

#[test]
fn malformed_inputs_fail_even_when_both_sides_are_identical() {
    let valid = fixture(vec![page(0x1000, 1)]);
    let mut cases = vec![
        vec![],
        valid[..23].to_vec(),
        valid[..valid.len() - 1].to_vec(),
    ];
    for (offset, value) in [(0, 0), (8, u32::MAX - 7), (12, u32::MAX - 7), (20, 0)] {
        let mut bytes = valid.clone();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        cases.push(bytes);
    }
    let page = body_offset(&valid, IgvmVariableHeaderType::IGVM_VHT_PAGE_DATA);
    for (offset, value) in [
        (page - 8, 0x8000_0400),
        (page + 8, 0),
        (page + 8, 2),
        (page + 12, 1),
        (page + 12, u32::MAX),
        (page + 16, 1),
        (page + 16, 8),
    ] {
        let mut bytes = valid.clone();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        checksum(&mut bytes);
        cases.push(bytes);
    }
    for (index, bytes) in cases.iter().enumerate() {
        assert!(diff(bytes, bytes).is_err(), "malformed case {index}");
    }
}

#[test]
fn header_bit_mutations_never_panic_or_disappear_from_the_report() {
    let seeds = [
        fixture(vec![page(0x1000, 1)]),
        fixture(vec![
            D::ParameterArea {
                number_of_bytes: 4096,
                parameter_area_index: 0,
                initial_data: vec![1; 4096],
            },
            D::VpCount(IGVM_VHS_PARAMETER {
                parameter_area_index: 0,
                byte_offset: 0,
            }),
            D::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
                gpa: 0x1000,
                compatibility_mask: 1,
                parameter_area_index: 0,
            }),
        ]),
        fixture(vec![D::SnpVpContext {
            gpa: 0x2000,
            compatibility_mask: 1,
            vp_index: 0,
            vmsa: SevVmsa::new_box_zeroed().unwrap(),
        }]),
    ];
    for (seed, valid) in seeds.iter().enumerate() {
        let header = IGVM_FIXED_HEADER::read_from_prefix(valid).unwrap().0;
        let end = (header.variable_header_offset + header.variable_header_size) as usize;
        for offset in header.variable_header_offset as usize..end {
            for bit in 0..8 {
                let mut mutated = valid.clone();
                mutated[offset] ^= 1 << bit;
                checksum(&mut mutated);
                for (before, after) in [(valid, &mutated), (&mutated, valid)] {
                    let result = std::panic::catch_unwind(|| diff(before, after));
                    let result = result
                        .unwrap_or_else(|_| panic!("seed {seed}, offset {offset}, bit {bit}"));
                    if let Ok(report) = result {
                        assert!(report.has_changes());
                        assert!(!report.findings.is_empty() || !report.diagnostics.is_empty());
                        assert!(!report.to_string().contains("Files are identical"));
                        serde_json::to_vec(&report).unwrap();
                    }
                }
            }
        }
    }
}

#[test]
fn file_and_expanded_payload_limits_are_enforced() {
    let oversized = vec![0; igvm_diff::MAX_FILE_SIZE + 1];
    assert!(
        diff(&oversized, &oversized)
            .unwrap_err()
            .to_string()
            .contains("64 MiB")
    );
    let mut directives = vec![page(0x1000, 1)];
    for parameter_area_index in 0..5 {
        directives.push(D::ParameterArea {
            number_of_bytes: 32 * 1024 * 1024,
            parameter_area_index,
            initial_data: vec![],
        });
    }
    let bytes = fixture(directives);
    assert!(
        diff(&bytes, &bytes)
            .unwrap_err()
            .to_string()
            .contains("128 MiB")
    );
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "igvm-diff-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn cli_formats_alias_and_exit_codes() {
    let dir = TempDir::new();
    let a = dir.0.join("a.igvm");
    let b = dir.0.join("b.igvm");
    let bad = dir.0.join("bad.igvm");
    fs::write(&a, include_bytes!("fixtures/before.igvm")).unwrap();
    fs::write(&b, include_bytes!("fixtures/after.igvm")).unwrap();
    fs::write(&bad, b"not an IGVM").unwrap();
    for (command, after, format, code) in [
        ("diff", &a, "json", 0),
        ("diff", &b, "json", 1),
        ("compare", &b, "text", 1),
        ("diff", &bad, "json", 2),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_igvm-diff"))
            .arg(command)
            .arg(&a)
            .arg(after)
            .args(["--format", format])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code));
        if code == 2 {
            assert!(output.stdout.is_empty());
            assert!(
                String::from_utf8(output.stderr)
                    .unwrap()
                    .contains("after input")
            );
        } else if format == "json" {
            let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(json["comparison"]["file_bytes_changed"], code == 1);
            assert!(output.stderr.is_empty());
        } else {
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("Contents changed in 1 memory page (4 KiB each)."));
            assert!(text.contains(
                "No changes found to page addresses, page attributes or boot-setting records."
            ));
            assert!(text.contains(
                "Next: identify the changed component using the build's symbols/linker map"
            ));
            assert!(text.contains("0x1000..0x2000"));
            assert!(text.contains("contents changed"));
            assert!(!text.contains("payload_sha256"));
        }
    }
    let output = Command::new(env!("CARGO_BIN_EXE_igvm-diff"))
        .args([
            "diff",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--verbose",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("page_data 0x1000"));
    assert!(text.contains("payload_sha256"));
    let json = |verbose| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_igvm-diff"));
        command.args([
            "diff",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--format",
            "json",
        ]);
        if verbose {
            command.arg("-v");
        }
        command.output().unwrap().stdout
    };
    assert_eq!(json(false), json(true));
    let output = Command::new(env!("CARGO_BIN_EXE_igvm-diff"))
        .arg("diff")
        .arg(&a)
        .arg(dir.0.join("missing"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn snp_identity_metadata_and_key_material_changes_are_visible() {
    let make = |guest_svn, coordinate| {
        let mut id_public_key = IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY::new_box_zeroed().unwrap();
        id_public_key.qx[0] = coordinate;
        fixture(vec![
            page(0x1000, 1),
            D::SnpIdBlock {
                compatibility_mask: 1,
                author_key_enabled: 0,
                reserved: [0; 3],
                ld: [0; 48],
                family_id: [0; 16],
                image_id: [0; 16],
                version: 1,
                guest_svn,
                id_key_algorithm: 1,
                author_key_algorithm: 0,
                id_key_signature: IGVM_VHS_SNP_ID_BLOCK_SIGNATURE::new_box_zeroed().unwrap(),
                id_public_key,
                author_key_signature: IGVM_VHS_SNP_ID_BLOCK_SIGNATURE::new_box_zeroed().unwrap(),
                author_public_key: IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY::new_box_zeroed().unwrap(),
            },
        ])
    };
    let report = diff(&make(1, 0), &make(2, 1)).unwrap();
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].fields,
        ["guest_svn", "id_public_key_sha256"]
    );
    assert_eq!(report.measurement, "not_requested");
    assert!(report.to_string().contains(
        "Next: verify the changed identity/measurement metadata against your trust policy."
    ));
}

#[test]
fn mismatched_context_layout_is_rejected_before_entering_the_upstream_parser() {
    let mut bytes = fixture(vec![
        page(0x1000, 1),
        D::SnpVpContext {
            gpa: 0x2000,
            compatibility_mask: 1,
            vp_index: 0,
            vmsa: SevVmsa::new_box_zeroed().unwrap(),
        },
    ]);
    let platform = body_offset(&bytes, IgvmVariableHeaderType::IGVM_VHT_SUPPORTED_PLATFORM);
    bytes[platform + 5] = IgvmPlatformType::VSM_ISOLATION.0;
    checksum(&mut bytes);
    let error = diff(&bytes, &bytes).unwrap_err().to_string();
    assert!(error.contains("VBS context requires zero GPA"));
}

#[test]
fn vbs_and_relocation_records_are_compared_in_mixed_platform_images() {
    use igvm::{hv_defs::Vtl, registers::X86Register};

    let cases = [
        (vec![], "vp_context"),
        (
            vec![I::RelocatableRegion {
                compatibility_mask: 4,
                relocation_alignment: 0x20_0000,
                relocation_region_gpa: 0x20_0000,
                relocation_region_size: 0x20_0000,
                minimum_relocation_gpa: 0x20_0000,
                maximum_relocation_gpa: 0x1_0000_0000,
                is_vtl2: true,
                apply_rip_offset: true,
                apply_gdtr_offset: true,
                vp_index: 0,
                vtl: Vtl::Vtl2,
            }],
            "relocatable_region",
        ),
        (
            vec![I::PageTableRelocationRegion {
                compatibility_mask: 4,
                gpa: 0x1000,
                size: 0x2000,
                used_size: 0x1000,
                vp_index: 0,
                vtl: Vtl::Vtl2,
            }],
            "page_table_relocation",
        ),
    ];
    let directory = TempDir::new();
    let path = directory.0.join("vbs.igvm");
    let supported = fixture(vec![page(0x1000, 1)]);
    for (init, feature) in cases {
        let bytes = image(
            IgvmRevision::V2 {
                arch: Arch::X64,
                page_size: 4096,
            },
            [
                IgvmPlatformType::SEV_SNP,
                IgvmPlatformType::TDX,
                IgvmPlatformType::VSM_ISOLATION,
            ]
            .into_iter()
            .enumerate()
            .map(|(bit, typ)| {
                let P::SupportedPlatform(mut info) = platform(1 << bit, typ);
                info.highest_vtl = 2;
                P::SupportedPlatform(info)
            })
            .collect(),
            init,
            vec![
                page(0x20_0000, 1),
                D::X64VbsVpContext {
                    vtl: Vtl::Vtl2,
                    registers: vec![X86Register::Rip(0x20_0000), X86Register::Cr3(0x1000)],
                    compatibility_mask: 4,
                },
            ],
        );
        IgvmFile::new_from_binary(&bytes, None).unwrap();
        for (a, b) in [(&bytes, &supported), (&supported, &bytes)] {
            let report = diff(a, b).unwrap();
            assert!(
                report.findings.iter().any(|c| c
                    .before
                    .iter()
                    .chain(&c.after)
                    .any(|r| r.kind == feature))
            );
        }
        fs::write(&path, &bytes).unwrap();
        for format in ["text", "json"] {
            let output = Command::new(env!("CARGO_BIN_EXE_igvm-diff"))
                .arg("diff")
                .arg(&path)
                .arg(&path)
                .args(["--format", format])
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(0));
            assert!(output.stderr.is_empty());
            if format == "text" {
                assert!(
                    String::from_utf8(output.stdout)
                        .unwrap()
                        .contains("Files are identical")
                );
            } else {
                let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(report["findings"], serde_json::json!([]));
            }
        }
    }
}

#[test]
fn record_count_is_bounded_even_when_payloads_alias() {
    let base = fixture(vec![page(0x1000, 1)]);
    let body = body_offset(&base, IgvmVariableHeaderType::IGVM_VHT_PAGE_DATA);
    let platform_end = body - 8;
    let mut record = base[platform_end..platform_end + 32].to_vec();
    let data_start = platform_end + 32 * 32_768;
    record[20..24].copy_from_slice(&(data_start as u32).to_le_bytes());
    let mut bytes = base[..platform_end].to_vec();
    for _ in 0..32_768 {
        bytes.extend_from_slice(&record);
    }
    bytes.extend_from_slice(&[1; 4096]);
    let size = bytes.len() as u32;
    bytes[12..16].copy_from_slice(&((data_start - 24) as u32).to_le_bytes());
    bytes[16..20].copy_from_slice(&size.to_le_bytes());
    checksum(&mut bytes);
    assert!(
        diff(&bytes, &bytes)
            .unwrap_err()
            .to_string()
            .contains("32768 records")
    );
}

#[test]
fn masks_can_include_unused_bits_while_resolving_declared_platforms() {
    let before = fixture(vec![page(0x1000, 1)]);
    let mut changed = page(0x1000, 1);
    let D::PageData {
        compatibility_mask, ..
    } = &mut changed
    else {
        unreachable!()
    };
    *compatibility_mask = 0x11;
    let after = fixture(vec![changed]);
    let report = diff(&before, &after).unwrap();
    assert_eq!(report.findings.len(), 1);
    let change = &report.findings[0];
    assert_eq!(change.kind, ChangeKind::MaskReassigned);
    assert_eq!(change.after.as_ref().unwrap().platforms, ["sev-snp"]);
    assert_eq!(
        change.after.as_ref().unwrap().compatibility_mask,
        Some(0x11)
    );
    assert!(change.fields.is_empty());
}

#[test]
fn public_coconut_images_match_the_manifest_and_can_be_compared() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/coconut-svsm");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap()).unwrap();
    let mut images = Vec::new();
    for entry in manifest["files"].as_array().unwrap() {
        let bytes = fs::read(directory.join(entry["file"].as_str().unwrap())).unwrap();
        let report = diff(&bytes, &bytes).unwrap();
        assert!(!report.has_changes());
        assert!(report.findings.is_empty());
        assert_eq!(
            report.inputs.before.sha256,
            entry["sha256"].as_str().unwrap()
        );
        assert_eq!(
            report.inputs.before.size as u64,
            entry["size"].as_u64().unwrap()
        );
        assert_eq!(
            report.inputs.before.record_count as u64,
            entry["record_count"].as_u64().unwrap()
        );
        images.push(bytes);
    }
    for (a, before) in images.iter().enumerate() {
        for after in &images[a + 1..] {
            let report = diff(before, after).unwrap();
            assert!(report.has_changes());
            assert!(
                report
                    .findings
                    .iter()
                    .any(|change| change.fields.iter().any(|field| field == "payload_sha256"))
            );
            let summary = report.to_string();
            assert!(summary.lines().count() < 110);
            assert!(summary.contains("Configuration and CPU changes:"));
            assert!(summary.contains("more ranges; use --verbose"));
            assert!(format!("{report:#}").lines().count() > report.findings.len());
            let reverse = diff(after, before).unwrap();
            let mut expected: Vec<_> = report
                .findings
                .iter()
                .map(|change| {
                    let kind = match change.kind {
                        ChangeKind::Added => ChangeKind::Removed,
                        ChangeKind::Removed => ChangeKind::Added,
                        kind => kind,
                    };
                    serde_json::to_string(&(
                        kind,
                        &change.after,
                        &change.before,
                        &change.fields,
                        change.order_changed,
                    ))
                    .unwrap()
                })
                .collect();
            let mut actual: Vec<_> = reverse
                .findings
                .iter()
                .map(|change| {
                    serde_json::to_string(&(
                        change.kind,
                        &change.before,
                        &change.after,
                        &change.fields,
                        change.order_changed,
                    ))
                    .unwrap()
                })
                .collect();
            expected.sort();
            actual.sort();
            assert_eq!(actual, expected);
            assert_eq!(reverse.diagnostics, report.diagnostics);
            assert!(report.diagnostics.is_empty(), "{report:#}");
        }
    }
}

#[test]
fn coconut_fedora_cli_prioritizes_startup_and_layout_changes() {
    let output = Command::new(env!("CARGO_BIN_EXE_igvm-diff"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "diff",
            "tests/fixtures/coconut-svsm/coconut-fedora-9065337.igvm",
            "tests/fixtures/coconut-svsm/coconut-fedora-10828816.igvm",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "Files differ: 2289 record changes",
        "Boot configuration changed: CPU startup state, boot parameters, memory requirements, platform settings.",
        "Memory pages changed: addresses or platform coverage, contents, storage.",
        "Next: review startup configuration and memory layout in the image builder's source/build diff.",
        "Entry point (RIP): 0x808000 -> 0x10002",
        "no-execute (NXE) enabled [1]",
        "debug-register virtualization (DebugVirtualization) enabled [2]",
        "Memory pages (4 KiB each): 1400 added, 646 removed, 233 modified",
        "... 24 more ranges; use --verbose",
        "Launch measurement: not computed",
    ] {
        assert!(text.contains(expected), "missing: {expected}\n{text}");
    }
    assert!(text.find("Next:").unwrap() < text.find("Configuration and CPU changes:").unwrap());
    assert!(text.lines().count() < 80);
}

#[test]
fn summary_groups_only_adjacent_pages_with_matching_attributes() {
    let addresses = [0x1000, 0x2000, 0x4000, 0x5000, 0x6000];
    let before = fixture(addresses.map(|gpa| page(gpa, 1)).to_vec());
    let mut changed = addresses.map(|gpa| page(gpa, 2));
    for (index, shared, unmeasured) in [(3, true, false), (4, false, true)] {
        let D::PageData { flags, .. } = &mut changed[index] else {
            unreachable!()
        };
        *flags = flags.with_shared(shared).with_unmeasured(unmeasured);
    }
    let report = diff(&before, &fixture(changed.to_vec())).unwrap();
    let text = report.to_string();
    assert!(text.contains("5 modified"));
    assert!(text.contains("Page attribute changes: 2"));
    assert!(text.contains("Shared: false -> true"));
    assert!(text.contains("Unmeasured: false -> true"));
    assert!(text.contains("Records involving shared pages: 1"));
    assert!(text.contains("Records involving unmeasured pages: 1"));
    assert!(text.contains("0x1000..0x3000: 2 pages"));
    for (start, end) in [(0x4000, 0x5000), (0x5000, 0x6000), (0x6000, 0x7000)] {
        assert!(text.contains(&format!("{start:#x}..{end:#x}: 1 page,")));
    }
    assert!(!text.contains("0x1000..0x7000"));
}

#[test]
fn page_flags_remain_visible_among_many_mask_reassignments() {
    let make = |mask, changed| {
        let pages = (0..20)
            .map(|i| {
                let mut p = page(0x1000 + i * 4096, 1);
                let D::PageData {
                    compatibility_mask,
                    flags,
                    ..
                } = &mut p
                else {
                    unreachable!()
                };
                *compatibility_mask = mask;
                *flags = flags.with_unmeasured(changed && i == 19);
                p
            })
            .collect();
        image(
            IgvmRevision::V1,
            vec![platform(mask, IgvmPlatformType::SEV_SNP)],
            vec![],
            pages,
        )
    };
    let report = diff(&make(1, false), &make(2, true)).unwrap();
    let text = report.to_string();
    assert!(text.contains("Unmeasured: false -> true"));
    assert!(text.contains("8 more changes; use --verbose"));
    assert_eq!(report.findings.len(), 21);
}

#[test]
fn summary_preserves_platform_boundaries_and_ambiguous_duplicates() {
    let make = |byte| {
        let mut tdx = page(0x2000, byte);
        let D::PageData {
            compatibility_mask, ..
        } = &mut tdx
        else {
            unreachable!()
        };
        *compatibility_mask = 2;
        image(
            IgvmRevision::V1,
            vec![
                platform(1, IgvmPlatformType::SEV_SNP),
                platform(2, IgvmPlatformType::TDX),
            ],
            vec![],
            vec![page(0x1000, byte), tdx],
        )
    };
    let text = diff(&make(1), &make(2)).unwrap().to_string();
    assert!(text.contains("0x1000..0x2000: 1 page,"));
    assert!(text.contains("0x2000..0x3000: 1 page,"));
    assert!(!text.contains("0x1000..0x3000"));
    assert!(text.contains("[sev-snp]"));
    assert!(text.contains("[tdx]"));

    let before = fixture(vec![page(0x1000, 1), page(0x1000, 2)]);
    let after = fixture(vec![page(0x1000, 2), page(0x1000, 1)]);
    let text = diff(&before, &after).unwrap().to_string();
    assert!(text.contains("2 added, 2 removed"));
    assert_eq!(text.matches("0x1000..0x2000: 1 page,").count(), 4);
    assert!(text.contains("Ambiguous alignment"));
}

#[test]
fn summary_keeps_policy_cpu_order_and_unexplained_bytes_visible() {
    let make = |policy, rip, reverse| {
        let mut vmsa = SevVmsa::new_box_zeroed().unwrap();
        vmsa.rip = rip;
        let mut directives = vec![page(0x1000, 1), page(0x2000, 1)];
        if reverse {
            directives.reverse();
        }
        directives.push(D::SnpVpContext {
            gpa: 0x3000,
            compatibility_mask: 1,
            vp_index: 0,
            vmsa,
        });
        image(
            IgvmRevision::V1,
            vec![platform(1, IgvmPlatformType::SEV_SNP)],
            vec![I::GuestPolicy {
                policy,
                compatibility_mask: 1,
            }],
            directives,
        )
    };
    let text = diff(&make(0, 0x1000, false), &make(1, 0x2000, true))
        .unwrap()
        .to_string();
    assert!(text.contains("Policy: 0x0 -> 0x1"));
    assert!(text.contains("Entry point (RIP): 0x1000 -> 0x2000"));
    assert!(text.contains("Relative record order changed"));
    assert!(text.contains("2 reordered"));
    assert!(text.contains("Launch measurement: not computed"));

    let before = fixture(vec![page(0x1000, 1)]);
    let mut after = before.clone();
    after.push(42);
    let size = after.len() as u32;
    after[16..20].copy_from_slice(&size.to_le_bytes());
    checksum(&mut after);
    let text = diff(&before, &after).unwrap().to_string();
    assert!(text.contains("Files differ: 0 record changes"));
    assert!(text.contains("unreferenced data"));
    assert!(!text.contains("Files are identical"));
}

#[test]
fn summary_decodes_cpu_flags_and_deduplicates_references() {
    let make = |efer, features: u64| {
        let mut directives = vec![page(0x1000, 1)];
        for vp_index in 0..2 {
            let mut vmsa = SevVmsa::new_box_zeroed().unwrap();
            vmsa.efer = efer;
            vmsa.sev_features = features.into();
            directives.push(D::SnpVpContext {
                gpa: 0x2000 + u64::from(vp_index) * 4096,
                compatibility_mask: 1,
                vp_index,
                vmsa,
            });
        }
        fixture(directives)
    };
    let before = make(0x1000, 0x9);
    let after = make(0x1800, 0x29);
    let report = diff(&before, &after).unwrap();
    let text = report.to_string();
    assert_eq!(text.matches("no-execute (NXE) enabled [1]").count(), 2);
    assert_eq!(
        text.matches("debug-register virtualization (DebugVirtualization) enabled [2]")
            .count(),
        2
    );
    assert!(text.contains("EFER: 0x1000 -> 0x1800"));
    assert!(text.contains("SEV features: 0x9 -> 0x29"));
    assert_eq!(text.matches("https://").count(), 2);
    assert_eq!(text.matches("References:").count(), 1);
    assert!(!format!("{report:#}").contains("References:"));

    let text = diff(&after, &before).unwrap().to_string();
    assert!(text.contains("no-execute (NXE) disabled [1]"));
    assert!(text.contains("debug-register virtualization (DebugVirtualization) disabled [2]"));

    let text = diff(
        &make(0x1000 | (1 << 62), 0x9),
        &make(0x1800 | (1 << 63), 0x29),
    )
    .unwrap()
    .to_string();
    assert!(text.contains("no-execute (NXE) enabled"));
    assert!(text.contains("undecoded bits set: 0x8000000000000000"));
    assert!(text.contains("undecoded bits cleared: 0x4000000000000000"));
}

#[test]
fn review_guidance_distinguishes_storage_layout_masks_and_ambiguity() {
    let unchanged = fixture(vec![page(0x1000, 1)]);
    let mut flags = page(0x1000, 1);
    let D::PageData {
        flags: page_flags, ..
    } = &mut flags
    else {
        unreachable!()
    };
    *page_flags = page_flags.with_shared(true).with_unmeasured(true);
    let mut masked = page(0x1000, 2);
    let D::PageData {
        compatibility_mask, ..
    } = &mut masked
    else {
        unreachable!()
    };
    *compatibility_mask = 0x11;
    let mut zero = page(0x2000, 0);
    let D::PageData { data, .. } = &mut zero else {
        unreachable!()
    };
    data.clear();
    let mut unreferenced = unchanged.clone();
    unreferenced.push(42);
    let size = unreferenced.len() as u32;
    unreferenced[16..20].copy_from_slice(&size.to_le_bytes());
    checksum(&mut unreferenced);
    let cases = [
        (
            "page flags",
            unchanged.clone(),
            fixture(vec![flags]),
            "Memory pages changed: attributes.",
            "Next: review changes to page sharing",
        ),
        (
            "address",
            unchanged.clone(),
            fixture(vec![page(0x2000, 1)]),
            "Memory pages changed: addresses or platform coverage.",
            "Next: check the build's memory layout",
        ),
        (
            "content and mask",
            unchanged.clone(),
            fixture(vec![masked]),
            "platform masks",
            "Next: check how the platform masks select records",
        ),
        (
            "storage",
            fixture(vec![page(0x1000, 1), page(0x2000, 0)]),
            fixture(vec![page(0x1000, 1), zero]),
            "Memory pages changed: storage.",
            "storage changes may preserve contents",
        ),
        (
            "order",
            fixture(vec![page(0x1000, 1), page(0x2000, 2)]),
            fixture(vec![page(0x2000, 2), page(0x1000, 1)]),
            "Boot configuration changed: record loading order.",
            "Next: review the loader/build changes",
        ),
        (
            "duplicates",
            fixture(vec![page(0x1000, 1), page(0x1000, 2)]),
            fixture(vec![page(0x1000, 2), page(0x1000, 1)]),
            "Some differences could not be matched or explained.",
            "Next: resolve the comparison notes",
        ),
        (
            "unreferenced bytes",
            unchanged.clone(),
            unreferenced,
            "Some differences could not be matched or explained.",
            "Next: resolve the comparison notes",
        ),
        (
            "format",
            unchanged,
            image(
                IgvmRevision::V2 {
                    arch: Arch::X64,
                    page_size: 4096,
                },
                vec![platform(1, IgvmPlatformType::SEV_SNP)],
                vec![],
                vec![page(0x1000, 1)],
            ),
            "Boot configuration changed: IGVM format.",
            "Next: review the image-format change",
        ),
    ];
    for (name, before, after, meaning, next) in cases {
        let text = diff(&before, &after).unwrap().to_string();
        assert!(text.contains(meaning), "{name}: {text}");
        assert!(text.contains(next), "{name}: {text}");
        assert!(
            !text.contains("No changes found to page addresses"),
            "{name}: {text}"
        );
        assert!(!text.contains("reordered; reordered"));
    }
}

#[test]
fn startup_changes_stay_visible_when_parameter_changes_are_truncated() {
    let make = |byte, rip| {
        let mut directives = vec![page(0x1000, 1)];
        for index in 0..13 {
            directives.push(D::ParameterArea {
                number_of_bytes: 4096,
                parameter_area_index: index,
                initial_data: vec![byte; 4096],
            });
        }
        let mut vmsa = SevVmsa::new_box_zeroed().unwrap();
        vmsa.rip = rip;
        directives.push(D::SnpVpContext {
            gpa: 0x2000,
            compatibility_mask: 1,
            vp_index: 0,
            vmsa,
        });
        fixture(directives)
    };
    let text = diff(&make(1, 0x1000), &make(2, 0x2000))
        .unwrap()
        .to_string();
    assert!(text.contains("Entry point (RIP): 0x1000 -> 0x2000"));
    assert!(text.contains("2 more changes; use --verbose"));
    assert!(text.contains("CPU startup state, boot parameters"));
}
