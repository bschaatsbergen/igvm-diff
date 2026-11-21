//! Payload detection and firmware module comparison on synthetic UEFI firmware volumes.

use igvm::{IgvmDirectiveHeader as D, IgvmFile, IgvmPlatformHeader as P, IgvmRevision};
use igvm_defs::*;
use igvm_diff::{Format, ModuleChangeKind, diff};

const BASE: u64 = 0xffe0_0000;
const FFS2: [u8; 16] = [
    0x78, 0xe5, 0x8c, 0x8c, 0x3d, 0x8a, 0x1c, 0x4f, 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3,
];
const LZMA: [u8; 16] = [
    0x98, 0x58, 0x4e, 0xee, 0x14, 0x39, 0x59, 0x42, 0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf,
];

fn section(kind: u8, body: &[u8]) -> Vec<u8> {
    let size = body.len() + 4;
    let mut out = vec![size as u8, (size >> 8) as u8, (size >> 16) as u8, kind];
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn name(text: &str) -> Vec<u8> {
    let mut body: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    body.extend_from_slice(&[0, 0]);
    section(0x15, &body)
}

fn file(guid: u8, kind: u8, sections: &[Vec<u8>]) -> Vec<u8> {
    let body = sections.concat();
    let size = body.len() + 24;
    let mut out = vec![guid; 16];
    out.extend_from_slice(&[
        0,
        0,
        kind,
        0,
        size as u8,
        (size >> 8) as u8,
        (size >> 16) as u8,
        0xf8,
    ]);
    out.extend_from_slice(&body);
    out
}

fn volume(files: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for file in files {
        while body.len() % 8 != 0 {
            body.push(0xff);
        }
        body.extend_from_slice(file);
    }
    let length = (72 + body.len()).next_multiple_of(4096);
    let mut out = vec![0; 16];
    out.extend_from_slice(&FFS2);
    out.extend_from_slice(&(length as u64).to_le_bytes());
    out.extend_from_slice(b"_FVH");
    out.extend_from_slice(&0x800_u32.to_le_bytes()); // erase polarity 1
    out.extend_from_slice(&72_u16.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 2]); // checksum, no extension header, revision
    out.extend_from_slice(&((length / 4096) as u32).to_le_bytes());
    out.extend_from_slice(&4096_u32.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&body);
    out.resize(length, 0xff);
    out
}

/// A minimal PE32+ image with one section that holds a CodeView debug entry and `code`.
fn pe(timestamp: u32, path: &str, code: &[u8]) -> Vec<u8> {
    let mut codeview = b"NB10".to_vec();
    codeview.extend_from_slice(&[0; 12]);
    codeview.extend_from_slice(path.as_bytes());
    codeview.push(0);
    let raw = 0x200_usize;
    let size = 28 + codeview.len() + code.len();
    let mut image = vec![0; raw + size];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
    image[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    image[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    image[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[coff + 4..coff + 8].copy_from_slice(&timestamp.to_le_bytes());
    image[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes());
    let optional = coff + 20;
    image[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
    image[optional + 56..optional + 60].copy_from_slice(&((raw + size) as u32).to_le_bytes());
    image[optional + 60..optional + 64].copy_from_slice(&(raw as u32).to_le_bytes());
    image[optional + 64..optional + 68].copy_from_slice(&timestamp.to_le_bytes()); // checksum
    image[optional + 108..optional + 112].copy_from_slice(&16_u32.to_le_bytes());
    let debug = optional + 112 + 48;
    image[debug..debug + 4].copy_from_slice(&(raw as u32).to_le_bytes());
    image[debug + 4..debug + 8].copy_from_slice(&28_u32.to_le_bytes());
    let table = optional + 240;
    image[table..table + 5].copy_from_slice(b".data");
    for (offset, value) in [(8, size), (12, raw), (16, size), (20, raw)] {
        image[table + offset..table + offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
    let entry = raw;
    image[entry + 4..entry + 8].copy_from_slice(&timestamp.to_le_bytes());
    image[entry + 12..entry + 16].copy_from_slice(&2_u32.to_le_bytes());
    image[entry + 16..entry + 20].copy_from_slice(&(codeview.len() as u32).to_le_bytes());
    image[entry + 20..entry + 24].copy_from_slice(&((raw + 28) as u32).to_le_bytes());
    image[entry + 24..entry + 28].copy_from_slice(&((raw + 28) as u32).to_le_bytes());
    image[raw + 28..raw + 28 + codeview.len()].copy_from_slice(&codeview);
    image[raw + 28 + codeview.len()..].copy_from_slice(code);
    image
}

fn driver(guid: u8, label: &str, timestamp: u32, path: &str, code: &[u8]) -> Vec<u8> {
    file(
        guid,
        0x07,
        &[section(0x10, &pe(timestamp, path, code)), name(label)],
    )
}

fn igvm(masks: &[(u32, IgvmPlatformType)], regions: &[(u64, &[u8])]) -> Vec<u8> {
    let platforms = masks
        .iter()
        .map(|&(mask, platform_type)| {
            P::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
                compatibility_mask: mask,
                highest_vtl: 0,
                platform_type,
                platform_version: 1,
                shared_gpa_boundary: 0,
            })
        })
        .collect();
    let all = masks.iter().fold(0, |bits, (mask, _)| bits | mask);
    let mut directives = Vec::new();
    for (gpa, bytes) in regions {
        for (index, chunk) in bytes.chunks(4096).enumerate() {
            let mut data = chunk.to_vec();
            data.resize(4096, 0);
            directives.push(D::PageData {
                gpa: gpa + index as u64 * 4096,
                compatibility_mask: all,
                flags: IgvmPageDataFlags::new(),
                data_type: IgvmPageDataType::NORMAL,
                data,
            });
        }
    }
    let file = IgvmFile::new(IgvmRevision::V1, platforms, vec![], directives).unwrap();
    let mut out = Vec::new();
    file.serialize(&mut out).unwrap();
    out
}

fn snp(regions: &[(u64, &[u8])]) -> Vec<u8> {
    igvm(&[(1, IgvmPlatformType::SEV_SNP)], regions)
}

fn lzma(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    lzma_rs::lzma_compress(&mut &data[..], &mut out).unwrap();
    out
}

fn guided(guid: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut body = guid.to_vec();
    body.extend_from_slice(&24_u16.to_le_bytes()); // data offset from the section start
    body.extend_from_slice(&1_u16.to_le_bytes()); // processing required
    body.extend_from_slice(payload);
    section(0x02, &body)
}

#[test]
fn modules_separate_pe_debug_data_from_code_changes() {
    let before = volume(&[
        driver(0xa1, "Same", 1, "/build/one/Same.dll", b"same code"),
        driver(
            0xa2,
            "DebugOnly",
            1,
            "/build/one/DebugOnly.dll",
            b"same code",
        ),
        driver(0xa3, "Patched", 1, "/build/one/Patched.dll", b"old code"),
        driver(0xa4, "Dropped", 1, "/build/one/Dropped.dll", b"code"),
    ]);
    let after = volume(&[
        driver(0xa1, "Same", 1, "/build/one/Same.dll", b"same code"),
        driver(
            0xa2,
            "DebugOnly",
            2,
            "/build/two/DebugOnly.dll",
            b"same code",
        ),
        driver(0xa3, "Patched", 1, "/build/one/Patched.dll", b"new code"),
        driver(0xa5, "New", 1, "/build/one/New.dll", b"code"),
    ]);
    let report = diff(&snp(&[(BASE, &before)]), &snp(&[(BASE, &after)])).unwrap();
    let content = &report.content;
    assert_eq!(content.components.len(), 1, "{content:#?}");
    let component = &content.components[0];
    assert_eq!(component.platforms, ["sev-snp"]);
    assert_eq!(component.start, "0xffe00000");
    assert_eq!(component.before_format, Some(Format::UefiFirmwareVolume));
    assert_eq!(component.after_format, Some(Format::UefiFirmwareVolume));
    assert!(content.unidentified.is_empty());

    assert_eq!(content.firmware.len(), 1);
    let modules = content.firmware[0].modules.as_ref().unwrap();
    // "Same" and the volume data outside files.
    assert_eq!(modules.unchanged, 2);
    let changes: Vec<_> = modules
        .changes
        .iter()
        .map(|c| (c.change, c.name.as_deref().unwrap(), c.differing_bytes))
        .collect();
    assert_eq!(
        changes,
        [
            (ModuleChangeKind::Modified, "Patched", Some(3)),
            (ModuleChangeKind::DebugDataOnly, "DebugOnly", None),
            (ModuleChangeKind::Added, "New", None),
            (ModuleChangeKind::Removed, "Dropped", None),
        ]
    );

    let text = report.to_string();
    for expected in [
        "  0xffe00000..0xffe01000: UEFI firmware volume [sev-snp], 1 page\n",
        "Firmware modules [sev-snp]: 1 modified, 1 added, 1 removed, 1 changed only in PE debug data (timestamps, checksum, CodeView path), 2 unchanged\n",
        "  DXE (1): Patched\n",
        "  added DXE (1): New\n",
        "  removed DXE (1): Dropped\n",
        "  debug data only DXE (1): DebugOnly\n",
        "Attestation impact:\n  Launch measurement changes [sev-snp] (from the computed digests below).\n  Measured page data changed: 1 page [sev-snp].\n",
    ] {
        assert!(text.contains(expected), "missing: {expected}\n{text}");
    }
    // --verbose names debug-data-only modules and shows byte counts.
    let verbose = format!("{report:#}");
    assert!(
        verbose.contains("  debug data only DXE (1): DebugOnly\n"),
        "{verbose}"
    );
    assert!(
        verbose.contains("  DXE (1): Patched (3 bytes differ)\n"),
        "{verbose}"
    );
}

#[test]
fn lzma_sections_and_nested_volumes_are_decoded() {
    let wrap = |code: &[u8]| {
        let inner = volume(&[driver(0xb1, "Inner", 1, "/x.dll", code)]);
        volume(&[file(
            0xb0,
            0x0b,
            &[guided(LZMA, &lzma(&section(0x17, &inner)))],
        )])
    };
    let report = diff(
        &snp(&[(BASE, &wrap(b"before"))]),
        &snp(&[(BASE, &wrap(b"after!"))]),
    )
    .unwrap();
    let modules = report.content.firmware[0].modules.as_ref().unwrap();
    // The container file's own sections and both volumes' data outside files are unchanged;
    // the nested module is reported.
    assert_eq!(modules.unchanged, 3);
    assert_eq!(modules.changes.len(), 1);
    assert_eq!(modules.changes[0].change, ModuleChangeKind::Modified);
    assert_eq!(modules.changes[0].name.as_deref(), Some("Inner"));
    assert!(!modules.changes[0].undecoded_sections);
}

#[test]
fn modules_are_matched_across_a_layout_change() {
    let fv = volume(&[driver(0xc1, "Moved", 1, "/x.dll", b"code")]);
    let report = diff(&snp(&[(BASE, &fv)]), &snp(&[(BASE + 0x10_0000, &fv)])).unwrap();
    let content = &report.content;
    let formats: Vec<_> = content
        .components
        .iter()
        .map(|c| (c.start.as_str(), c.before_format, c.after_format))
        .collect();
    assert_eq!(
        formats,
        [
            ("0xffe00000", Some(Format::UefiFirmwareVolume), None),
            ("0xfff00000", None, Some(Format::UefiFirmwareVolume)),
        ]
    );
    let modules = content.firmware[0].modules.as_ref().unwrap();
    assert_eq!(modules.unchanged, 2);
    assert!(modules.changes.is_empty());
    let text = report.to_string();
    assert!(
        text.contains("UEFI firmware volume (before only)"),
        "{text}"
    );
    assert!(text.contains("UEFI firmware volume (after only)"), "{text}");
}

#[test]
fn identical_results_on_several_platforms_are_reported_once() {
    let masks = [(1, IgvmPlatformType::SEV_SNP), (2, IgvmPlatformType::TDX)];
    let before = volume(&[driver(0xd1, "Shared", 1, "/x.dll", b"one")]);
    let after = volume(&[driver(0xd1, "Shared", 1, "/x.dll", b"two")]);
    let report = diff(
        &igvm(&masks, &[(BASE, &before)]),
        &igvm(&masks, &[(BASE, &after)]),
    )
    .unwrap();
    assert_eq!(report.content.components.len(), 1);
    assert_eq!(report.content.components[0].platforms, ["sev-snp", "tdx"]);
    assert_eq!(report.content.firmware.len(), 1);
    assert_eq!(report.content.firmware[0].platforms, ["sev-snp", "tdx"]);
}

#[test]
fn malformed_volumes_are_reported_without_failing_the_diff() {
    let good = volume(&[driver(0xe1, "Good", 1, "/x.dll", b"code")]);
    let mut bad = good.clone();
    // Claim a file size that extends past the end of the volume.
    bad[72 + 20..72 + 23].copy_from_slice(&[0xff, 0xff, 0x0f]);
    let report = diff(&snp(&[(BASE, &good)]), &snp(&[(BASE, &bad)])).unwrap();
    assert!(report.has_changes());
    let firmware = &report.content.firmware[0];
    assert!(firmware.modules.is_none());
    let error = firmware.error.as_deref().unwrap();
    assert!(error.contains("extends beyond its volume"), "{error}");
    assert!(
        report
            .to_string()
            .contains("not decoded (after: volume at 0xffe00000")
    );
}

#[test]
fn lzma_sections_larger_than_the_limit_are_rejected_before_decoding() {
    // LZMA-alone header: properties, dictionary size, then an unpacked size of 1 GiB.
    let mut bomb = vec![0x5d, 0, 0, 0x80, 0];
    bomb.extend_from_slice(&(1_u64 << 30).to_le_bytes());
    bomb.extend_from_slice(&[0; 16]);
    let fv = |payload: &[u8]| volume(&[file(0xf1, 0x07, &[guided(LZMA, payload), name("Big")])]);
    let report = diff(
        &snp(&[(BASE, &fv(&lzma(&section(0x19, b"small"))))]),
        &snp(&[(BASE, &fv(&bomb))]),
    )
    .unwrap();
    let error = report.content.firmware[0].error.as_deref().unwrap();
    assert!(
        error.contains("larger than the decompression limit"),
        "{error}"
    );
}

#[test]
fn changed_pages_outside_recognized_payloads_are_counted() {
    let report = diff(&snp(&[(0x1000, &[1; 8192])]), &snp(&[(0x1000, &[2; 8192])])).unwrap();
    assert!(report.content.components.is_empty());
    assert!(report.content.firmware.is_empty());
    assert_eq!(report.content.unidentified.len(), 1);
    assert_eq!(report.content.unidentified[0].changed_pages, 2);
    assert!(
        report
            .to_string()
            .contains("  outside recognized payloads: 2 [sev-snp]\n")
    );
}

#[test]
fn identical_files_skip_content_analysis() {
    let bytes = snp(&[(BASE, &volume(&[driver(0xa1, "Same", 1, "/x.dll", b"code")]))]);
    let report = diff(&bytes, &bytes).unwrap();
    assert!(report.content.components.is_empty());
    assert!(report.content.firmware.is_empty());
    assert!(!report.to_string().contains("Changed contents by payload"));
}

fn single_page(platform: IgvmPlatformType, unmeasured: bool, byte: u8) -> Vec<u8> {
    let platforms = vec![P::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask: 1,
        highest_vtl: 0,
        platform_type: platform,
        platform_version: 1,
        shared_gpa_boundary: 0,
    })];
    let directives = vec![D::PageData {
        gpa: 0x1000,
        compatibility_mask: 1,
        flags: IgvmPageDataFlags::new().with_unmeasured(unmeasured),
        data_type: IgvmPageDataType::NORMAL,
        data: vec![byte; 4096],
    }];
    let file = IgvmFile::new(IgvmRevision::V1, platforms, vec![], directives).unwrap();
    let mut out = Vec::new();
    file.serialize(&mut out).unwrap();
    out
}

#[test]
fn unmeasured_page_changes_are_not_reported_as_measurement_changes() {
    let report = diff(
        &single_page(IgvmPlatformType::SEV_SNP, true, 1),
        &single_page(IgvmPlatformType::SEV_SNP, true, 2),
    )
    .unwrap();
    let impact = report.attestation.as_ref().unwrap();
    assert!(impact.measured_page_changes.is_empty());
    assert_eq!(impact.unmeasured_page_changes["sev-snp"], 1);
    assert!(impact.changed.is_empty());
    let text = report.to_string();
    assert!(
        text.contains(
            "  Unmeasured or shared page data changed: 1 page [sev-snp]. IGVM excludes their contents from the launch measurement; an unmeasured page's address still counts.\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("  Unchanged: measured pages, VP context,"),
        "{text}"
    );
    assert!(!text.contains("The launch measurement changes"), "{text}");
    // Same address, new contents of an unmeasured page: the SNP digest does not change.
    assert!(
        text.contains(
            "  Launch measurement unchanged [sev-snp] (from the computed digests below).\n"
        ),
        "{text}"
    );
}

#[test]
fn measured_to_unmeasured_flag_changes_count_as_measured_changes() {
    let report = diff(
        &single_page(IgvmPlatformType::SEV_SNP, false, 1),
        &single_page(IgvmPlatformType::SEV_SNP, true, 1),
    )
    .unwrap();
    let impact = report.attestation.as_ref().unwrap();
    assert_eq!(impact.measured_page_changes["sev-snp"], 1);
    assert!(impact.unmeasured_page_changes.is_empty());
}

#[test]
fn native_only_changes_have_no_attestation_summary() {
    let report = diff(
        &single_page(IgvmPlatformType::NATIVE, false, 1),
        &single_page(IgvmPlatformType::NATIVE, false, 2),
    )
    .unwrap();
    assert!(report.attestation.is_none());
    assert!(!report.to_string().contains("Attestation impact"));
}

fn modified_names(before: &[u8], after: &[u8]) -> Vec<(ModuleChangeKind, String)> {
    let report = diff(&snp(&[(BASE, before)]), &snp(&[(BASE, after)])).unwrap();
    report.content.firmware[0]
        .modules
        .as_ref()
        .unwrap()
        .changes
        .iter()
        .map(|c| (c.change, c.name.clone().unwrap_or_else(|| c.guid.clone())))
        .collect()
}

#[test]
fn codeview_size_covering_code_does_not_hide_code_changes() {
    let image = |code: &[u8]| {
        let mut pe = pe(1, "/x.dll", code);
        // Debug entry SizeOfData: claim the CodeView record runs to the end of the image.
        let entry = 0x200;
        let codeview = 16 + "/x.dll".len() + 1;
        pe[entry + 16..entry + 20].copy_from_slice(&((codeview + code.len()) as u32).to_le_bytes());
        volume(&[file(0xa1, 0x07, &[section(0x10, &pe), name("Evil")])])
    };
    assert_eq!(
        modified_names(&image(b"good code!"), &image(b"evil code!")),
        [(ModuleChangeKind::Modified, "Evil".to_string())]
    );
}

#[test]
fn codeview_records_in_executable_sections_are_compared_as_raw_bytes() {
    let image = |path: &str| {
        let mut pe = pe(1, path, b"code");
        // Section characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE.
        let characteristics = 0x44 + 20 + 240 + 36;
        pe[characteristics..characteristics + 4].copy_from_slice(&0x2000_0020_u32.to_le_bytes());
        volume(&[file(0xa1, 0x07, &[section(0x10, &pe), name("Exec")])])
    };
    assert_eq!(
        modified_names(&image("/build/one.dll"), &image("/build/two.dll")),
        [(ModuleChangeKind::Modified, "Exec".to_string())]
    );
}

#[test]
fn ffs_file_type_changes_are_modifications() {
    let fv = |file_type| {
        volume(&[file(
            0xa1,
            file_type,
            &[section(0x19, b"data"), name("Typed")],
        )])
    };
    // EFI_FV_FILETYPE_FREEFORM (not dispatched) -> EFI_FV_FILETYPE_DRIVER.
    assert_eq!(
        modified_names(&fv(0x02), &fv(0x07)),
        [(ModuleChangeKind::Modified, "Typed".to_string())]
    );
}

#[test]
fn swapping_which_duplicate_file_is_deleted_is_a_modification() {
    let deleted = |mut file: Vec<u8>| {
        // EFI_FILE_DELETED (0x10), stored inverted because the erase polarity is 1.
        file[23] &= !0x10;
        file
    };
    let one = || driver(0xa1, "Twin", 1, "/x.dll", b"one");
    let two = || driver(0xa1, "Twin", 1, "/x.dll", b"two");
    let changes = modified_names(
        &volume(&[deleted(one()), two()]),
        &volume(&[one(), deleted(two())]),
    );
    assert_eq!(changes.len(), 2, "{changes:?}");
    assert!(
        changes
            .iter()
            .all(|(kind, _)| *kind == ModuleChangeKind::Modified)
    );
}

#[test]
fn guid_defined_header_data_is_compared() {
    let fv = |key: &[u8; 4]| {
        let mut body = [0x11; 16].to_vec();
        body.extend_from_slice(&28_u16.to_le_bytes()); // data offset after 4 bytes of header data
        body.extend_from_slice(&0_u16.to_le_bytes()); // no processing required
        body.extend_from_slice(key);
        body.extend_from_slice(&section(0x19, b"payload!"));
        volume(&[file(0xa1, 0x07, &[section(0x02, &body), name("Signed")])])
    };
    assert_eq!(
        modified_names(&fv(b"key1"), &fv(b"key2")),
        [(ModuleChangeKind::Modified, "Signed".to_string())]
    );
}

#[test]
fn pad_file_contents_are_compared_as_volume_data() {
    let fv = |pad: &[u8]| {
        volume(&[
            driver(0xa1, "Same", 1, "/x.dll", b"code"),
            file(0xff, 0xf0, &[section(0x19, pad)]),
        ])
    };
    let changes = modified_names(&fv(b"PAD!"), &fv(b"PAD?"));
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0].0, ModuleChangeKind::Modified);
    assert!(changes[0].1.contains("data outside files"), "{changes:?}");
}

#[test]
fn platforms_in_only_one_file_are_noted() {
    let fv = volume(&[driver(0xa1, "Same", 1, "/x.dll", b"code")]);
    let report = diff(
        &igvm(&[(1, IgvmPlatformType::SEV_SNP)], &[(BASE, &fv)]),
        &igvm(
            &[(1, IgvmPlatformType::SEV_SNP), (2, IgvmPlatformType::TDX)],
            &[(BASE, &fv)],
        ),
    )
    .unwrap();
    assert_eq!(
        report.content.notes,
        ["tdx: platform only in the after file; content analysis skipped"]
    );
}

/// Section characteristics offset of the single section in `pe()`.
const CHARACTERISTICS: usize = 0x44 + 20 + 240 + 36;

#[test]
fn debug_directories_in_executable_sections_are_compared_as_raw_bytes() {
    let image = |code: u32| {
        let mut pe = pe(1, "/x.dll", b"code");
        pe[CHARACTERISTICS..CHARACTERISTICS + 4].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
        // Not a CodeView entry, so only its timestamp field would be masked.
        pe[0x200 + 12..0x200 + 16].copy_from_slice(&0_u32.to_le_bytes());
        pe[0x200 + 4..0x200 + 8].copy_from_slice(&code.to_le_bytes());
        volume(&[file(0xa1, 0x07, &[section(0x10, &pe), name("ExecDir")])])
    };
    assert_eq!(
        modified_names(&image(0x9090_9090), &image(0xcccc_e9cc)),
        [(ModuleChangeKind::Modified, "ExecDir".to_string())]
    );
}

#[test]
fn codeview_records_in_the_entry_point_section_are_compared_as_raw_bytes() {
    let image = |path: &str| {
        let mut pe = pe(1, path, b"code");
        // AddressOfEntryPoint inside the only (data-flagged) section.
        let optional = 0x44 + 20;
        pe[optional + 16..optional + 20].copy_from_slice(&0x200_u32.to_le_bytes());
        volume(&[file(0xa1, 0x07, &[section(0x10, &pe), name("Entry")])])
    };
    assert_eq!(
        modified_names(&image("/build/one.dll"), &image("/build/two.dll")),
        [(ModuleChangeKind::Modified, "Entry".to_string())]
    );
}

#[test]
fn more_than_sixteen_debug_entries_are_compared_as_raw_bytes() {
    let image = |path: &str| {
        let mut pe = pe(1, path, b"code");
        // Debug data directory size: 17 entries.
        let directory = 0x44 + 20 + 112 + 48;
        pe[directory + 4..directory + 8].copy_from_slice(&(17 * 28_u32).to_le_bytes());
        volume(&[file(0xa1, 0x07, &[section(0x10, &pe), name("Many")])])
    };
    assert_eq!(
        modified_names(&image("/build/one.dll"), &image("/build/two.dll")),
        [(ModuleChangeKind::Modified, "Many".to_string())]
    );
}

#[test]
fn measurement_errors_are_shown_instead_of_a_digest() {
    // The igvm crate requires an SNP guest policy to compute the launch digest.
    let report = diff(
        &single_page(IgvmPlatformType::SEV_SNP, false, 1),
        &single_page(IgvmPlatformType::SEV_SNP, false, 2),
    )
    .unwrap();
    assert_eq!(report.measurement, "not_computed");
    let launch = report.launch_measurement.as_ref().unwrap();
    assert!(launch.before.igvm["sev-snp"].is_err());
    let text = report.to_string();
    assert!(
        text.contains(
            "  sev-snp launch digest, igvm crate:\n    not computed (no SNP guest policy found in initialization headers)\n"
        ),
        "{text}"
    );
}

fn build(platforms: &[(u32, IgvmPlatformType)], directives: Vec<D>) -> Vec<u8> {
    let platforms = platforms
        .iter()
        .map(|&(mask, platform_type)| {
            P::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
                compatibility_mask: mask,
                highest_vtl: 0,
                platform_type,
                platform_version: 1,
                shared_gpa_boundary: 0,
            })
        })
        .collect();
    let file = IgvmFile::new(IgvmRevision::V1, platforms, vec![], directives).unwrap();
    let mut out = Vec::new();
    file.serialize(&mut out).unwrap();
    out
}

fn data_page(gpa: u64, mask: u32, data_type: IgvmPageDataType, unmeasured: bool) -> D {
    D::PageData {
        gpa,
        compatibility_mask: mask,
        flags: IgvmPageDataFlags::new().with_unmeasured(unmeasured),
        data_type,
        data: if data_type == IgvmPageDataType::NORMAL {
            vec![7; 4096]
        } else {
            vec![]
        },
    }
}

#[test]
fn vbs_files_with_non_normal_pages_do_not_crash_the_measurement() {
    let vbs = [(1, IgvmPlatformType::VSM_ISOLATION)];
    let before = build(
        &vbs,
        vec![data_page(0x1000, 1, IgvmPageDataType::NORMAL, false)],
    );
    let after = build(
        &vbs,
        vec![
            data_page(0x1000, 1, IgvmPageDataType::NORMAL, false),
            data_page(0x2000, 1, IgvmPageDataType::SECRETS, false),
        ],
    );
    let report = diff(&before, &after).unwrap();
    let launch = report.launch_measurement.as_ref().unwrap();
    assert_eq!(
        launch.after.igvm["vbs"],
        Err("vbs page data with a non-normal page type".to_string())
    );
}

#[test]
fn vbs_measurement_work_is_bounded() {
    let vbs = [(1, IgvmPlatformType::VSM_ISOLATION)];
    let ranges = (0..4)
        .map(|index| D::ErrorRange {
            gpa: (index as u64) << 32,
            compatibility_mask: 1,
            size_bytes: u32::MAX,
        })
        .collect::<Vec<_>>();
    let mut directives = vec![data_page(0x1000, 1, IgvmPageDataType::NORMAL, false)];
    directives.extend(ranges);
    let bytes = build(&vbs, directives);
    let started = std::time::Instant::now();
    let report = diff(&bytes, &bytes).unwrap();
    assert!(started.elapsed().as_secs() < 5, "{:?}", started.elapsed());
    let launch = report.launch_measurement.as_ref().unwrap();
    assert_eq!(
        launch.before.igvm["vbs"],
        Err("more than 131072 pages to measure for vbs".to_string())
    );
}

#[test]
fn adding_an_unmeasured_page_is_reported_as_a_measurement_change() {
    let snp = [(1, IgvmPlatformType::SEV_SNP)];
    let before = build(
        &snp,
        vec![data_page(0x1000, 1, IgvmPageDataType::NORMAL, true)],
    );
    let after = build(
        &snp,
        vec![
            data_page(0x1000, 1, IgvmPageDataType::NORMAL, true),
            data_page(0x2000, 1, IgvmPageDataType::NORMAL, true),
        ],
    );
    let text = diff(&before, &after).unwrap().to_string();
    assert!(
        text.contains(
            "  Launch measurement changes [sev-snp] (from the computed digests below).\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("an unmeasured page's address still counts"),
        "{text}"
    );
}

#[test]
fn widening_a_page_mask_is_not_reported_as_a_measurement_change() {
    let platforms = [(1, IgvmPlatformType::SEV_SNP), (2, IgvmPlatformType::TDX)];
    let before = build(
        &platforms,
        vec![data_page(0x1000, 1, IgvmPageDataType::NORMAL, false)],
    );
    let after = build(
        &platforms,
        vec![data_page(0x1000, 3, IgvmPageDataType::NORMAL, false)],
    );
    let report = igvm_diff::diff_platform(&before, &after, Some("sev-snp")).unwrap();
    let text = report.to_string();
    assert!(
        text.contains(
            "  Launch measurement unchanged [sev-snp] (from the computed digests below).\n"
        ),
        "{text}"
    );
    assert!(!text.contains("The launch measurement changes"), "{text}");
}

#[test]
fn small_debug_data_only_sets_are_named_by_default() {
    let before = volume(&[driver(0xa2, "DebugOnly", 1, "/build/one/x.dll", b"code")]);
    let after = volume(&[driver(0xa2, "DebugOnly", 2, "/build/two/x.dll", b"code")]);
    let text = diff(&snp(&[(BASE, &before)]), &snp(&[(BASE, &after)]))
        .unwrap()
        .to_string();
    assert!(
        text.contains("  debug data only DXE (1): DebugOnly\n"),
        "{text}"
    );
}

/// A minimal PE with one `.cmdline` section holding `text`, and a SizeOfImage far larger than
/// the file, as in a Unified Kernel Image loaded into guest memory as a file.
fn uki(text: &[u8]) -> Vec<u8> {
    let raw = 0x200_usize;
    let mut image = vec![0; raw + 0x200];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x40_u32.to_le_bytes());
    image[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    image[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
    image[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
    image[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes());
    let optional = coff + 20;
    image[optional..optional + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
    image[optional + 56..optional + 60].copy_from_slice(&0x1000_0000_u32.to_le_bytes());
    image[optional + 60..optional + 64].copy_from_slice(&(raw as u32).to_le_bytes());
    let table = optional + 240;
    image[table..table + 8].copy_from_slice(b".cmdline");
    for (offset, value) in [(8, 0x200), (12, 0x1000), (16, 0x200), (20, raw)] {
        image[table + offset..table + offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
    image[raw..raw + text.len()].copy_from_slice(text);
    image
}

#[test]
fn unified_kernel_image_command_line_changes_are_shown() {
    let before = uki(b"console=ttyS0 roothash=aaaa ro");
    let after = uki(b"console=ttyS0 roothash=bbbb ro");
    let report = diff(
        &snp(&[(0x2000_0000, &before)]),
        &snp(&[(0x2000_0000, &after)]),
    )
    .unwrap();
    let component = &report.content.components[0];
    assert_eq!(component.after_format, Some(Format::Pe));
    assert_eq!(
        component.changed_sections.as_deref(),
        Some(&[".cmdline".to_string()][..])
    );
    let text = report.to_string();
    assert!(
        text.contains("changed PE sections: .cmdline\n    .cmdline: removed roothash=aaaa; added roothash=bbbb\n"),
        "{text}"
    );
}
