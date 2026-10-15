use igvm_diff::{ChangeKind, Record, Report, diff};
use serde_json::json;
use sha2::{Digest, Sha256};

// Encode specification offsets directly, independently of igvm's structs and serializer.
// Sources and interpretation limits are recorded in docs/mappings.md.
struct Header {
    typ: u32,
    body: Vec<u8>,
    data: Option<(usize, Vec<u8>)>,
}

impl Header {
    fn new(typ: u32, size: usize, fields: &[(usize, usize, u64)]) -> Self {
        let mut body = vec![0; size];
        for &(offset, width, value) in fields {
            put(&mut body, offset, width, value);
        }
        Self {
            typ,
            body,
            data: None,
        }
    }

    fn data(mut self, offset: usize, bytes: Vec<u8>) -> Self {
        self.data = Some((offset, bytes));
        self
    }
}

fn put(bytes: &mut [u8], offset: usize, width: usize, value: u64) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

fn image(platform: u8, records: Vec<Header>) -> Vec<u8> {
    let mut headers = vec![Header::new(
        1,
        16,
        &[(0, 4, 1), (5, 1, platform.into()), (6, 2, 1)],
    )];
    headers.extend(records);
    headers.push(page(0, 0).data(12, vec![0xa5; 4096]));
    let header_size: usize = headers
        .iter()
        .map(|h| (8 + h.body.len()).next_multiple_of(8))
        .sum();
    let mut bytes = vec![0; 32];
    let mut data = Vec::new();
    for mut header in headers {
        if let Some((offset, payload)) = header.data {
            put(
                &mut header.body,
                offset,
                4,
                (32 + header_size + data.len()) as u64,
            );
            data.extend(payload);
        }
        bytes.extend(header.typ.to_le_bytes());
        bytes.extend((header.body.len() as u32).to_le_bytes());
        bytes.extend(header.body);
        bytes.resize(bytes.len().next_multiple_of(8), 0);
    }
    let total = bytes.len() + data.len();
    for (offset, value) in [
        (0, 0x4d564749),
        (4, 2),
        (8, 32),
        (12, header_size as u64),
        (16, total as u64),
        (28, 4096),
    ] {
        put(&mut bytes, offset, 4, value);
    }
    let checksum = crc32fast::hash(&bytes);
    put(&mut bytes, 20, 4, checksum.into());
    bytes.extend(data);
    bytes
}

fn page(typ: u16, flags: u32) -> Header {
    Header::new(
        0x302,
        24,
        &[
            (0, 8, 0x2000),
            (8, 4, 1),
            (16, 4, flags.into()),
            (20, 2, typ.into()),
        ],
    )
}

fn vmsa(platform: u8, fields: &[(usize, usize, u64)]) -> Vec<u8> {
    let mut data = vec![0; 4096];
    for &(offset, width, value) in fields {
        put(&mut data, offset, width, value);
    }
    image(
        platform,
        vec![Header::new(0x304, 20, &[(0, 8, 0x3000), (8, 4, 1), (16, 2, 7)]).data(12, data)],
    )
}

fn added(platform: u8, headers: Vec<Header>) -> Report {
    diff(&image(platform, vec![]), &image(platform, headers)).unwrap()
}

fn record(report: &Report, kind: &str) -> Record {
    let changes: Vec<_> = report
        .findings
        .iter()
        .filter(|c| c.after.as_ref().is_some_and(|r| r.kind == kind))
        .collect();
    assert_eq!(changes.len(), 1, "{kind}: {report:#}");
    assert_eq!(changes[0].kind, ChangeKind::Added);
    changes[0].after.clone().unwrap()
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn every_cpu_feature_bit_matches_the_amd_tables_in_both_directions() {
    let registers = [
        (
            "efer",
            0xd0,
            "§3.1.7",
            &[
                (0, "SCE"),
                (8, "LME"),
                (10, "LMA"),
                (11, "NXE"),
                (12, "SVME"),
                (13, "LMSLE"),
                (14, "FFXSR"),
                (15, "TCE"),
                (17, "MCOMMIT"),
                (18, "INTWB"),
                (20, "UAIE"),
                (21, "AIBRSE"),
                (24, "EnhancedTlbi"),
            ][..],
        ),
        (
            "sev_features",
            0x3b0,
            "Table B-4",
            &[
                (0, "SNPActive"),
                (1, "vTOM"),
                (2, "ReflectVC"),
                (3, "RestrictedInjection"),
                (4, "AlternateInjection"),
                (5, "DebugVirtualization"),
                (6, "PreventHostIBS"),
                (7, "BTBIsolation"),
                (8, "VmplSSS"),
                (9, "SecureTSC"),
                (10, "VmgexitParameter"),
                (11, "PmcVirtualization"),
                (12, "IbsVirtualization"),
                (13, "GuestInterceptCtl"),
                (14, "VmsaRegProt"),
                (15, "SmtProtection"),
                (16, "SecureAvic"),
                (21, "IbpbOnEntry"),
            ][..],
        ),
    ];
    let zero = vmsa(2, &[]);
    for (field, offset, reference, known) in registers {
        for bit in 0..64 {
            let mask = 1_u64 << bit;
            let set = vmsa(2, &[(offset, 8, mask)]);
            for (before, after, setting) in [(&zero, &set, true), (&set, &zero, false)] {
                let report = diff(before, after).unwrap();
                assert_eq!(report.findings.len(), 1);
                let change = &report.findings[0];
                assert!(change.fields.iter().any(|f| f == field));
                assert_eq!(
                    change.after.as_ref().unwrap().fields[field],
                    format!("{:#x}", if setting { mask } else { 0 })
                );
                let text = report.to_string();
                if let Some((_, mnemonic)) = known.iter().find(|(b, _)| *b == bit) {
                    let status = (field == "efer" && matches!(bit, 8 | 10))
                        || (field == "sev_features" && bit == 0);
                    let state = match (status, setting) {
                        (true, true) => "set",
                        (true, false) => "cleared",
                        (false, true) => "enabled",
                        (false, false) => "disabled",
                    };
                    assert!(
                        text.contains(&format!("{mnemonic}) {state}"))
                            || text.contains(&format!("{mnemonic} {state}")),
                        "{field}[{bit}]: {text}"
                    );
                    assert!(!text.contains("undecoded"), "{field}[{bit}]: {text}");
                } else {
                    let state = if setting { "set" } else { "cleared" };
                    assert!(
                        text.contains(&format!("undecoded bits {state}: {mask:#x}")),
                        "{field}[{bit}]: {text}"
                    );
                }
                assert!(text.contains(reference));
                assert!(text.contains("https://docs.amd.com/v/u/en-US/24593_3.45_APM_Vol2_PUB"));
                assert!(!text.contains("build is safe"));
            }
        }
    }
}

#[test]
fn every_displayed_vmsa_register_matches_its_documented_byte_offset() {
    let fields = [
        ("vmpl", 0xca, 1, 3),
        ("efer", 0xd0, 8, 0x1800),
        ("cr4", 0x148, 8, 0x123456789abcdef0),
        ("cr3", 0x150, 8, 0x123456789abc0018),
        ("cr0", 0x158, 8, 0x87654321),
        ("rflags", 0x170, 8, 0x202),
        ("rip", 0x178, 8, 0xfedcba9876543210),
        ("rsp", 0x1d8, 8, 0x123456789abc0000),
        ("pat", 0x268, 8, 0x0007040600070406),
        ("sev_features", 0x3b0, 8, 0x29),
    ];
    for platform in [2, 5] {
        let before = vmsa(platform, &[]);
        for (field, offset, width, value) in fields {
            let after = vmsa(platform, &[(offset, width, value)]);
            for (a, b, expected) in [(&before, &after, value), (&after, &before, 0)] {
                let report = diff(a, b).unwrap();
                assert_eq!(report.findings.len(), 1);
                let change = &report.findings[0];
                let mut changed = vec![field, "payload_sha256"];
                changed.sort();
                assert_eq!(change.fields, changed, "{platform}/{field}");
                let actual = &change.after.as_ref().unwrap().fields[field];
                assert_eq!(
                    *actual,
                    if width == 1 {
                        json!(expected)
                    } else {
                        json!(format!("{expected:#x}"))
                    }
                );
                assert_eq!(change.after.as_ref().unwrap().identity, "7");
                if field == "cr3" {
                    assert!(report.to_string().contains("Page-table control (CR3)"));
                }
            }
        }
    }
}

#[test]
fn obfuscated_vmsa_registers_are_never_reported_as_plain_cpu_settings() {
    for platform in [2, 5] {
        let zero_nonce = vmsa(platform, &[(0x3b0, 8, 1 << 14), (0x178, 8, 0x1234)]);
        assert!(diff(&zero_nonce, &zero_nonce).is_ok());
        let inactive = vmsa(platform, &[(0x300, 8, u64::MAX)]);
        assert!(diff(&inactive, &inactive).is_ok());
        for byte in 0..8 {
            let protected = vmsa(platform, &[(0x3b0, 8, 1 << 14), (0x300 + byte, 1, 1)]);
            for (a, b, side) in [
                (&protected, &zero_nonce, "before"),
                (&zero_nonce, &protected, "after"),
            ] {
                let error = diff(a, b).unwrap_err().to_string();
                assert!(error.contains(side));
                assert!(
                    error.contains(
                        "unsupported IGVM: VMSA register protection with a nonzero REG_PROT_NONCE"
                    ),
                    "{error}"
                );
            }
        }
    }
}

#[test]
fn context_layout_is_selected_by_platform() {
    for platform in [0, 4] {
        let mut data = vec![0; 4096];
        data[0] = 0x42;
        let context = Header::new(0x304, 20, &[(8, 4, 1), (16, 2, 7)]).data(12, data.clone());
        let report = added(platform, vec![context]);
        let r = record(&report, "vp_context");
        assert_eq!(
            r.fields,
            json!({"gpa": "0x0", "vp_index": 7, "payload_sha256": hash(&data)})
        );
        assert!(!report.to_string().contains("EFER:"));
    }
    for (platform, name) in [(1, "vbs"), (3, "tdx")] {
        let error = diff(&vmsa(platform, &[]), &image(platform, vec![]))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&format!("unsupported IGVM: {name} VP context")),
            "{error}"
        );
    }
}

#[test]
fn platform_values_and_platform_fields_keep_their_specification_meaning() {
    for (typ, name) in [
        (0, "native"),
        (1, "vbs"),
        (2, "sev-snp"),
        (3, "tdx"),
        (4, "sev"),
        (5, "sev-es"),
    ] {
        let before = if typ == 2 { 0 } else { 2 };
        let report = diff(&image(before, vec![]), &image(typ, vec![])).unwrap();
        let r = record(&report, "supported_platform");
        assert_eq!(r.platforms, [name]);
        assert_eq!(r.identity, name);
        assert_eq!(r.compatibility_mask, Some(1));
        assert_eq!(
            r.fields,
            json!({"platform": name, "version": 1, "highest_vtl": 0, "shared_gpa_boundary": "0x0"})
        );
    }
    for typ in [6, 255] {
        assert!(
            diff(&image(typ, vec![]), &image(2, vec![]))
                .unwrap_err()
                .to_string()
                .contains("unsupported IGVM: platform type")
        );
    }
    for (platform, vtl, boundary) in [(1, 2, 0), (2, 0, 0x400000000000)] {
        let mut changed = image(platform, vec![]);
        changed[44] = vtl;
        put(&mut changed, 48, 8, boundary);
        put(&mut changed, 20, 4, 0);
        let end = 32 + u32::from_le_bytes(changed[12..16].try_into().unwrap()) as usize;
        let crc = crc32fast::hash(&changed[..end]);
        put(&mut changed, 20, 4, crc.into());
        let report = diff(&image(platform, vec![]), &changed).unwrap();
        let r = report.findings[0].after.as_ref().unwrap();
        assert_eq!(r.fields["highest_vtl"], vtl);
        assert_eq!(r.fields["shared_gpa_boundary"], format!("{boundary:#x}"));
    }
}

#[test]
fn page_types_flags_and_storage_are_independent() {
    for (typ, name) in [(0, "normal"), (1, "secrets"), (2, "CPUID"), (3, "CPUID XF")] {
        for flags in [0, 2, 4, 6] {
            for stored in [false, true] {
                let mut p = page(typ, flags);
                put(&mut p.body, 0, 8, 0x5000);
                if stored {
                    p = p.data(12, vec![0x5a; 4096]);
                }
                let report = added(2, vec![p]);
                let r = record(&report, "page_data");
                assert_eq!(r.identity, "0x5000");
                assert_eq!(
                    r.fields,
                    json!({
                        "gpa": "0x5000", "size": 4096, "data_type": typ,
                        "unmeasured": flags & 2 != 0, "shared": flags & 4 != 0,
                        "data_present": stored, "payload_sha256": hash(if stored { &[0x5a; 4096] } else { &[] }),
                    })
                );
                let text = report.to_string();
                if typ == 0 && flags == 0 && stored {
                    assert!(text.contains("0x5000..0x6000: 1 page, added [sev-snp]"));
                } else {
                    assert!(text.contains(&format!("({name},")), "{text}");
                }
            }
        }
    }
    for bit in 0..32 {
        if matches!(bit, 1 | 2) {
            continue;
        }
        let error = diff(&image(2, vec![page(0, 1 << bit)]), &image(2, vec![]))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(if bit == 0 {
                "2 MiB pages"
            } else {
                "reserved fields or flags"
            }),
            "{bit}: {error}"
        );
    }
    for typ in [4, u16::MAX] {
        assert!(diff(&image(2, vec![page(typ, 0)]), &image(2, vec![])).is_err());
    }
}

#[test]
fn parameter_record_numbers_map_to_the_correct_parameter_kind() {
    for (typ, kind, label) in [
        (0x307, "vp_count", "Processor count parameter"),
        (0x308, "srat", "SRAT table parameter"),
        (0x309, "madt", "Interrupt-controller table parameter (MADT)"),
        (0x30a, "mmio_ranges", "MMIO ranges parameter"),
        (0x30c, "memory_map", "Memory map parameter"),
        (0x30e, "command_line", "Command line parameter"),
        (0x30f, "slit", "SLIT table parameter"),
        (0x310, "pptt", "PPTT table parameter"),
        (0x312, "device_tree", "Device tree parameter"),
        (
            0x313,
            "environment_info",
            "Environment information parameter",
        ),
    ] {
        let report = added(
            2,
            vec![
                Header::new(0x301, 16, &[(0, 8, 4096), (8, 4, 9)]).data(12, vec![0x5a; 4096]),
                Header::new(typ, 8, &[(0, 4, 9), (4, 4, 128)]),
                Header::new(0x303, 16, &[(0, 8, 0x12345678000), (8, 4, 1), (12, 4, 9)]),
            ],
        );
        let r = record(&report, kind);
        assert_eq!(r.identity, "9");
        assert_eq!(r.compatibility_mask, None);
        assert!(r.platforms.is_empty());
        assert_eq!(
            r.fields,
            json!({"parameter_area_index": 9, "byte_offset": 128})
        );
        assert!(report.to_string().contains(label));
        assert_eq!(
            record(&report, "parameter_area").fields,
            json!({
                "parameter_area_index": 9, "size": 4096, "data_present": true, "payload_sha256": hash(&[0x5a; 4096]),
            })
        );
        assert_eq!(
            record(&report, "parameter_insert").fields,
            json!({"parameter_area_index": 9, "gpa": "0x12345678000"})
        );
    }
}

#[test]
fn policy_memory_requirements_and_error_ranges_preserve_all_fields() {
    let report = added(
        2,
        vec![
            Header::new(0x101, 16, &[(0, 8, 0x123456789abcdef0), (8, 4, 1)]),
            Header::new(
                0x305,
                24,
                &[(0, 8, 0x123400000000), (8, 4, 1), (12, 4, 8192), (16, 4, 1)],
            ),
            Header::new(
                0x30d,
                16,
                &[(0, 8, 0x567800000000), (8, 4, 1), (12, 4, 12288)],
            ),
        ],
    );
    assert_eq!(
        record(&report, "guest_policy").fields,
        json!({"policy": "0x123456789abcdef0"})
    );
    assert_eq!(
        record(&report, "required_memory").fields,
        json!({"gpa": "0x123400000000", "size": 8192, "vtl2_protectable": true})
    );
    assert_eq!(
        record(&report, "error_range").fields,
        json!({"gpa": "0x567800000000", "size": 12288})
    );
    for bit in 1..32 {
        let h = Header::new(
            0x305,
            24,
            &[(0, 8, 0x3000), (8, 4, 1), (12, 4, 4096), (16, 4, 1 << bit)],
        );
        assert!(
            diff(&image(2, vec![h]), &image(2, vec![]))
                .unwrap_err()
                .to_string()
                .contains("reserved fields or flags")
        );
    }
}

#[test]
fn snp_identity_fields_and_each_key_or_signature_use_the_correct_bytes() {
    let mut h = Header::new(
        0x30b,
        696,
        &[
            (0, 4, 1),
            (4, 1, 1),
            (88, 4, 2),
            (92, 4, 3),
            (96, 4, 4),
            (100, 4, 5),
        ],
    );
    for (start, end, byte) in [
        (8, 56, 0x11),
        (56, 72, 0x22),
        (72, 88, 0x33),
        (104, 248, 0x44),
        (248, 400, 0x55),
        (400, 544, 0x66),
        (544, 696, 0x77),
    ] {
        h.body[start..end].fill(byte);
    }
    let report = added(2, vec![h]);
    assert_eq!(
        record(&report, "snp_id_block").fields,
        json!({
            "author_key_enabled": 1, "version": 2, "guest_svn": 3, "id_key_algorithm": 4, "author_key_algorithm": 5,
            "launch_digest": "11".repeat(48), "family_id": "22".repeat(16), "image_id": "33".repeat(16),
            "id_key_signature_sha256": hash(&[0x44; 144]), "id_public_key_sha256": hash(&[0x55; 152]),
            "author_key_signature_sha256": hash(&[0x66; 144]), "author_public_key_sha256": hash(&[0x77; 152]),
        })
    );
    assert_eq!(report.measurement, "not_requested");
}

#[test]
fn vbs_measurement_fields_keep_digests_signatures_and_keys_separate() {
    let mut h = Header::new(
        0x311,
        864,
        &[
            (0, 4, 1),
            (4, 4, 2),
            (8, 4, 3),
            (12, 4, 4),
            (16, 4, 5),
            (20, 4, 6),
            (24, 4, 7),
            (28, 4, 8),
        ],
    );
    h.body[32..96].fill(0x11);
    h.body[96..352].fill(0x22);
    h.body[352..864].fill(0x33);
    let report = added(1, vec![h]);
    assert_eq!(
        record(&report, "vbs_measurement").fields,
        json!({
            "version": 2, "product_id": 3, "module_id": 4, "security_version": 5,
            "policy_flags": 6, "boot_digest_algo": 7, "signing_algo": 8,
            "boot_measurement_digest": "11".repeat(64), "signature_sha256": hash(&[0x22; 256]), "public_key_sha256": hash(&[0x33; 512]),
        })
    );
    assert_eq!(report.measurement, "not_requested");
}
