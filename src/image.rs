use std::collections::{BTreeMap, BTreeSet};

use igvm::{IgvmFile, registers::X86Register, snp_defs::SevVmsa};
use igvm_defs::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{Artifact, Error, MAX_FILE_SIZE, Record};

const MAX_RECORDS: usize = 32_768;
const MAX_REFERENCED_BYTES: u64 = 128 * 1024 * 1024;

pub(crate) struct Image {
    pub artifact: Artifact,
    pub records: Vec<Record>,
    pub unreferenced_sha256: String,
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn invalid(message: &str) -> Error {
    Error::Invalid(message.into())
}

fn read<T: FromBytes + KnownLayout + Immutable>(bytes: &[u8]) -> Result<T, Error> {
    T::read_from_bytes(bytes).map_err(|_| invalid("invalid record length"))
}

fn reserved(value: bool) -> Result<(), Error> {
    if value {
        return Err(Error::Unsupported(
            "nonzero reserved fields or flags".into(),
        ));
    }
    Ok(())
}

fn address(value: u64) -> String {
    format!("{value:#x}")
}

fn range(gpa: u64, size: u64) -> Result<(), Error> {
    gpa.checked_add(size)
        .ok_or_else(|| invalid("guest address range overflows"))?;
    Ok(())
}

fn platform_name(platform: IgvmPlatformType) -> Result<&'static str, Error> {
    match platform {
        IgvmPlatformType::NATIVE => Ok("native"),
        IgvmPlatformType::VSM_ISOLATION => Ok("vbs"),
        IgvmPlatformType::SEV_SNP => Ok("sev-snp"),
        IgvmPlatformType::TDX => Ok("tdx"),
        IgvmPlatformType::SEV => Ok("sev"),
        IgvmPlatformType::SEV_ES => Ok("sev-es"),
        _ => Err(Error::Unsupported(format!("platform type {}", platform.0))),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    data_start: usize,
    referenced_bytes: u64,
    payload_ranges: Vec<(usize, usize)>,
    platforms: BTreeMap<u32, &'static str>,
    parameters: BTreeMap<u32, u64>,
}

impl<'a> Reader<'a> {
    fn payload(&mut self, offset: u32, size: u64) -> Result<&'a [u8], Error> {
        self.referenced_bytes = self
            .referenced_bytes
            .checked_add(size)
            .filter(|size| *size <= MAX_REFERENCED_BYTES)
            .ok_or(Error::Limit(
                "more than 128 MiB of referenced or implicit payloads",
            ))?;
        if offset == 0 {
            return Ok(&[]);
        }
        let start = offset as usize;
        let end = u64::from(offset)
            .checked_add(size)
            .filter(|end| *end <= self.bytes.len() as u64)
            .ok_or_else(|| invalid("payload extends beyond the file"))? as usize;
        if start < self.data_start {
            return Err(invalid("payload points into the headers"));
        }
        if start < end {
            self.payload_ranges.push((start, end));
        }
        Ok(&self.bytes[start..end])
    }

    fn unreferenced_hash(&mut self, fixed_size: usize, header_start: usize) -> String {
        let mut hasher = Sha256::new();
        let gap = &self.bytes[fixed_size..header_start];
        hasher.update((gap.len() as u64).to_le_bytes());
        hasher.update(gap);
        self.payload_ranges.sort_unstable();
        let mut cursor = self.data_start;
        for &(start, end) in &self.payload_ranges {
            if start > cursor {
                hasher.update(&self.bytes[cursor..start]);
            }
            cursor = cursor.max(end);
        }
        hasher.update(&self.bytes[cursor..]);
        hex(&hasher.finalize())
    }

    fn vbs_context(&mut self, h: &IGVM_VHS_VP_CONTEXT) -> Result<(String, Value), Error> {
        if h.vp_index != 0 {
            return Err(Error::Unsupported(
                "VBS VP contexts for secondary processors".into(),
            ));
        }
        if h.gpa.get() != 0 || h.file_offset == 0 {
            return Err(invalid(
                "VBS context requires zero GPA and a stored payload",
            ));
        }
        let header: VbsVpContextHeader = read(self.payload(h.file_offset, 4)?)?;
        if header.register_count == 0 {
            return Err(invalid("VBS context has no registers"));
        }
        if header.register_count > 256 {
            return Err(Error::Limit("more than 256 VBS context registers"));
        }
        let offset = h
            .file_offset
            .checked_add(4)
            .ok_or_else(|| invalid("VBS payload offset overflows"))?;
        let registers = self.payload(offset, u64::from(header.register_count) * 32)?;
        let data = &self.bytes[h.file_offset as usize..offset as usize + registers.len()];
        let mut fields = json!({
            "gpa": "0x0", "vp_index": h.vp_index, "register_count": header.register_count,
            "payload_sha256": hash(data), "rip": null, "rsp": null,
            "cr0": null, "cr3": null, "cr4": null, "efer": null, "rflags": null, "pat": null
        });
        let mut names = BTreeSet::new();
        let mut vtl = None;
        for bytes in registers.as_chunks::<32>().0 {
            let reg: VbsVpContextRegister = read(bytes)?;
            reserved(reg.mbz != [0; 11])?;
            if reg.vtl > 2 || vtl.is_some_and(|v| v != reg.vtl) {
                return Err(invalid("VBS registers must use one valid VTL"));
            }
            vtl = Some(reg.vtl);
            if !names.insert(reg.register_name.get()) {
                return Err(invalid("duplicate VBS register"));
            }
            let decoded = X86Register::try_from(reg).map_err(|_| {
                Error::Unsupported(format!("VBS register {:#x}", reg.register_name.get()))
            })?;
            let (name, value) = match decoded {
                X86Register::Rip(v) => ("rip", v),
                X86Register::Rsp(v) => ("rsp", v),
                X86Register::Cr0(v) => ("cr0", v),
                X86Register::Cr3(v) => ("cr3", v),
                X86Register::Cr4(v) => ("cr4", v),
                X86Register::Efer(v) => ("efer", v),
                X86Register::Rflags(v) => ("rflags", v),
                X86Register::Pat(v) => ("pat", v),
                _ => continue,
            };
            fields[name] = json!(address(value));
        }
        let vtl = vtl.expect("nonempty register list");
        fields["vtl"] = json!(vtl);
        Ok((format!("{}/vtl{vtl}", h.vp_index), fields))
    }

    fn record(
        &mut self,
        typ: IgvmVariableHeaderType,
        body: &[u8],
        index: usize,
    ) -> Result<Record, Error> {
        use IgvmVariableHeaderType as T;

        let (kind, mask, identity, fields) = match typ {
            T::IGVM_VHT_SUPPORTED_PLATFORM => {
                let h: IGVM_VHS_SUPPORTED_PLATFORM = read(body)?;
                let name = platform_name(h.platform_type)?;
                if h.compatibility_mask.count_ones() != 1
                    || self.platforms.insert(h.compatibility_mask, name).is_some()
                {
                    return Err(invalid("platform masks must be distinct single bits"));
                }
                (
                    "supported_platform",
                    Some(h.compatibility_mask),
                    name.to_string(),
                    json!({
                        "platform": name, "version": h.platform_version,
                        "highest_vtl": h.highest_vtl, "shared_gpa_boundary": address(h.shared_gpa_boundary)
                    }),
                )
            }
            T::IGVM_VHT_GUEST_POLICY => {
                let h: IGVM_VHS_GUEST_POLICY = read(body)?;
                reserved(h.reserved != 0)?;
                (
                    "guest_policy",
                    Some(h.compatibility_mask),
                    String::new(),
                    json!({"policy": address(h.policy)}),
                )
            }
            T::IGVM_VHT_RELOCATABLE_REGION => {
                let h: IGVM_VHS_RELOCATABLE_REGION = read(body)?;
                reserved(h.flags & !7 != 0)?;
                if h.relocation_alignment == 0 || h.relocation_region_size == 0 {
                    return Err(invalid("relocation alignment and size must be nonzero"));
                }
                if h.minimum_relocation_gpa > h.maximum_relocation_gpa {
                    return Err(invalid("relocation minimum exceeds maximum"));
                }
                range(h.relocation_region_gpa, h.relocation_region_size)?;
                range(h.maximum_relocation_gpa, h.relocation_region_size)?;
                (
                    "relocatable_region",
                    Some(h.compatibility_mask),
                    address(h.relocation_region_gpa),
                    json!({
                        "gpa": address(h.relocation_region_gpa), "size": h.relocation_region_size,
                        "alignment": h.relocation_alignment,
                        "minimum_gpa": address(h.minimum_relocation_gpa), "maximum_gpa": address(h.maximum_relocation_gpa),
                        "vp_index": h.vp_index, "vtl": h.vtl, "is_vtl2": h.flags & 1 != 0,
                        "apply_rip_offset": h.flags & 2 != 0, "apply_gdtr_offset": h.flags & 4 != 0
                    }),
                )
            }
            T::IGVM_VHT_PAGE_TABLE_RELOCATION_REGION => {
                let h: IGVM_VHS_PAGE_TABLE_RELOCATION = read(body)?;
                reserved(h.reserved != 0)?;
                if h.size == 0 {
                    return Err(invalid("page-table relocation size must be nonzero"));
                }
                range(h.gpa, h.size)?;
                (
                    "page_table_relocation",
                    Some(h.compatibility_mask),
                    format!("{}/vtl{}", h.vp_index, h.vtl),
                    json!({"gpa": address(h.gpa), "size": h.size, "used_size": h.used_size, "vp_index": h.vp_index, "vtl": h.vtl}),
                )
            }
            T::IGVM_VHT_CORIM_DOCUMENT | T::IGVM_VHT_CORIM_SIGNATURE => {
                let h: IGVM_VHS_CORIM_DATA = read(body)?;
                reserved(h.reserved != 0)?;
                if h.file_offset == 0 || h.size_bytes == 0 {
                    return Err(invalid("CoRIM metadata requires a nonempty stored payload"));
                }
                let data = self.payload(h.file_offset, h.size_bytes.into())?;
                (
                    if typ == T::IGVM_VHT_CORIM_DOCUMENT {
                        "corim_document"
                    } else {
                        "corim_signature"
                    },
                    Some(h.compatibility_mask),
                    String::new(),
                    json!({"size": h.size_bytes, "payload_sha256": hash(data)}),
                )
            }
            T::IGVM_VHT_PAGE_DATA => {
                let h: IGVM_VHS_PAGE_DATA = read(body)?;
                reserved(h.reserved != 0 || h.flags.reserved() != 0)?;
                if h.flags.is_2mb_page() {
                    return Err(Error::Unsupported("2 MiB pages".into()));
                }
                range(h.gpa, 4096)?;
                let data = self.payload(h.file_offset, 4096)?;
                (
                    "page_data",
                    Some(h.compatibility_mask),
                    address(h.gpa),
                    json!({
                        "gpa": address(h.gpa), "size": 4096,
                        "data_type": h.data_type.0, "unmeasured": h.flags.unmeasured(),
                        "shared": h.flags.shared(), "data_present": h.file_offset != 0,
                        "payload_sha256": hash(data)
                    }),
                )
            }
            T::IGVM_VHT_PARAMETER_AREA => {
                let h: IGVM_VHS_PARAMETER_AREA = read(body)?;
                let data = self.payload(h.file_offset, h.number_of_bytes)?;
                self.parameters
                    .insert(h.parameter_area_index, h.number_of_bytes);
                (
                    "parameter_area",
                    None,
                    h.parameter_area_index.to_string(),
                    json!({
                        "parameter_area_index": h.parameter_area_index, "size": h.number_of_bytes,
                        "data_present": h.file_offset != 0, "payload_sha256": hash(data)
                    }),
                )
            }
            T::IGVM_VHT_PARAMETER_INSERT => {
                let h: IGVM_VHS_PARAMETER_INSERT = read(body)?;
                let size = self
                    .parameters
                    .get(&h.parameter_area_index)
                    .ok_or_else(|| invalid("parameter insert references an undefined area"))?;
                range(h.gpa, *size)?;
                (
                    "parameter_insert",
                    Some(h.compatibility_mask),
                    h.parameter_area_index.to_string(),
                    json!({
                        "gpa": address(h.gpa), "parameter_area_index": h.parameter_area_index
                    }),
                )
            }
            T::IGVM_VHT_VP_CONTEXT => {
                let h: IGVM_VHS_VP_CONTEXT = read(body)?;
                reserved(h.reserved != 0)?;
                let platform = self
                    .platforms
                    .get(&h.compatibility_mask)
                    .copied()
                    .ok_or_else(|| invalid("VP context must reference one defined platform"))?;
                if !matches!(platform, "sev-snp" | "sev-es" | "native" | "sev" | "vbs") {
                    return Err(Error::Unsupported(format!("{platform} VP context")));
                }
                if platform == "vbs" {
                    let (identity, fields) = self.vbs_context(&h)?;
                    return Ok(Record {
                        index,
                        kind: "vp_context",
                        platforms: vec![platform.into()],
                        compatibility_mask: Some(h.compatibility_mask),
                        identity,
                        fields,
                    });
                }
                if h.file_offset == 0 {
                    return Err(invalid("VP context has no payload"));
                }
                let data = self.payload(h.file_offset, 4096)?;
                let gpa = h.gpa.get();
                range(gpa, 4096)?;
                let mut fields = json!({
                    "gpa": address(gpa), "vp_index": h.vp_index, "payload_sha256": hash(data)
                });
                if matches!(platform, "sev-snp" | "sev-es") {
                    let vmsa: SevVmsa = read(data)?;
                    let features: u64 = vmsa.sev_features.into();
                    let nonce: u64 = read(&data[0x300..0x308])?;
                    if features & (1 << 14) != 0 && nonce != 0 {
                        return Err(Error::Unsupported(
                            "VMSA register protection with a nonzero REG_PROT_NONCE".into(),
                        ));
                    }
                    let object = fields.as_object_mut().expect("object literal");
                    for (name, value) in [
                        ("rip", vmsa.rip),
                        ("rsp", vmsa.rsp),
                        ("cr0", vmsa.cr0),
                        ("cr3", vmsa.cr3),
                        ("cr4", vmsa.cr4),
                        ("efer", vmsa.efer),
                        ("rflags", vmsa.rflags),
                        ("pat", vmsa.pat),
                        ("sev_features", vmsa.sev_features.into()),
                    ] {
                        object.insert(name.into(), json!(address(value)));
                    }
                    object.insert("vmpl".into(), json!(vmsa.vmpl));
                }
                (
                    "vp_context",
                    Some(h.compatibility_mask),
                    h.vp_index.to_string(),
                    fields,
                )
            }
            T::IGVM_VHT_REQUIRED_MEMORY => {
                let h: IGVM_VHS_REQUIRED_MEMORY = read(body)?;
                reserved(h.reserved != 0 || h.flags.reserved() != 0)?;
                range(h.gpa, h.number_of_bytes.into())?;
                (
                    "required_memory",
                    Some(h.compatibility_mask),
                    address(h.gpa),
                    json!({
                        "gpa": address(h.gpa), "size": h.number_of_bytes,
                        "vtl2_protectable": h.flags.vtl2_protectable()
                    }),
                )
            }
            T::IGVM_VHT_ERROR_RANGE => {
                let h: IGVM_VHS_ERROR_RANGE = read(body)?;
                range(h.gpa, h.size_bytes.into())?;
                (
                    "error_range",
                    Some(h.compatibility_mask),
                    address(h.gpa),
                    json!({
                        "gpa": address(h.gpa), "size": h.size_bytes
                    }),
                )
            }
            T::IGVM_VHT_SNP_ID_BLOCK => {
                let h: IGVM_VHS_SNP_ID_BLOCK = read(body)?;
                reserved(h.reserved != [0; 3])?;
                (
                    "snp_id_block",
                    Some(h.compatibility_mask),
                    String::new(),
                    json!({
                        "author_key_enabled": h.author_key_enabled, "version": h.version,
                        "guest_svn": h.guest_svn, "id_key_algorithm": h.id_key_algorithm,
                        "author_key_algorithm": h.author_key_algorithm,
                        "launch_digest": hex(&h.ld), "family_id": hex(&h.family_id), "image_id": hex(&h.image_id),
                        "id_key_signature_sha256": hash(h.id_key_signature.as_bytes()),
                        "id_public_key_sha256": hash(h.id_public_key.as_bytes()),
                        "author_key_signature_sha256": hash(h.author_key_signature.as_bytes()),
                        "author_public_key_sha256": hash(h.author_public_key.as_bytes())
                    }),
                )
            }
            T::IGVM_VHT_VBS_MEASUREMENT => {
                let h: IGVM_VHS_VBS_MEASUREMENT = read(body)?;
                (
                    "vbs_measurement",
                    Some(h.compatibility_mask),
                    String::new(),
                    json!({
                        "version": h.version, "product_id": h.product_id, "module_id": h.module_id,
                        "security_version": h.security_version, "policy_flags": h.policy_flags,
                        "boot_digest_algo": h.boot_digest_algo, "signing_algo": h.signing_algo,
                        "boot_measurement_digest": hex(&h.boot_measurement_digest),
                        "signature_sha256": hash(&h.signature), "public_key_sha256": hash(&h.public_key)
                    }),
                )
            }
            _ => {
                let kind = match typ {
                    T::IGVM_VHT_VP_COUNT_PARAMETER => "vp_count",
                    T::IGVM_VHT_ENVIRONMENT_INFO_PARAMETER => "environment_info",
                    T::IGVM_VHT_SRAT => "srat",
                    T::IGVM_VHT_MADT => "madt",
                    T::IGVM_VHT_SLIT => "slit",
                    T::IGVM_VHT_PPTT => "pptt",
                    T::IGVM_VHT_MMIO_RANGES => "mmio_ranges",
                    T::IGVM_VHT_MEMORY_MAP => "memory_map",
                    T::IGVM_VHT_COMMAND_LINE => "command_line",
                    T::IGVM_VHT_DEVICE_TREE => "device_tree",
                    _ => {
                        let name = match typ.0 {
                            0x106 => "CCA policy",
                            0x107 => "version string",
                            _ => "unknown record",
                        };
                        return Err(Error::Unsupported(format!(
                            "{name} (record type {:#x} at index {index})",
                            typ.0
                        )));
                    }
                };
                let h: IGVM_VHS_PARAMETER = read(body)?;
                let size = self
                    .parameters
                    .get(&h.parameter_area_index)
                    .ok_or_else(|| invalid("parameter references an undefined area"))?;
                if u64::from(h.byte_offset) >= *size {
                    return Err(invalid("parameter offset is outside its area"));
                }
                (
                    kind,
                    None,
                    h.parameter_area_index.to_string(),
                    json!({
                        "parameter_area_index": h.parameter_area_index, "byte_offset": h.byte_offset
                    }),
                )
            }
        };
        let mut platforms = Vec::new();
        if let Some(mask) = mask {
            let defined = self.platforms.keys().fold(0, |bits, bit| bits | bit);
            if mask & defined == 0 {
                return Err(invalid(
                    "record references an undefined or empty platform mask",
                ));
            }
            for (&bit, &name) in &self.platforms {
                if mask & bit != 0 {
                    platforms.push(name.to_string());
                }
            }
            platforms.sort();
        }
        Ok(Record {
            index,
            kind,
            platforms,
            compatibility_mask: mask,
            identity,
            fields,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Image, Error> {
    if bytes.len() > MAX_FILE_SIZE {
        return Err(Error::Limit("file is larger than 64 MiB"));
    }
    if cfg!(target_endian = "big") {
        return Err(Error::Unsupported("big-endian hosts".into()));
    }
    let fixed = bytes
        .get(..size_of::<IGVM_FIXED_HEADER>())
        .ok_or_else(|| invalid("truncated fixed header"))?;
    let h: IGVM_FIXED_HEADER = read(fixed)?;
    if h.magic != IGVM_MAGIC_VALUE || h.total_file_size as usize != bytes.len() {
        return Err(invalid("bad magic or file size"));
    }
    let fixed_size = match h.format_version {
        1 => size_of::<IGVM_FIXED_HEADER>(),
        2 => {
            let v2: IGVM_FIXED_HEADER_V2 = read(
                bytes
                    .get(..size_of::<IGVM_FIXED_HEADER_V2>())
                    .ok_or_else(|| invalid("truncated v2 fixed header"))?,
            )?;
            if v2.architecture != IgvmArchitecture::X64 || v2.page_size != 4096 {
                return Err(Error::Unsupported(
                    "only x64 with 4 KiB pages is supported".into(),
                ));
            }
            size_of::<IGVM_FIXED_HEADER_V2>()
        }
        version => return Err(Error::Unsupported(format!("format version {version}"))),
    };
    let start = h.variable_header_offset as usize;
    let end = start
        .checked_add(h.variable_header_size as usize)
        .filter(|end| *end < bytes.len())
        .ok_or_else(|| invalid("variable headers extend beyond the file"))?;
    if start < fixed_size || !start.is_multiple_of(8) || !h.variable_header_size.is_multiple_of(8) {
        return Err(invalid("invalid variable header offset or alignment"));
    }
    let mut reader = Reader {
        bytes,
        data_start: end,
        referenced_bytes: 0,
        payload_ranges: Vec::new(),
        platforms: BTreeMap::new(),
        parameters: BTreeMap::new(),
    };
    let mut records = Vec::new();
    let mut cursor = start;
    // Bound allocations and payload offsets before passing untrusted bytes to igvm.
    while cursor < end {
        if records.len() == MAX_RECORDS {
            return Err(Error::Limit("more than 32768 records"));
        }
        let prefix_end = cursor
            .checked_add(8)
            .filter(|offset| *offset <= end)
            .ok_or_else(|| invalid("truncated variable header"))?;
        let header: IGVM_VHS_VARIABLE_HEADER = read(&bytes[cursor..prefix_end])?;
        let body_end = prefix_end
            .checked_add(header.length as usize)
            .filter(|offset| *offset <= end)
            .ok_or_else(|| invalid("truncated record body"))?;
        let next = body_end
            .checked_add(7)
            .map(|offset| offset & !7)
            .filter(|offset| *offset <= end)
            .ok_or_else(|| invalid("truncated record padding"))?;
        reserved(bytes[body_end..next].iter().any(|byte| *byte != 0))?;
        let index = records.len();
        records.push(
            reader
                .record(header.typ, &bytes[prefix_end..body_end], index)
                .map_err(|source| Error::Record {
                    index,
                    source: Box::new(source),
                })?,
        );
        cursor = next;
    }
    IgvmFile::new_from_binary(bytes, None)?;
    Ok(Image {
        artifact: Artifact {
            sha256: hash(bytes),
            size: bytes.len(),
            format_version: h.format_version,
            record_count: records.len(),
        },
        records,
        unreferenced_sha256: reader.unreferenced_hash(fixed_size, start),
    })
}
