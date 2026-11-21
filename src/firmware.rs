//! UEFI firmware volume decoding (PI specification, volume 3) and module comparison.

use std::{collections::BTreeMap, io};

use serde::Serialize;
use sha2::{Digest, Sha256};

const FFS2: [u8; 16] = guid_bytes(
    0x8c8ce578,
    0x8a3d,
    0x4f1c,
    [0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3],
);
const FFS3: [u8; 16] = guid_bytes(
    0x5473c07a,
    0x3dcb,
    0x4dca,
    [0xbd, 0x6f, 0x1e, 0x96, 0x89, 0xe7, 0x34, 0x9a],
);
/// EDK2 `LzmaCustomDecompressGuid`.
const LZMA: [u8; 16] = guid_bytes(
    0xee4e5898,
    0x3914,
    0x4259,
    [0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf],
);

/// `gEfiFirmwareVolumeTopFileGuid` (EDK2 MdePkg.dec): the Volume Top File, which holds the x86
/// reset vector (FILE_GUID of OvmfPkg/ResetVector and UefiCpuPkg/ResetVector/Vtf0).
const VOLUME_TOP_FILE: [u8; 16] = guid_bytes(
    0x1ba0062e,
    0xc779,
    0x4582,
    [0x85, 0x66, 0x33, 0x6a, 0xe8, 0xf7, 0x8f, 0x09],
);
/// `gEfiSystemNvDataFvGuid` (EDK2 MdeModulePkg.dec): the file system GUID of a UEFI variable
/// store volume.
const SYSTEM_NV_DATA: [u8; 16] = guid_bytes(
    0xfff12b8d,
    0x7696,
    0x4c8b,
    [0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50],
);

/// `gEfiCrc32GuidedSectionExtractionGuid` (EDK2 MdeModulePkg.dec): its header holds a CRC32 of
/// the payload, so the header carries no information beyond the payload itself.
const CRC32_GUIDED: [u8; 16] = guid_bytes(
    0xfc1bcdb0,
    0x7d31,
    0x49aa,
    [0x93, 0x6a, 0xa4, 0x60, 0x0d, 0x9d, 0xd0, 0x83],
);

const MAX_DEPTH: usize = 8;
const MAX_FILES: usize = 16_384;
const MAX_DECOMPRESSED: usize = 128 * 1024 * 1024;

const FILE_RAW: u8 = 0x01;
const FILE_PAD: u8 = 0xf0;
const SECTION_COMPRESSION: u8 = 0x01;
const SECTION_GUID_DEFINED: u8 = 0x02;
const SECTION_PE32: u8 = 0x10;
const SECTION_USER_INTERFACE: u8 = 0x15;
const SECTION_FIRMWARE_VOLUME: u8 = 0x17;
const GUIDED_PROCESSING_REQUIRED: u16 = 0x01;

const fn guid_bytes(a: u32, b: u16, c: u16, d: [u8; 8]) -> [u8; 16] {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

fn guid(bytes: &[u8]) -> String {
    let a = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes"));
    let b = u16::from_le_bytes(bytes[4..6].try_into().expect("2 bytes"));
    let c = u16::from_le_bytes(bytes[6..8].try_into().expect("2 bytes"));
    let d: String = bytes[8..10].iter().map(|x| format!("{x:02x}")).collect();
    let e: String = bytes[10..16].iter().map(|x| format!("{x:02x}")).collect();
    format!("{a:08x}-{b:04x}-{c:04x}-{d}-{e}")
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn u24_at(data: &[u8], offset: usize) -> Option<usize> {
    let b = data.get(offset..offset.checked_add(3)?)?;
    Some(usize::from(b[0]) | usize::from(b[1]) << 8 | usize::from(b[2]) << 16)
}

fn align(value: usize, to: usize) -> Option<usize> {
    value.checked_add(to - 1).map(|v| v & !(to - 1))
}

/// Returns the length of a firmware volume header at the start of `data`, if one is present
/// and fits.
pub(crate) fn volume_length(data: &[u8]) -> Option<usize> {
    if data.get(40..44)? != b"_FVH" {
        return None;
    }
    let length = usize::try_from(u64_at(data, 32)?).ok()?;
    let header = usize::from(u16_at(data, 48)?);
    (header >= 56 && header <= length && length <= data.len()).then_some(length)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleChangeKind {
    Modified,
    /// Only PE/COFF timestamps, the optional-header checksum and CodeView debug data differ.
    DebugDataOnly,
    Added,
    Removed,
}

/// FFS file types (`EFI_FV_FILETYPE_*`, UEFI PI specification volume 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    SecurityCore,
    PeiCore,
    Peim,
    CombinedPeimDriver,
    DxeCore,
    Driver,
    CombinedMmDxe,
    Mm,
    MmCore,
    MmStandalone,
    MmCoreStandalone,
    Application,
    FirmwareVolumeImage,
    Freeform,
    Raw,
    Other,
    /// A firmware volume that does not use a firmware file system, such as a variable store.
    NonFfsVolume,
    /// Bytes of a firmware volume outside its files: headers, alignment, pad files, free space.
    VolumeData,
}

impl FileType {
    fn from_byte(value: u8) -> Self {
        match value {
            0x01 => FileType::Raw,
            0x02 => FileType::Freeform,
            0x03 => FileType::SecurityCore,
            0x04 => FileType::PeiCore,
            0x05 => FileType::DxeCore,
            0x06 => FileType::Peim,
            0x07 => FileType::Driver,
            0x08 => FileType::CombinedPeimDriver,
            0x09 => FileType::Application,
            0x0a => FileType::Mm,
            0x0b => FileType::FirmwareVolumeImage,
            0x0c => FileType::CombinedMmDxe,
            0x0d => FileType::MmCore,
            0x0e => FileType::MmStandalone,
            0x0f => FileType::MmCoreStandalone,
            _ => FileType::Other,
        }
    }

    /// The PI boot phase that dispatches this file type.
    pub fn phase(self) -> &'static str {
        match self {
            FileType::SecurityCore => "SEC",
            FileType::PeiCore | FileType::Peim | FileType::CombinedPeimDriver => "PEI",
            FileType::DxeCore | FileType::Driver | FileType::CombinedMmDxe => "DXE",
            FileType::Mm
            | FileType::MmCore
            | FileType::MmStandalone
            | FileType::MmCoreStandalone => "MM",
            FileType::Application => "UEFI applications",
            FileType::FirmwareVolumeImage
            | FileType::Freeform
            | FileType::Raw
            | FileType::Other
            | FileType::NonFfsVolume
            | FileType::VolumeData => "Other files",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleChange {
    pub change: ModuleChangeKind,
    pub file_type: FileType,
    /// PI boot phase that runs the file; the Volume Top File (reset vector) is reported as SEC.
    pub boot_phase: &'static str,
    /// Firmware volume name GUID; otherwise the GUID of the file that contains the volume, or
    /// the guest address of a top-level volume.
    pub volume: String,
    pub guid: String,
    pub name: Option<String>,
    /// Some contents use an encapsulation this tool does not decode; they are compared as bytes.
    pub undecoded_sections: bool,
    /// For modified modules whose normalized contents have equal length: the number of bytes
    /// that differ. `None` when the length changed or the module was added or removed.
    pub differing_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleDiff {
    pub unchanged: usize,
    pub changes: Vec<ModuleChange>,
}

struct Module {
    file_type: FileType,
    volume: String,
    guid: String,
    name: Option<String>,
    container: bool,
    undecoded: bool,
    raw: [u8; 32],
    normalized: Vec<u8>,
}

struct Walker {
    decompressed: usize,
    files: usize,
    modules: Vec<Module>,
}

struct FileState {
    hasher: Vec<u8>,
    name: Option<String>,
    container: bool,
    undecoded: bool,
}

struct Limited {
    buffer: Vec<u8>,
    limit: usize,
}

impl io::Write for Limited {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.buffer.len().saturating_add(data.len()) > self.limit {
            return Err(io::Error::other("decompressed data exceeds the limit"));
        }
        self.buffer.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Appends `bytes` with a tag and length unless they are all the erase byte, so free space,
/// alignment gaps and pad files only count when they hold data. Their sizes follow the file
/// layout, which the file entries already compare.
fn content(residual: &mut Vec<u8>, tag: u8, bytes: &[u8], erased: u8) {
    if bytes.iter().any(|byte| *byte != erased) {
        residual.push(tag);
        residual.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        residual.extend_from_slice(bytes);
    }
}

impl Walker {
    fn volume(&mut self, data: &[u8], label: &str, depth: usize) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("firmware volumes are nested too deeply".into());
        }
        let length = volume_length(data).ok_or("invalid firmware volume header")?;
        let data = &data[..length];
        let ffs3 = match data[16..32].try_into().expect("16 bytes") {
            FFS2 => false,
            FFS3 => true,
            other => {
                // Not a firmware file system (for example a variable store): compare the whole
                // volume as one opaque entry keyed by its file system GUID.
                self.modules.push(Module {
                    file_type: FileType::NonFfsVolume,
                    volume: label.to_string(),
                    guid: guid(&other),
                    name: Some(if other == SYSTEM_NV_DATA {
                        "UEFI variable store volume".into()
                    } else {
                        "non-FFS volume".into()
                    }),
                    container: false,
                    undecoded: true,
                    raw: Sha256::digest(data).into(),
                    normalized: data.to_vec(),
                });
                return Ok(());
            }
        };
        let attributes = u32_at(data, 44).ok_or("truncated volume header")?;
        // EFI_FVB2_ERASE_POLARITY: free space is all ones when set.
        let erased = if attributes & 0x800 != 0 { 0xff } else { 0x00 };
        let extension = usize::from(u16_at(data, 52).ok_or("truncated volume header")?);
        let (label, start) = if extension != 0 {
            let size = u32_at(data, extension + 16).ok_or("truncated volume extension header")?;
            let name = guid(&data[extension..extension + 16]);
            (name, extension.saturating_add(size as usize))
        } else {
            (
                label.to_string(),
                usize::from(u16_at(data, 48).expect("checked")),
            )
        };
        // Bytes outside non-pad files are compared as one entry per volume, so header, padding,
        // pad file and free-space changes are not lost.
        let mut residual = Vec::new();
        let mut cursor = 0;
        let mut offset = align(start, 8).ok_or("volume offset overflows")?;
        while offset.checked_add(24).is_some_and(|end| end <= length) {
            let header = &data[offset..offset + 24];
            if header.iter().all(|byte| *byte == erased) {
                break;
            }
            let file_type = header[18];
            let file_attributes = header[19];
            let mut size = u24_at(header, 20).expect("in bounds");
            let mut header_size = 24;
            if ffs3 && file_attributes & 0x01 != 0 {
                size = usize::try_from(u64_at(data, offset + 24).ok_or("truncated file header")?)
                    .map_err(|_| "file size overflows")?;
                header_size = 32;
            }
            if size < header_size || offset.checked_add(size).is_none_or(|end| end > length) {
                return Err(format!(
                    "file {} extends beyond its volume",
                    guid(&header[..16])
                ));
            }
            self.files += 1;
            if self.files > MAX_FILES {
                return Err(format!("more than {MAX_FILES} firmware files"));
            }
            let body = &data[offset + header_size..offset + size];
            if cursor == 0 {
                residual.extend_from_slice(&data[..offset]);
            } else {
                content(&mut residual, b'g', &data[cursor..offset], erased);
            }
            if file_type == FILE_PAD {
                content(&mut residual, b'p', body, erased);
            } else {
                // EFI_FFS_FILE_HEADER.State bits are inverted when the erase polarity is 1.
                let state = header[23] ^ erased;
                let header = [file_type, file_attributes & !0x01, state];
                self.file(&label, &data[offset..offset + 16], header, body, depth)?;
            }
            cursor = offset + size;
            offset = align(offset + size, 8).ok_or("file offset overflows")?;
        }
        if cursor == 0 {
            residual.extend_from_slice(&data[..offset.min(length)]);
            cursor = offset.min(length);
        }
        content(
            &mut residual,
            b'f',
            &data[cursor.min(length)..length],
            erased,
        );
        self.modules.push(Module {
            file_type: FileType::VolumeData,
            volume: label.clone(),
            // Top-level volumes without a name are labelled by address; match those by order so
            // a layout change does not look like a removed and an added volume.
            guid: if extension == 0 && depth == 0 {
                "volume data (unnamed top-level volume)".into()
            } else {
                format!("volume data {label}")
            },
            name: Some(format!("volume {label}: data outside files")),
            container: false,
            undecoded: false,
            raw: Sha256::digest(&residual).into(),
            normalized: residual,
        });
        Ok(())
    }

    /// `header` is the file type, the attributes without FFS_ATTRIB_LARGE_FILE, and the state
    /// normalized for erase polarity; both comparisons include it.
    fn file(
        &mut self,
        volume: &str,
        name: &[u8],
        header: [u8; 3],
        body: &[u8],
        depth: usize,
    ) -> Result<(), String> {
        let file_type = header[0];
        let file_guid = guid(name);
        let mut state = FileState {
            hasher: Vec::new(),
            name: None,
            container: false,
            undecoded: false,
        };
        state.hasher.extend_from_slice(&header);
        if file_type == FILE_RAW {
            state.hasher.extend_from_slice(body);
        } else {
            self.sections(body, &file_guid, depth, &mut state)?;
        }
        self.modules.push(Module {
            file_type: FileType::from_byte(file_type),
            volume: volume.to_string(),
            guid: file_guid,
            name: state.name.or_else(|| {
                (name == VOLUME_TOP_FILE).then(|| "Volume Top File (reset vector)".into())
            }),
            container: state.container,
            undecoded: state.undecoded,
            raw: {
                let mut raw = Sha256::new();
                raw.update(header);
                raw.update(body);
                raw.finalize().into()
            },
            normalized: state.hasher,
        });
        Ok(())
    }

    fn sections(
        &mut self,
        data: &[u8],
        file_guid: &str,
        depth: usize,
        state: &mut FileState,
    ) -> Result<(), String> {
        if depth > MAX_DEPTH {
            return Err("sections are nested too deeply".into());
        }
        let mut offset = 0;
        while offset + 4 <= data.len() {
            let mut size = u24_at(data, offset).expect("in bounds");
            let section_type = data[offset + 3];
            let mut header = 4;
            if size == 0xff_ffff {
                size = u32_at(data, offset + 4).ok_or("truncated section header")? as usize;
                header = 8;
            }
            let end = offset
                .checked_add(size)
                .filter(|end| size >= header && *end <= data.len())
                .ok_or_else(|| format!("section in file {file_guid} extends beyond the file"))?;
            let body = &data[offset + header..end];
            state.hasher.push(section_type);
            // Section boundaries are part of the comparison: a decoded payload contributes its
            // decoded length, every other section its body length.
            let length = |hasher: &mut Vec<u8>, length: usize| {
                hasher.extend_from_slice(&(length as u64).to_le_bytes())
            };
            match section_type {
                SECTION_GUID_DEFINED => {
                    let definition = body.get(..20).ok_or("truncated GUID-defined section")?;
                    let data_offset = usize::from(u16_at(definition, 16).expect("in bounds"));
                    let guided_attributes = u16_at(definition, 18).expect("in bounds");
                    let payload = data
                        .get(offset + data_offset..end)
                        .filter(|_| data_offset >= header + 20)
                        .ok_or("invalid GUID-defined section data offset")?;
                    state.hasher.extend_from_slice(definition);
                    // GUID-specific header data (for example a signature) is compared, except
                    // the CRC32 guided section's checksum, which is derived from the payload.
                    if definition[..16] != CRC32_GUIDED {
                        state
                            .hasher
                            .extend_from_slice(&data[offset + header + 20..offset + data_offset]);
                    }
                    if definition[..16] == LZMA {
                        let decoded = self.decompress(payload)?;
                        length(&mut state.hasher, decoded.len());
                        self.sections(&decoded, file_guid, depth + 1, state)?;
                    } else if guided_attributes & GUIDED_PROCESSING_REQUIRED == 0 {
                        length(&mut state.hasher, payload.len());
                        self.sections(payload, file_guid, depth + 1, state)?;
                    } else {
                        state.undecoded = true;
                        length(&mut state.hasher, payload.len());
                        state.hasher.extend_from_slice(payload);
                    }
                }
                SECTION_COMPRESSION => {
                    // EFI_COMPRESSION_SECTION: UncompressedLength (u32), CompressionType (u8).
                    if body.get(4) == Some(&0) {
                        length(&mut state.hasher, body.len() - 5);
                        self.sections(&body[5..], file_guid, depth + 1, state)?;
                    } else {
                        state.undecoded = true;
                        length(&mut state.hasher, body.len());
                        state.hasher.extend_from_slice(body);
                    }
                }
                SECTION_FIRMWARE_VOLUME => {
                    state.container = true;
                    length(&mut state.hasher, body.len());
                    // Bytes after the nested volume's FvLength belong to this file.
                    if let Some(volume) = volume_length(body) {
                        state.hasher.extend_from_slice(&body[volume..]);
                    }
                    self.volume(body, file_guid, depth + 1)?;
                }
                SECTION_PE32 => {
                    length(&mut state.hasher, body.len());
                    state.hasher.extend_from_slice(&normalize_pe(body));
                }
                SECTION_USER_INTERFACE => {
                    let units: Vec<u16> = body
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| u16::from_le_bytes(*pair))
                        .take_while(|unit| *unit != 0)
                        .collect();
                    state.name = Some(String::from_utf16_lossy(&units));
                    length(&mut state.hasher, body.len());
                    state.hasher.extend_from_slice(body);
                }
                _ => {
                    length(&mut state.hasher, body.len());
                    state.hasher.extend_from_slice(body);
                }
            }
            let next = align(end, 4).ok_or("section offset overflows")?;
            if let Some(padding) = data.get(end..next.min(data.len())) {
                state.hasher.extend_from_slice(padding);
            }
            offset = next;
        }
        Ok(())
    }

    fn decompress(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        let remaining = MAX_DECOMPRESSED - self.decompressed;
        // LZMA-alone header: properties (1), dictionary size (4), unpacked size (8).
        if u64_at(payload, 5).is_some_and(|size| size != u64::MAX && size > remaining as u64) {
            return Err("LZMA section is larger than the decompression limit".into());
        }
        let mut output = Limited {
            buffer: Vec::new(),
            limit: remaining,
        };
        let options = lzma_rs::decompress::Options {
            memlimit: Some(remaining),
            ..Default::default()
        };
        lzma_rs::lzma_decompress_with_options(&mut &payload[..], &mut output, &options)
            .map_err(|error| format!("LZMA section: {error}"))?;
        self.decompressed += output.buffer.len();
        Ok(output.buffer)
    }
}

const MAX_DEBUG_ENTRIES: usize = 16;
const MAX_SECTIONS: usize = 96;
const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
const IMAGE_SCN_CNT_CODE: u32 = 0x20;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Zeroes fields that the PE/COFF specification defines as build metadata: the COFF header
/// timestamp, the optional-header checksum, each debug directory entry's timestamp, and the
/// signature and PDB path of CodeView (`RSDS` or `NB10`) debug records.
///
/// Normalization is all or nothing: if any structure is out of place (a debug directory or
/// CodeView record outside a non-executable section's raw data or in the section holding the
/// entry point, more than one CodeView record, a record overlapping the directory, a path that
/// is not printable ASCII, more than 16 debug entries), the image is returned unchanged and
/// compared as raw bytes.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
pub(crate) fn normalize_pe(image: &[u8]) -> Vec<u8> {
    let mut out = image.to_vec();
    match pe_metadata(image) {
        Some(ranges) => {
            for (start, end) in ranges {
                out[start..end].fill(0);
            }
            out
        }
        None => out,
    }
}

struct PeSection {
    address: usize,
    virtual_size: usize,
    raw: usize,
    raw_size: usize,
    executable: bool,
}

/// Returns the byte ranges to zero, or `None` if the image does not pass every check.
fn pe_metadata(image: &[u8]) -> Option<Vec<(usize, usize)>> {
    if image.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32_at(image, 0x3c)? as usize;
    if image.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let count = usize::from(u16_at(image, coff + 2)?);
    let optional_size = usize::from(u16_at(image, coff + 16)?);
    let optional = coff + 20;
    let table = optional.checked_add(optional_size)?;
    let (directories, directory_count) = match u16_at(image, optional)? {
        0x20b => (112, 108),
        0x10b => (96, 92),
        _ => return None,
    };
    if count > MAX_SECTIONS || optional_size < directories {
        return None;
    }
    let headers_end = u32_at(image, optional + 60)? as usize;
    if headers_end < table.checked_add(count * 40)? || headers_end > image.len() {
        return None;
    }
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let entry = table + index * 40;
        let section = PeSection {
            virtual_size: u32_at(image, entry + 8)? as usize,
            address: u32_at(image, entry + 12)? as usize,
            raw_size: u32_at(image, entry + 16)? as usize,
            raw: u32_at(image, entry + 20)? as usize,
            executable: u32_at(image, entry + 36)? & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)
                != 0,
        };
        if section.raw_size > 0
            && (section.raw < headers_end
                || section.raw.checked_add(section.raw_size)? > image.len())
        {
            return None;
        }
        sections.push(section);
    }
    let mut ranges = vec![(coff + 4, coff + 8), (optional + 64, optional + 68)];
    if u32_at(image, optional + directory_count)? <= 6 || directories + 56 > optional_size {
        return Some(ranges);
    }
    let rva = u32_at(image, optional + directories + 48)? as usize;
    let size = u32_at(image, optional + directories + 52)? as usize;
    if rva == 0 && size == 0 {
        return Some(ranges);
    }
    if size == 0 || !size.is_multiple_of(28) || size / 28 > MAX_DEBUG_ENTRIES {
        return None;
    }
    // The debug directory must lie inside one section's raw data.
    let directory = sections.iter().find_map(|s| {
        let offset = rva.checked_sub(s.address)?;
        (offset.checked_add(size)? <= s.raw_size).then(|| s.raw + offset)
    })?;
    let directory_end = directory + size;
    // AddressOfEntryPoint: the section that holds it contains code whatever its flags say.
    let entry_point = u32_at(image, optional + 16)? as usize;
    let inside_data = |start: usize, end: usize| {
        sections.iter().any(|s| {
            let holds_entry = entry_point >= s.address
                && entry_point - s.address < s.virtual_size.max(s.raw_size);
            !s.executable
                && !holds_entry
                && s.raw_size > 0
                && start >= s.raw
                && end <= s.raw + s.raw_size
        })
    };
    if !inside_data(directory, directory_end) {
        return None;
    }
    let mut codeview_records = 0;
    for index in 0..size / 28 {
        let entry = directory + index * 28;
        ranges.push((entry + 4, entry + 8));
        if u32_at(image, entry + 12)? != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }
        // Toolchains emit one CodeView record per image.
        codeview_records += 1;
        if codeview_records > 1 {
            return None;
        }
        let data_size = u32_at(image, entry + 16)? as usize;
        let pointer = u32_at(image, entry + 24)? as usize;
        let data = image.get(pointer..pointer.checked_add(data_size)?)?;
        let fixed = match data.get(..4)? {
            b"RSDS" => 24, // signature, GUID, age
            b"NB10" => 16, // signature, offset, timestamp, age
            _ => return None,
        };
        let path = data.get(fixed..)?;
        let length = path.iter().position(|byte| *byte == 0)?;
        if !path[..length]
            .iter()
            .all(|byte| (0x20..0x7f).contains(byte))
        {
            return None;
        }
        let end = pointer + fixed + length + 1;
        if !inside_data(pointer, end) || (pointer < directory_end && directory < end) {
            return None;
        }
        ranges.push((pointer, end));
    }
    // Overlapping CodeView records would let one record widen another's range.
    let mut records: Vec<_> = ranges[2..].to_vec();
    records.sort_unstable();
    if records.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return None;
    }
    Some(ranges)
}

fn modules(volumes: &[(u64, &[u8])]) -> Result<Vec<Module>, String> {
    let mut walker = Walker {
        decompressed: 0,
        files: 0,
        modules: Vec::new(),
    };
    for (address, volume) in volumes {
        walker
            .volume(volume, &format!("{address:#x}"), 0)
            .map_err(|error| format!("volume at {address:#x}: {error}"))?;
    }
    Ok(walker.modules)
}

/// Compares the files of two sets of firmware volumes. Files are matched by GUID and
/// occurrence rather than by volume, so the comparison survives changes to the volume layout.
pub(crate) fn diff(before: &[(u64, &[u8])], after: &[(u64, &[u8])]) -> Result<ModuleDiff, String> {
    let index = |modules: Vec<Module>| {
        let mut map = BTreeMap::new();
        for module in modules {
            let mut occurrence = 0;
            while map.contains_key(&(module.guid.clone(), occurrence)) {
                occurrence += 1;
            }
            map.insert((module.guid.clone(), occurrence), module);
        }
        map
    };
    let mut before = index(modules(before).map_err(|error| format!("before: {error}"))?);
    let after = index(modules(after).map_err(|error| format!("after: {error}"))?);
    let mut unchanged = 0;
    let mut changes = Vec::new();
    let change = |kind, module: &Module, undecoded, differing| ModuleChange {
        change: kind,
        file_type: module.file_type,
        boot_phase: if module.guid == guid(&VOLUME_TOP_FILE) {
            "SEC"
        } else {
            module.file_type.phase()
        },
        volume: module.volume.clone(),
        guid: module.guid.clone(),
        name: module.name.clone(),
        undecoded_sections: undecoded,
        differing_bytes: differing,
    };
    for (key, b) in &after {
        match before.remove(key) {
            None => changes.push(change(ModuleChangeKind::Added, b, b.undecoded, None)),
            Some(a) => {
                let undecoded = a.undecoded || b.undecoded;
                if a.raw == b.raw || (a.normalized == b.normalized && b.container) {
                    unchanged += 1;
                } else if a.normalized == b.normalized {
                    changes.push(change(ModuleChangeKind::DebugDataOnly, b, undecoded, None));
                } else {
                    let differing = (a.normalized.len() == b.normalized.len()).then(|| {
                        a.normalized
                            .iter()
                            .zip(&b.normalized)
                            .filter(|(x, y)| x != y)
                            .count()
                    });
                    changes.push(change(ModuleChangeKind::Modified, b, undecoded, differing));
                }
            }
        }
    }
    for a in before.values() {
        changes.push(change(ModuleChangeKind::Removed, a, a.undecoded, None));
    }
    // Within each kind, size changes first, then the most differing bytes.
    changes.sort_by(|a, b| {
        let weight = |c: &ModuleChange| std::cmp::Reverse(c.differing_bytes.unwrap_or(usize::MAX));
        (a.change, weight(a), &a.name, &a.volume, &a.guid).cmp(&(
            b.change,
            weight(b),
            &b.name,
            &b.volume,
            &b.guid,
        ))
    });
    Ok(ModuleDiff { unchanged, changes })
}
