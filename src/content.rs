//! Locates changed page contents inside recognizable payloads (firmware volumes, ELF, PE and
//! Linux bzImage) for each platform, and decodes firmware volumes into modules.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    firmware::{self, ModuleDiff},
    image::Image,
};

const PAGE: u64 = 4096;
static ZERO: [u8; PAGE as usize] = [0; PAGE as usize];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    UefiFirmwareVolume,
    LinuxBzimage,
    Elf,
    Pe,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Format::UefiFirmwareVolume => "UEFI firmware volume",
            Format::LinuxBzimage => "Linux bzImage",
            Format::Elf => "ELF image",
            Format::Pe => "PE image",
        }
    }
}

/// A recognized payload that overlaps pages whose contents changed. Payloads are paired by
/// start address; a payload found in only one file has the other format set to `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Component {
    pub platforms: Vec<String>,
    pub start: String,
    pub end: String,
    pub before_format: Option<Format>,
    pub after_format: Option<Format>,
    pub changed_pages: usize,
    /// Changed pages that are marked unmeasured or shared in either file.
    pub unmeasured_changed_pages: usize,
    /// For a PE or ELF image in both files: the sections (by name) whose bytes differ.
    pub changed_sections: Option<Vec<String>>,
    /// Changed PE sections that hold short printable text (for example a Unified Kernel Image's
    /// `.cmdline`, `.osrel` or `.uname`): the whitespace-separated tokens removed and added.
    pub text_changes: Vec<TextChange>,
    /// For an ELF image with a symbol table in both files: functions (STT_FUNC symbols, matched by
    /// name with compiler hash suffixes removed) whose bytes differ, or that were added/removed.
    pub function_changes: Option<FunctionChanges>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionChanges {
    pub changed: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

const MAX_SYMBOLS: usize = 1 << 20;

/// Readable symbol name: drops `.llvm.<n>` suffixes and decodes legacy Rust mangling
/// (`_ZN` length-prefixed path, `17h<16 hex>E` hash) so rebuilt functions keep their name.
fn symbol_name(raw: &str) -> String {
    let raw = match raw.find(".llvm.") {
        Some(index) => &raw[..index],
        None => raw,
    };
    let Some(mut rest) = raw.strip_prefix("_ZN") else {
        return raw.to_string();
    };
    let mut parts = Vec::new();
    loop {
        if rest.starts_with('E') || rest.is_empty() {
            break;
        }
        let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        let Ok(length) = rest[..digits].parse::<usize>() else {
            return raw.to_string();
        };
        let Some(part) = rest.get(digits..digits + length) else {
            return raw.to_string();
        };
        parts.push(part);
        rest = &rest[digits + length..];
    }
    if parts.last().is_some_and(|p| {
        p.len() == 17 && p.starts_with('h') && p[1..].chars().all(|c| c.is_ascii_hexdigit())
    }) {
        parts.pop();
    }
    let decode = |part: &str| {
        let mut out = part.trim_start_matches('_').replace("..", "::");
        for (from, to) in [
            ("$LT$", "<"),
            ("$GT$", ">"),
            ("$u20$", " "),
            ("$C$", ","),
            ("$RF$", "&"),
            ("$BP$", "*"),
            ("$u7b$", "{"),
            ("$u7d$", "}"),
            ("$u27$", "'"),
            ("$u5b$", "["),
            ("$u5d$", "]"),
            ("$u3b$", ";"),
        ] {
            out = out.replace(from, to);
        }
        out
    };
    parts.into_iter().map(decode).collect::<Vec<_>>().join("::")
}

/// Function bytes by readable name, from the ELF symbol table (SHT_SYMTAB) of a little-endian
/// ELF64 file. Symbols are mapped to file bytes through their section's address and offset.
fn elf_functions(data: &[u8]) -> Option<BTreeMap<String, Vec<&[u8]>>> {
    let shoff = usize::try_from(u64_at(data, 40)?).ok()?;
    let entry_size = usize::from(u16_at(data, 58)?);
    let count = usize::from(u16_at(data, 60)?);
    if count == 0 || count > 1024 || entry_size < 64 {
        return None;
    }
    let header = |index: usize| -> Option<(u32, u64, usize, usize, u32)> {
        let entry = shoff.checked_add(index.checked_mul(entry_size)?)?;
        Some((
            u32_at(data, entry + 4)?,
            u64_at(data, entry + 16)?,
            usize::try_from(u64_at(data, entry + 24)?).ok()?,
            usize::try_from(u64_at(data, entry + 32)?).ok()?,
            u32_at(data, entry + 40)?,
        ))
    };
    let symtab = (0..count).find(|i| header(*i).is_some_and(|h| h.0 == 2))?;
    let (_, _, offset, size, link) = header(symtab)?;
    let (_, _, strings, strings_size, _) = header(link as usize)?;
    let strings = data.get(strings..strings.checked_add(strings_size)?)?;
    let symbols = data.get(offset..offset.checked_add(size)?)?;
    if symbols.len() / 24 > MAX_SYMBOLS {
        return None;
    }
    let mut functions = BTreeMap::<String, Vec<&[u8]>>::new();
    for symbol in symbols.as_chunks::<24>().0 {
        let name = u32_at(symbol, 0)? as usize;
        let info = symbol[4];
        let section = usize::from(u16_at(symbol, 6)?);
        let value = u64_at(symbol, 8)?;
        let length = usize::try_from(u64_at(symbol, 16)?).ok()?;
        // STT_FUNC with a size, defined in a regular section.
        if info & 0xf != 2 || length == 0 || section == 0 || section >= count {
            continue;
        }
        let (_, address, file_offset, _, _) = header(section)?;
        let Some(start) = value
            .checked_sub(address)
            .and_then(|d| usize::try_from(d).ok())
            .and_then(|d| d.checked_add(file_offset))
        else {
            continue;
        };
        let Some(bytes) = start
            .checked_add(length)
            .and_then(|end| data.get(start..end))
        else {
            continue;
        };
        let raw = strings.get(name..)?;
        let raw = String::from_utf8_lossy(&raw[..raw.iter().position(|b| *b == 0)?]);
        functions.entry(symbol_name(&raw)).or_default().push(bytes);
    }
    Some(functions)
}

fn elf_function_changes(before: &[u8], after: &[u8]) -> Option<FunctionChanges> {
    let a = elf_functions(before)?;
    let b = elf_functions(after)?;
    let mut changes = FunctionChanges {
        changed: Vec::new(),
        added: Vec::new(),
        removed: Vec::new(),
    };
    for (name, bodies) in &b {
        match a.get(name) {
            None => changes.added.push(name.clone()),
            Some(old) if old != bodies => changes.changed.push(name.clone()),
            Some(_) => {}
        }
    }
    changes.removed = a.keys().filter(|n| !b.contains_key(*n)).cloned().collect();
    Some(changes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TextChange {
    pub section: String,
    pub removed: Vec<String>,
    pub added: Vec<String>,
}

const MAX_TEXT_SECTION: usize = 4096;

fn section_text(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
    let text = &bytes[..end];
    (text.len() <= MAX_TEXT_SECTION
        && text
            .iter()
            .all(|b| (0x20..0x7f).contains(b) || matches!(b, b'\n' | b'\t' | b'\r')))
    .then(|| String::from_utf8_lossy(text).into_owned())
}

/// Token-level differences for changed PE sections that hold short printable text.
fn pe_text_changes(
    format: Format,
    before: &[u8],
    after: &[u8],
    changed: &[String],
) -> Vec<TextChange> {
    let (Some((_, a)), Some((_, b))) = (sections(format, before), sections(format, after)) else {
        return Vec::new();
    };
    let mut changes = Vec::new();
    for name in changed {
        let (Some(old), Some(new)) = (
            a.iter().find(|s| &s.name == name),
            b.iter().find(|s| &s.name == name),
        ) else {
            continue;
        };
        let (Some(old), Some(new)) = (
            before.get(old.raw.clone()).and_then(section_text),
            after.get(new.raw.clone()).and_then(section_text),
        ) else {
            continue;
        };
        let old_tokens: Vec<&str> = old.split_whitespace().collect();
        let new_tokens: Vec<&str> = new.split_whitespace().collect();
        changes.push(TextChange {
            section: name.clone(),
            removed: old_tokens
                .iter()
                .filter(|t| !new_tokens.contains(t))
                .map(|t| t.to_string())
                .collect(),
            added: new_tokens
                .iter()
                .filter(|t| !old_tokens.contains(t))
                .map(|t| t.to_string())
                .collect(),
        });
    }
    changes
}

/// Module comparison across every firmware volume found in loaded memory runs that contain
/// changed pages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FirmwareModules {
    pub platforms: Vec<String>,
    pub modules: Option<ModuleDiff>,
    pub error: Option<String>,
}

/// Changed pages that are not inside any recognized payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unidentified {
    pub platforms: Vec<String>,
    pub changed_pages: usize,
}

#[derive(Debug, Default, Serialize)]
pub struct Content {
    pub components: Vec<Component>,
    pub firmware: Vec<FirmwareModules>,
    pub unidentified: Vec<Unidentified>,
    pub notes: Vec<String>,
}

struct Page<'a> {
    data: &'a [u8],
    unmeasured: bool,
}

fn memory<'a>(bytes: &'a [u8], image: &Image, bit: u32) -> Result<BTreeMap<u64, Page<'a>>, String> {
    let mut memory = BTreeMap::new();
    for page in image.pages.iter().filter(|page| page.mask & bit != 0) {
        let data = if page.offset == 0 {
            &ZERO[..]
        } else {
            &bytes[page.offset as usize..page.offset as usize + PAGE as usize]
        };
        let value = Page {
            data,
            unmeasured: page.unmeasured || page.shared,
        };
        if memory.insert(page.gpa, value).is_some() {
            return Err(format!("overlapping page records at {:#x}", page.gpa));
        }
    }
    Ok(memory)
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

/// Linux x86 boot protocol: <https://www.kernel.org/doc/html/latest/arch/x86/boot.html>
fn bzimage_length(data: &[u8]) -> Option<usize> {
    if data.get(0x1fe..0x200)? != [0x55, 0xaa] || data.get(0x202..0x206)? != b"HdrS" {
        return None;
    }
    let setup = match *data.get(0x1f1)? {
        0 => 4,
        sectors => usize::from(sectors),
    };
    let system = (u32_at(data, 0x1f4)? as usize).checked_mul(16)?;
    (setup + 1).checked_mul(512)?.checked_add(system)
}

/// ELF file extent from its program and section header tables.
fn elf_length(data: &[u8]) -> Option<usize> {
    if data.get(..4)? != b"\x7fELF" || *data.get(5)? != 1 {
        return None;
    }
    let (ph, sh, ph_size, ph_count, sh_size, sh_count, off, filesz) = match *data.get(4)? {
        1 => (
            u32_at(data, 28)? as u64,
            u32_at(data, 32)? as u64,
            u16_at(data, 42)?,
            u16_at(data, 44)?,
            u16_at(data, 46)?,
            u16_at(data, 48)?,
            4,
            16,
        ),
        2 => (
            u64_at(data, 32)?,
            u64_at(data, 40)?,
            u16_at(data, 54)?,
            u16_at(data, 56)?,
            u16_at(data, 58)?,
            u16_at(data, 60)?,
            8,
            32,
        ),
        _ => return None,
    };
    // Real images have a few dozen program headers; a cap bounds the per-page probe cost.
    if ph_count > 1024 || (ph_count > 0 && usize::from(ph_size) < filesz + 8) {
        return None;
    }
    let table =
        |start: u64, size: u16, count: u16| start.checked_add(u64::from(size) * u64::from(count));
    let mut end = table(ph, ph_size, ph_count)?.max(table(sh, sh_size, sh_count)?);
    let wide = data[4] == 2;
    for index in 0..u64::from(ph_count) {
        let entry = usize::try_from(ph.checked_add(index * u64::from(ph_size))?).ok()?;
        let read = |at: usize| {
            if wide {
                u64_at(data, entry + at)
            } else {
                u32_at(data, entry + at).map(u64::from)
            }
        };
        end = end.max(read(off)?.checked_add(read(filesz)?)?);
    }
    usize::try_from(end).ok()
}

/// PE extent: the larger of SizeOfImage and the end of the last section's raw data.
/// A PE/COFF section as stored in the file: name and raw byte range.
struct PeSection {
    name: String,
    raw: std::ops::Range<usize>,
}

/// Parses the PE/COFF headers at the start of `data`: the end of the headers and the raw
/// (file) layout of each section, at most 96 sections.
fn pe_sections(data: &[u8]) -> Option<(usize, Vec<PeSection>)> {
    if data.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32_at(data, 0x3c)? as usize;
    if data.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let count = usize::from(u16_at(data, pe + 6)?);
    if count > 96 {
        return None;
    }
    let optional = pe + 24;
    let table = optional + usize::from(u16_at(data, pe + 20)?);
    let headers = u32_at(data, optional + 60)? as usize;
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let entry = table + index * 40;
        let name = data.get(entry..entry + 8)?;
        let raw_size = u32_at(data, entry + 16)? as usize;
        let raw = u32_at(data, entry + 20)? as usize;
        let name = String::from_utf8_lossy(&name[..name.iter().position(|b| *b == 0).unwrap_or(8)])
            .into_owned();
        sections.push(PeSection {
            name,
            raw: raw..raw.checked_add(raw_size)?,
        });
    }
    Some((headers, sections))
}

/// PE extent in its file layout. An image stored in guest memory as a file (for example a
/// Unified Kernel Image) has a much larger SizeOfImage than file size, so that is not used.
fn pe_length(data: &[u8]) -> Option<usize> {
    let (headers, sections) = pe_sections(data)?;
    Some(sections.iter().map(|s| s.raw.end).fold(headers, usize::max))
}

/// ELF sections as stored in the file (ELF specification: section header table and the
/// section-name string table `e_shstrndx`). SHT_NOBITS sections hold no file bytes and are
/// skipped. Little-endian ELF64 only, at most 1,024 sections.
fn elf_sections(data: &[u8]) -> Option<(usize, Vec<PeSection>)> {
    if data.get(..4)? != b"\x7fELF" || *data.get(4)? != 2 || *data.get(5)? != 1 {
        return None;
    }
    let shoff = usize::try_from(u64_at(data, 40)?).ok()?;
    let entry_size = usize::from(u16_at(data, 58)?);
    let count = usize::from(u16_at(data, 60)?);
    let names = usize::from(u16_at(data, 62)?);
    if count == 0 || count > 1024 || entry_size < 64 || names >= count {
        return None;
    }
    let header = |index: usize| -> Option<(u32, u32, usize, usize)> {
        let entry = shoff.checked_add(index.checked_mul(entry_size)?)?;
        Some((
            u32_at(data, entry)?,
            u32_at(data, entry + 4)?,
            usize::try_from(u64_at(data, entry + 24)?).ok()?,
            usize::try_from(u64_at(data, entry + 32)?).ok()?,
        ))
    };
    let (_, _, strings, strings_size) = header(names)?;
    let strings = data.get(strings..strings.checked_add(strings_size)?)?;
    let mut sections = Vec::with_capacity(count);
    for index in 1..count {
        let (name, kind, offset, size) = header(index)?;
        if kind == 8 {
            continue; // SHT_NOBITS
        }
        let name = strings.get(name as usize..)?;
        let name =
            String::from_utf8_lossy(&name[..name.iter().position(|b| *b == 0)?]).into_owned();
        sections.push(PeSection {
            name,
            raw: offset..offset.checked_add(size)?,
        });
    }
    Some((64, sections))
}

/// Section layout of a PE or ELF payload.
fn sections(format: Format, data: &[u8]) -> Option<(usize, Vec<PeSection>)> {
    match format {
        Format::Pe => pe_sections(data),
        Format::Elf => elf_sections(data),
        _ => None,
    }
}

/// Names of the PE sections (and "headers") whose file bytes differ.
fn pe_changed_sections(format: Format, before: &[u8], after: &[u8]) -> Option<Vec<String>> {
    let (headers_a, a) = sections(format, before)?;
    let (headers_b, b) = sections(format, after)?;
    let mut changed = Vec::new();
    if before.get(..headers_a) != after.get(..headers_b) {
        changed.push("headers".to_string());
    }
    for section in &b {
        match a.iter().find(|s| s.name == section.name) {
            Some(old) if before.get(old.raw.clone()) == after.get(section.raw.clone()) => {}
            Some(_) => changed.push(section.name.clone()),
            None => changed.push(format!("{} (added)", section.name)),
        }
    }
    for section in &a {
        if !b.iter().any(|s| s.name == section.name) {
            changed.push(format!("{} (removed)", section.name));
        }
    }
    Some(changed)
}

fn probe(data: &[u8]) -> Option<(usize, Format)> {
    let (length, format) = if let Some(length) = firmware::volume_length(data) {
        (length, Format::UefiFirmwareVolume)
    } else if let Some(length) = bzimage_length(data) {
        (length, Format::LinuxBzimage)
    } else if let Some(length) = elf_length(data) {
        (length, Format::Elf)
    } else {
        (pe_length(data)?, Format::Pe)
    };
    (length > 0 && length <= data.len()).then_some((length, format))
}

struct Found {
    start: u64,
    end: u64,
    format: Format,
    bytes: Vec<u8>,
}

/// Scans each contiguous run of loaded pages that contains a changed page for payloads that
/// start on a page boundary.
fn find(memory: &BTreeMap<u64, Page<'_>>, changed: &BTreeSet<u64>) -> Vec<Found> {
    let mut runs = Vec::new();
    for &gpa in memory.keys() {
        match runs.last_mut() {
            Some((_, end)) if *end == gpa => *end += PAGE,
            _ => runs.push((gpa, gpa + PAGE)),
        }
    }
    let mut found = Vec::new();
    for (start, end) in runs {
        if changed.range(start..end).next().is_none() {
            continue;
        }
        let mut buffer = Vec::with_capacity((end - start) as usize);
        for (_, page) in memory.range(start..end) {
            buffer.extend_from_slice(page.data);
        }
        let mut offset = 0;
        while offset < buffer.len() {
            let Some((length, format)) = probe(&buffer[offset..]) else {
                offset += PAGE as usize;
                continue;
            };
            let length = length
                .next_multiple_of(PAGE as usize)
                .min(buffer.len() - offset);
            found.push(Found {
                start: start + offset as u64,
                end: start + (offset + length) as u64,
                format,
                bytes: buffer[offset..offset + length].to_vec(),
            });
            offset += length;
        }
    }
    found
}

fn volumes(found: &[Found]) -> Vec<(u64, &[u8])> {
    found
        .iter()
        .filter(|f| f.format == Format::UefiFirmwareVolume)
        .map(|f| (f.start, &f.bytes[..]))
        .collect()
}

type Cache = HashMap<[u8; 32], Result<ModuleDiff, String>>;

struct PlatformContent {
    components: Vec<Component>,
    firmware: Option<FirmwareModules>,
    unidentified: BTreeSet<u64>,
}

fn platform(
    before: &BTreeMap<u64, Page<'_>>,
    after: &BTreeMap<u64, Page<'_>>,
    cache: &mut Cache,
) -> PlatformContent {
    let mut changed = BTreeSet::new();
    for gpa in before.keys().chain(after.keys()) {
        if before.get(gpa).map(|page| page.data) != after.get(gpa).map(|page| page.data) {
            changed.insert(*gpa);
        }
    }
    let left = find(before, &changed);
    let right = find(after, &changed);

    let (volumes_before, volumes_after) = (volumes(&left), volumes(&right));
    let firmware = (!volumes_before.is_empty() || !volumes_after.is_empty()).then(|| {
        let mut key = Sha256::new();
        for (marker, side) in [(0u8, &volumes_before), (1, &volumes_after)] {
            for (address, bytes) in side {
                key.update([marker]);
                key.update(address.to_le_bytes());
                key.update(Sha256::digest(bytes));
            }
        }
        let result = cache
            .entry(key.finalize().into())
            .or_insert_with(|| firmware::diff(&volumes_before, &volumes_after));
        FirmwareModules {
            platforms: Vec::new(),
            modules: result.as_ref().ok().cloned(),
            error: result.as_ref().err().cloned(),
        }
    });

    let overlaps = |f: &Found| changed.range(f.start..f.end).next().is_some();
    let mut paired = BTreeMap::<u64, (Option<&Found>, Option<&Found>)>::new();
    for f in left.iter().filter(|f| overlaps(f)) {
        paired.entry(f.start).or_default().0 = Some(f);
    }
    for f in right.iter().filter(|f| overlaps(f)) {
        paired.entry(f.start).or_default().1 = Some(f);
    }
    let mut components = Vec::new();
    let mut attributed = BTreeSet::new();
    for (start, (a, b)) in paired {
        let end = a
            .iter()
            .chain(b.iter())
            .map(|f| f.end)
            .max()
            .expect("one side");
        let pages: Vec<u64> = changed.range(start..end).copied().collect();
        let unmeasured = pages
            .iter()
            .filter(|gpa| {
                before.get(gpa).is_some_and(|page| page.unmeasured)
                    || after.get(gpa).is_some_and(|page| page.unmeasured)
            })
            .count();
        attributed.extend(pages.iter().copied());
        let changed_sections = match (a, b) {
            (Some(a), Some(b))
                if a.format == b.format && matches!(a.format, Format::Pe | Format::Elf) =>
            {
                pe_changed_sections(a.format, &a.bytes, &b.bytes)
            }
            _ => None,
        };
        components.push(Component {
            platforms: Vec::new(),
            start: format!("{start:#x}"),
            end: format!("{end:#x}"),
            before_format: a.map(|f| f.format),
            after_format: b.map(|f| f.format),
            changed_pages: pages.len(),
            unmeasured_changed_pages: unmeasured,
            changed_sections: changed_sections.clone(),
            function_changes: match (a, b) {
                (Some(a), Some(b)) if a.format == Format::Elf && b.format == Format::Elf => {
                    elf_function_changes(&a.bytes, &b.bytes)
                }
                _ => None,
            },
            text_changes: match (a, b, &changed_sections) {
                (Some(a), Some(b), Some(changed)) => {
                    pe_text_changes(a.format, &a.bytes, &b.bytes, changed)
                }
                _ => Vec::new(),
            },
        });
    }
    PlatformContent {
        components,
        firmware,
        unidentified: changed.difference(&attributed).copied().collect(),
    }
}

/// Adds `name` to the platforms of an equal entry, or appends a new entry.
fn merge<T: Clone + PartialEq>(
    entries: &mut Vec<T>,
    item: T,
    name: &str,
    platforms: impl Fn(&mut T) -> &mut Vec<String>,
) {
    for entry in entries.iter_mut() {
        let mut probe = entry.clone();
        platforms(&mut probe).clear();
        if probe == item {
            platforms(entry).push(name.to_string());
            return;
        }
    }
    let mut item = item;
    platforms(&mut item).push(name.to_string());
    entries.push(item);
}

pub(crate) fn analyze(
    before_bytes: &[u8],
    before: &Image,
    after_bytes: &[u8],
    after: &Image,
) -> Content {
    let mut content = Content::default();
    let mut cache = Cache::new();
    let mut unidentified: Vec<(BTreeSet<u64>, Vec<String>)> = Vec::new();
    for (&left, &name) in &before.platforms {
        let Some((&right, _)) = after.platforms.iter().find(|(_, n)| **n == name) else {
            content.notes.push(format!(
                "{name}: platform only in the before file; content analysis skipped"
            ));
            continue;
        };
        let maps = memory(before_bytes, before, left)
            .and_then(|a| memory(after_bytes, after, right).map(|b| (a, b)));
        let (a, b) = match maps {
            Ok(maps) => maps,
            Err(error) => {
                content
                    .notes
                    .push(format!("{name}: content analysis skipped: {error}"));
                continue;
            }
        };
        let result = platform(&a, &b, &mut cache);
        for component in result.components {
            merge(&mut content.components, component, name, |c| {
                &mut c.platforms
            });
        }
        if let Some(firmware) = result.firmware {
            merge(&mut content.firmware, firmware, name, |c| &mut c.platforms);
        }
        if !result.unidentified.is_empty() {
            match unidentified
                .iter_mut()
                .find(|(set, _)| *set == result.unidentified)
            {
                Some((_, names)) => names.push(name.to_string()),
                None => unidentified.push((result.unidentified, vec![name.to_string()])),
            }
        }
    }
    for name in after.platforms.values() {
        if !before.platforms.values().any(|n| n == name) {
            content.notes.push(format!(
                "{name}: platform only in the after file; content analysis skipped"
            ));
        }
    }
    for component in &mut content.components {
        component.platforms.sort();
    }
    for firmware in &mut content.firmware {
        firmware.platforms.sort();
    }
    content.components.sort_by(|a, b| {
        let start = |c: &Component| u64::from_str_radix(&c.start[2..], 16).expect("hex");
        (start(a), &a.platforms).cmp(&(start(b), &b.platforms))
    });
    content.unidentified = unidentified
        .into_iter()
        .map(|(pages, mut platforms)| {
            platforms.sort();
            Unidentified {
                platforms,
                changed_pages: pages.len(),
            }
        })
        .collect();
    content
}

#[cfg(test)]
mod tests {
    use super::symbol_name;

    #[test]
    fn symbol_names_drop_compiler_hashes() {
        assert_eq!(symbol_name("CryptRsaSign"), "CryptRsaSign");
        assert_eq!(
            symbol_name(
                "_ZN4svsm3cpu2vc14vc_decode_insn17h649b5c5067f5f3c4E.llvm.15934132641764171485"
            ),
            "svsm::cpu::vc::vc_decode_insn"
        );
        assert_eq!(
            symbol_name(
                "_ZN59_$LT$svsm..error..SvsmError$u20$as$u20$core..fmt..Debug$GT$3fmt17h68f31f21c5a1ed1cE"
            ),
            "<svsm::error::SvsmError as core::fmt::Debug>::fmt"
        );
        // Malformed input is returned unchanged.
        assert_eq!(symbol_name("_ZN99short"), "_ZN99short");
    }
}
