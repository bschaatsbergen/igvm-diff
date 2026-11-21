use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde_json::Value;

use crate::{
    Area, Artifact, Change, ChangeKind, Component, FileMeasurements, FileType, Format,
    LaunchMeasurement, ModuleChange, ModuleChangeKind, Record, Report, SnpMeasurement,
};

/// Record details shown per section in the default output; --verbose shows all.
const DETAIL_LIMIT: usize = 6;
const RANGE_LIMIT: usize = 8;

/// The text report. `verbose` expands every list and adds page ranges and explanations; the
/// default keeps to what an operator needs to decide what to review.
pub(crate) fn summary(report: &Report, f: &mut fmt::Formatter<'_>, verbose: bool) -> fmt::Result {
    if report.has_changes() {
        let count = report.findings.len();
        let noun = if count == 1 { "change" } else { "changes" };
        writeln!(f, "Files differ: {count} record {noun}")?;
    } else {
        writeln!(f, "Files are identical")?;
    }
    artifact(f, "Before:", &report.inputs.before)?;
    artifact(f, "After:", &report.inputs.after)?;
    let isolated: Vec<&str> = report
        .platforms
        .iter()
        .map(String::as_str)
        .filter(|p| *p != "native")
        .collect();
    match &report.focus {
        Some(platform) => writeln!(f, "Platform: {platform} (other platforms left out)")?,
        None if isolated.len() > 1 => writeln!(
            f,
            "Platforms: {}. To review only the one you run, add --platform {}.",
            isolated.join(", "),
            isolated[0]
        )?,
        None => {}
    }
    if report.comparison.format_changed {
        writeln!(
            f,
            "Format version changed: {} -> {}",
            report.inputs.before.format_version, report.inputs.after.format_version
        )?;
    }
    if report.comparison.order_changed {
        writeln!(f, "Relative record order changed")?;
    }

    attestation(report, f)?;
    launch(report, f)?;
    overview(report, f)?;
    let (pages, mut configuration): (Vec<_>, Vec<_>) = report
        .findings
        .iter()
        .partition(|change| record(change).kind == "page_data");
    configuration.sort_by_key(|change| match record(change).kind {
        "guest_policy" => 0,
        "vp_context" => 1,
        "supported_platform" => 2,
        "snp_id_block" | "vbs_measurement" | "corim_document" | "corim_signature" => 3,
        _ => 4,
    });
    let mut references = Vec::new();
    details(
        f,
        "Configuration and CPU changes",
        &configuration,
        &mut references,
        verbose,
    )?;
    modules(report, f, verbose)?;
    if !pages.is_empty() {
        let counts: Vec<_> = [
            ChangeKind::Added,
            ChangeKind::Removed,
            ChangeKind::Modified,
            ChangeKind::Reordered,
            ChangeKind::MaskReassigned,
        ]
        .into_iter()
        .filter_map(|kind| {
            let count = pages.iter().filter(|change| change.kind == kind).count();
            (count > 0).then(|| format!("{count} {}", action(kind)))
        })
        .collect();
        writeln!(f, "\nChanged pages (4 KiB): {}", counts.join(", "))?;
        payloads(report, f, verbose)?;
        let mut attributes: Vec<_> = pages
            .iter()
            .copied()
            .filter(|change| {
                change.before.is_some()
                    && change.after.is_some()
                    && (change.fields.iter().any(|field| field != "payload_sha256")
                        || masks_changed(change))
            })
            .collect();
        attributes.sort_by_key(|change| {
            if change
                .fields
                .iter()
                .any(|field| matches!(field.as_str(), "shared" | "unmeasured" | "data_type"))
            {
                0
            } else if change.fields.iter().any(|field| field == "data_present") {
                1
            } else {
                2
            }
        });
        details(
            f,
            "Page attribute changes",
            &attributes,
            &mut references,
            verbose,
        )?;
        // Page ranges are the only location information when no payload was recognized.
        let located = !report.content.components.is_empty();
        if verbose || !located {
            if verbose {
                for flag in ["shared", "unmeasured"] {
                    let count = pages
                        .iter()
                        .filter(|change| {
                            change
                                .before
                                .iter()
                                .chain(&change.after)
                                .any(|r| r.fields[flag] == true)
                        })
                        .count();
                    if count > 0 {
                        writeln!(f, "  Records involving {flag} pages: {count}")?;
                    }
                }
            }
            ranges(f, &pages, verbose)?;
        }
    } else {
        payloads(report, f, verbose)?;
    }
    for diagnostic in &report.diagnostics {
        writeln!(f, "\nNote: {diagnostic}")?;
    }
    if !references.is_empty() {
        writeln!(f, "\nReferences:")?;
        for (index, reference) in references.iter().enumerate() {
            writeln!(f, "  [{}] {reference}", index + 1)?;
        }
    }
    if report.launch_measurement.is_none() && report.has_changes() {
        writeln!(
            f,
            "\nLaunch measurement: not computed; take the new reference value from the vendor's published measurement."
        )?;
    }
    if !verbose {
        writeln!(
            f,
            "\nMore: --verbose (all modules, page ranges, every record); --format json"
        )?;
    }
    Ok(())
}

fn overview(report: &Report, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if !report.has_changes() {
        return writeln!(f, "\nNo file differences to investigate.");
    }
    if !report.diagnostics.is_empty() {
        writeln!(f, "\nSome differences could not be matched or explained.")?;
        return writeln!(
            f,
            "Next: resolve the comparison notes below before interpreting the counts."
        );
    }
    let mut areas = BTreeSet::new();
    for change in &report.findings {
        if change.fields.is_empty()
            && !matches!(change.kind, ChangeKind::Added | ChangeKind::Removed)
        {
            if masks_changed(change) {
                areas.insert("platform masks");
            }
            continue;
        }
        let record = record(change);
        match record.kind {
            "page_data" => {
                if matches!(change.kind, ChangeKind::Added | ChangeKind::Removed) {
                    areas.insert("page addresses or platform coverage");
                }
                if change.fields.iter().any(|field| field == "data_present") {
                    areas.insert("page storage");
                } else if change.fields.iter().any(|field| field == "payload_sha256") {
                    areas.insert("page contents");
                }
                if change
                    .fields
                    .iter()
                    .any(|field| !matches!(field.as_str(), "data_present" | "payload_sha256"))
                {
                    areas.insert("page attributes");
                }
            }
            "vp_context" => {
                areas.insert("CPU startup state");
            }
            "supported_platform" => {
                areas.insert("platform settings");
            }
            "guest_policy" => {
                areas.insert("guest policy");
            }
            "required_memory" | "error_range" => {
                areas.insert("memory requirements");
            }
            "relocatable_region" | "page_table_relocation" => {
                areas.insert("relocation settings");
            }
            "snp_id_block" | "vbs_measurement" | "corim_document" | "corim_signature" => {
                areas.insert("identity/measurement metadata");
            }
            _ => {
                areas.insert("boot parameters");
            }
        }
        if masks_changed(change) {
            areas.insert("platform masks");
        }
    }
    if report.comparison.order_changed {
        areas.insert("record loading order");
    }
    if report.comparison.format_changed {
        areas.insert("IGVM format");
    }
    writeln!(f)?;
    // A pure page-contents change is already described by the attestation and module sections.
    if !(areas.len() == 1 && areas.contains("page contents")) {
        let (pages, settings): (Vec<_>, Vec<_>) = areas
            .iter()
            .copied()
            .partition(|area| area.starts_with("page "));
        if !settings.is_empty() {
            writeln!(f, "Boot configuration changed: {}.", settings.join(", "))?;
        }
        if !pages.is_empty() {
            let descriptions: Vec<_> = pages
                .iter()
                .map(|area| area.trim_start_matches("page "))
                .collect();
            writeln!(f, "Memory pages changed: {}.", descriptions.join(", "))?;
        }
    }
    let contents_next = contents_next(report);
    let next = if areas.contains("guest policy") {
        "compare the changed guest policy with the restrictions required by your verifier."
    } else if areas.contains("CPU startup state") || areas.contains("platform settings") {
        "get the vendor's explanation for the changed CPU startup state and platform settings, then check them against your attestation policy."
    } else if areas.contains("identity/measurement metadata") {
        "verify the changed identity/measurement metadata against your trust policy."
    } else if areas.contains("relocation settings") {
        "ask the vendor to confirm the changed load addresses and register/page-table adjustments are intended."
    } else if areas.contains("page attributes") {
        "review changes to page sharing, measurement flags and page types; pages that become unmeasured or shared are no longer covered by the launch measurement."
    } else if areas.contains("page addresses or platform coverage") {
        "check which platforms load the added/removed pages, and get the vendor's explanation for the memory layout change."
    } else if areas.contains("boot parameters") || areas.contains("memory requirements") {
        "get the vendor's explanation for the changed memory requirements and boot-parameter layout."
    } else if areas.contains("platform masks") {
        "check how the platform masks select records for the platform you run."
    } else if areas.contains("page storage") {
        "compare explicit page bytes with zero-filled pages; storage changes may preserve contents."
    } else if areas.contains("page contents") {
        &contents_next
    } else if areas.contains("record loading order") {
        "ask the vendor why the record order changed."
    } else {
        "check that your loader and tooling support the new IGVM format."
    };
    writeln!(f, "Next: {next}")
}

/// The next step when only page contents changed, naming what the payload analysis found.
fn contents_next(report: &Report) -> String {
    let firmware = report.content.firmware.iter().any(|c| {
        c.modules.as_ref().is_some_and(|m| {
            m.changes
                .iter()
                .any(|c| c.change != ModuleChangeKind::DebugDataOnly)
        })
    });
    let mut subjects: Vec<String> = Vec::new();
    if firmware {
        subjects.push("the modified firmware modules".into());
    }
    let payloads: BTreeSet<&str> = report
        .content
        .components
        .iter()
        .flat_map(|c| [c.before_format, c.after_format])
        .flatten()
        .filter(|format| *format != Format::UefiFirmwareVolume || !firmware)
        .map(Format::label)
        .collect();
    for payload in payloads {
        subjects.push(format!("the changed {payload}"));
    }
    if subjects.is_empty() {
        return "ask the vendor which component the changed pages belong to and what changed, then update the reference measurement in your attestation policy.".into();
    }
    format!(
        "get the vendor's release notes or source changes for {} below, then update the reference measurement in your attestation policy.",
        subjects.join(" and ")
    )
}

fn artifact(f: &mut fmt::Formatter<'_>, label: &str, artifact: &Artifact) -> fmt::Result {
    writeln!(
        f,
        "{label:<8}IGVM v{}, {}, {} records, SHA-256 {}",
        artifact.format_version,
        size(artifact.size as u64),
        artifact.record_count,
        artifact.sha256
    )
}

fn size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} bytes")
    }
}

fn record(change: &Change) -> &Record {
    change
        .after
        .as_ref()
        .or(change.before.as_ref())
        .expect("change has a record")
}

fn action(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Added => "added",
        ChangeKind::Removed => "removed",
        ChangeKind::Modified => "modified",
        ChangeKind::Reordered => "reordered",
        ChangeKind::MaskReassigned => "mask reassigned",
    }
}

fn label(name: &str) -> String {
    match name {
        "supported_platform" => "Platform".into(),
        "vp_context" => "CPU startup state".into(),
        "page_data" => "Page".into(),
        "parameter_insert" => "Parameter placement".into(),
        "snp_id_block" => "SNP identity block".into(),
        "vbs_measurement" => "VBS measurement".into(),
        "corim_document" => "CoRIM document".into(),
        "corim_signature" => "CoRIM signature".into(),
        "relocatable_region" => "Relocatable region".into(),
        "page_table_relocation" => "Page-table relocation".into(),
        "vtl" => "Virtual trust level (VTL)".into(),
        "is_vtl2" => "VTL2 region".into(),
        "minimum_gpa" => "Minimum relocation address".into(),
        "maximum_gpa" => "Maximum relocation address".into(),
        "apply_rip_offset" => "Adjust RIP on relocation".into(),
        "apply_gdtr_offset" => "Adjust GDTR on relocation".into(),
        "error_range" => "Host-visible error range".into(),
        "payload_sha256" => "Stored contents".into(),
        "data_present" => "Initial data storage".into(),
        "data_type" => "Page type".into(),
        "gpa" => "Guest memory address".into(),
        "highest_vtl" => "Highest virtual trust level (VTL)".into(),
        "vtl2_protectable" => "VTL2 protectable".into(),
        "sev_features" => "SEV features".into(),
        "madt" => "Interrupt-controller table parameter (MADT)".into(),
        "rip" => "Entry point (RIP)".into(),
        "rsp" => "Stack pointer (RSP)".into(),
        "cr3" => "Page-table control (CR3)".into(),
        "srat" | "slit" | "pptt" => format!("{} table parameter", name.to_uppercase()),
        "vp_count" => "Processor count parameter".into(),
        "mmio_ranges" => "MMIO ranges parameter".into(),
        "memory_map" => "Memory map parameter".into(),
        "command_line" => "Command line parameter".into(),
        "device_tree" => "Device tree parameter".into(),
        "environment_info" => "Environment information parameter".into(),
        "cr0" | "cr4" | "efer" | "rflags" | "pat" | "vmpl" => name.to_uppercase(),
        _ => {
            let mut label = name.replace('_', " ");
            if let Some(first) = label.get_mut(..1) {
                first.make_ascii_uppercase();
            }
            label
        }
    }
}

fn value(field: &str, value: &Value) -> String {
    if value.is_null() {
        return "not specified".into();
    }
    if field == "data_present" {
        return if value == true {
            "bytes in file"
        } else {
            "zero-filled"
        }
        .into();
    }
    if matches!(field, "size" | "used_size" | "alignment") {
        let bytes = value.as_u64().expect("size is an unsigned integer");
        return if bytes >= 1024 {
            format!("{} ({bytes} bytes)", size(bytes))
        } else {
            size(bytes)
        };
    }
    if field == "data_type" {
        return match value.as_u64() {
            Some(0) => "normal".into(),
            Some(1) => "secrets".into(),
            Some(2) => "CPUID".into(),
            Some(3) => "CPUID XF".into(),
            _ => value.to_string(),
        };
    }
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn masks_changed(change: &Change) -> bool {
    match (&change.before, &change.after) {
        (Some(a), Some(b)) => a.compatibility_mask != b.compatibility_mask,
        _ => false,
    }
}

fn details(
    f: &mut fmt::Formatter<'_>,
    title: &str,
    changes: &[&Change],
    references: &mut Vec<&'static str>,
    verbose: bool,
) -> fmt::Result {
    let limit = if verbose { usize::MAX } else { DETAIL_LIMIT };
    if changes.is_empty() {
        return Ok(());
    }
    writeln!(f, "\n{title}: {}", changes.len())?;
    for change in changes.iter().take(limit) {
        let record = record(change);
        write!(f, "  {}: {}", action(change.kind), label(record.kind))?;
        if !record.identity.is_empty() && record.kind != "supported_platform" {
            write!(f, " {}", record.identity)?;
        }
        if !record.platforms.is_empty() {
            write!(f, " [{}]", record.platforms.join(", "))?;
        }
        writeln!(f)?;
        if let (Some(a), Some(b)) = (&change.before, &change.after) {
            for field in &change.fields {
                if field.ends_with("sha256") {
                    if record.kind == "vp_context" && change.fields.len() == 1 {
                        writeln!(
                            f,
                            "    CPU state bytes changed outside the displayed register fields"
                        )?;
                    } else {
                        writeln!(f, "    {}: changed", label(field))?;
                    }
                } else {
                    write!(
                        f,
                        "    {}: {} -> {}",
                        label(field),
                        value(field, &a.fields[field]),
                        value(field, &b.fields[field])
                    )?;
                    if record.kind == "vp_context"
                        && record
                            .platforms
                            .iter()
                            .any(|p| matches!(p.as_str(), "sev-snp" | "sev-es"))
                        && let Some(note) =
                            crate::annotations::explain(field, &a.fields[field], &b.fields[field])
                    {
                        let index = references
                            .iter()
                            .position(|reference| *reference == note.reference)
                            .unwrap_or_else(|| {
                                references.push(note.reference);
                                references.len() - 1
                            });
                        write!(f, " ({} [{}])", note.text, index + 1)?;
                    }
                    writeln!(f)?;
                }
            }
            if masks_changed(change) {
                writeln!(
                    f,
                    "    compatibility mask: {:#x} -> {:#x}",
                    a.compatibility_mask.unwrap_or_default(),
                    b.compatibility_mask.unwrap_or_default()
                )?;
            }
            if change.order_changed {
                writeln!(f, "    relative record order changed")?;
            }
        } else {
            for (field, v) in record
                .fields
                .as_object()
                .expect("record fields are objects")
            {
                let identity =
                    matches!(field.as_str(), "gpa" | "parameter_area_index" | "vp_index")
                        && value(field, v) == record.identity;
                if !field.ends_with("sha256") && !identity {
                    writeln!(f, "    {}: {}", label(field), value(field, v))?;
                }
            }
        }
    }
    if changes.len() > limit {
        writeln!(
            f,
            "  ... {} more changes; use --verbose",
            changes.len() - limit
        )?;
    }
    Ok(())
}

fn page_properties(record: &Record) -> String {
    let mut properties = vec![value("data_type", &record.fields["data_type"])];
    properties.push(
        if record.fields["data_present"] == true {
            "stored"
        } else {
            "implicit zero"
        }
        .into(),
    );
    for flag in ["shared", "unmeasured"] {
        if record.fields[flag] == true {
            properties.push(flag.into());
        }
    }
    properties.join(", ")
}

fn ranges(f: &mut fmt::Formatter<'_>, pages: &[&Change], verbose: bool) -> fmt::Result {
    let mut groups = BTreeMap::<_, Vec<u64>>::new();
    for change in pages {
        let record = record(change);
        let contents_only = change.fields == ["payload_sha256"];
        let mut description = if contents_only {
            "contents changed"
        } else {
            action(change.kind)
        }
        .to_string();
        let properties = page_properties(record);
        if properties != "normal, stored" {
            description.push_str(&format!(" ({properties})"));
        }
        if let (Some(a), Some(b)) = (&change.before, &change.after) {
            if page_properties(a) != page_properties(b) {
                description = format!(
                    "{} ({} -> {})",
                    action(change.kind),
                    page_properties(a),
                    page_properties(b)
                );
            }
            if !contents_only && change.fields.iter().any(|field| field == "payload_sha256") {
                description.push_str("; stored contents changed");
            }
            if masks_changed(change) {
                description.push_str(&format!(
                    "; mask {:#x} -> {:#x}",
                    a.compatibility_mask.unwrap_or_default(),
                    b.compatibility_mask.unwrap_or_default()
                ));
            }
        }
        if change.order_changed && change.kind != ChangeKind::Reordered {
            description.push_str("; reordered");
        }
        let key = (
            description,
            &record.platforms,
            change.before.as_ref().and_then(|r| r.compatibility_mask),
            change.after.as_ref().and_then(|r| r.compatibility_mask),
        );
        let gpa = u64::from_str_radix(record.identity.trim_start_matches("0x"), 16)
            .expect("page GPA is hexadecimal");
        groups.entry(key).or_default().push(gpa);
    }
    let mut ranges = Vec::new();
    for (key, mut addresses) in groups {
        addresses.sort_unstable();
        let mut start = addresses[0];
        let mut end = start + 4096;
        for &address in &addresses[1..] {
            if address == end {
                end += 4096;
            } else {
                ranges.push((start, end, key.clone()));
                start = address;
                end = start + 4096;
            }
        }
        ranges.push((start, end, key));
    }
    ranges.sort_by(|a, b| (b.1 - b.0).cmp(&(a.1 - a.0)).then_with(|| a.cmp(b)));
    writeln!(
        f,
        "\nChanged guest-memory ranges, largest first (end address excluded):"
    )?;
    let limit = if verbose { usize::MAX } else { RANGE_LIMIT };
    for (start, end, (description, platforms, _, _)) in ranges.iter().take(limit) {
        writeln!(
            f,
            "  {start:#x}..{end:#x}: {} {}, {description} [{}]",
            (end - start) / 4096,
            if end - start == 4096 { "page" } else { "pages" },
            platforms.join(", ")
        )?;
    }
    if ranges.len() > limit {
        writeln!(
            f,
            "  ... {} more ranges; use --verbose for every record",
            ranges.len() - limit
        )?;
    }
    Ok(())
}

/// `duplicate` adds the file GUID so modules that share a UI name stay distinguishable.
fn module_name(change: &ModuleChange, duplicate: bool) -> String {
    let name = match &change.name {
        Some(name) if duplicate => format!("{name} {{{}}}", change.guid),
        Some(name) => name.clone(),
        None => change.guid.clone(),
    };
    let mut notes = Vec::new();
    match change.file_type {
        FileType::Freeform => notes.push("freeform file".to_string()),
        FileType::Raw => notes.push("raw file".to_string()),
        FileType::FirmwareVolumeImage => notes.push("firmware volume image file".to_string()),
        FileType::NonFfsVolume => notes.push(format!("file system {}", change.guid)),
        _ => {}
    }
    match change.differing_bytes {
        Some(1) => notes.push("1 byte differs".to_string()),
        Some(count) => notes.push(format!("{count} bytes differ")),
        None => {}
    }
    if change.undecoded_sections {
        notes.push("contains undecoded sections".into());
    }
    if notes.is_empty() {
        name
    } else {
        format!("{name} ({})", notes.join(", "))
    }
}

fn component_heading(component: &Component) -> String {
    let format = match (component.before_format, component.after_format) {
        (Some(a), Some(b)) if a == b => a.label().to_string(),
        (Some(a), Some(b)) => format!("{} -> {}", a.label(), b.label()),
        (Some(a), None) => format!("{} (before only)", a.label()),
        (None, Some(b)) => format!("{} (after only)", b.label()),
        (None, None) => unreachable!("a component is found in at least one file"),
    };
    let pages = component.changed_pages;
    let mut heading = format!(
        "{}..{}: {format} [{}], {pages} {}",
        component.start,
        component.end,
        component.platforms.join(", "),
        if pages == 1 { "page" } else { "pages" }
    );
    if component.unmeasured_changed_pages > 0 {
        heading.push_str(&format!(
            " ({} unmeasured or shared)",
            component.unmeasured_changed_pages
        ));
    }
    if let Some(sections) = &component.changed_sections {
        if sections.is_empty() {
            heading.push_str("; section contents unchanged");
        } else {
            let kind = if component.after_format == Some(Format::Elf) {
                "ELF"
            } else {
                "PE"
            };
            heading.push_str(&format!(
                "; changed {kind} sections: {}",
                sections.join(", ")
            ));
        }
    }
    heading
}

fn capitalized(text: &str) -> String {
    let mut text = text.to_string();
    if let Some(first) = text.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    text
}

fn platform_counts(counts: &BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(platform, count)| {
            format!(
                "{count} {} [{platform}]",
                if *count == 1 { "page" } else { "pages" }
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn area_short(area: Area) -> &'static str {
    match area {
        Area::VpContext => "VP context",
        Area::GuestPolicy => "guest policy",
        Area::IdentityRecords => "ID block/VBS measurement/CoRIM",
        Area::PlatformDefinitions => "platform definitions",
        Area::BootParameters => "boot parameters",
    }
}

fn area_label(area: Area) -> &'static str {
    match area {
        Area::VpContext => "CPU startup state (VP context)",
        Area::GuestPolicy => "guest policy",
        Area::IdentityRecords => {
            "identity and endorsement records (SNP ID block, VBS measurement, CoRIM)"
        }
        Area::PlatformDefinitions => "platform definitions",
        Area::BootParameters => "boot parameters, memory requirements and relocation",
    }
}

/// "Launch measurement changes [..]; unchanged [..]" from the computed digests. SEV-SNP falls
/// back to the igvmmeasure value when the igvm crate could not compute one.
fn digest_verdict(launch: &LaunchMeasurement) -> String {
    let value = |file: &FileMeasurements, platform: &str| -> Option<String> {
        match file.igvm.get(platform) {
            Some(Ok(digest)) => Some(digest.clone()),
            _ if platform == "sev-snp" => file.igvmmeasure.as_ref().map(|m| m.native_zero.clone()),
            _ => None,
        }
    };
    let platforms: BTreeSet<&String> = launch
        .before
        .igvm
        .keys()
        .chain(launch.after.igvm.keys())
        .collect();
    let (mut changes, mut same, mut unknown) = (Vec::new(), Vec::new(), Vec::new());
    for platform in platforms {
        let in_before = launch.before.igvm.contains_key(platform);
        let in_after = launch.after.igvm.contains_key(platform);
        match (
            value(&launch.before, platform),
            value(&launch.after, platform),
        ) {
            (Some(a), Some(b)) if a == b => same.push(platform.as_str()),
            (Some(_), Some(_)) => changes.push(platform.as_str()),
            _ if in_before != in_after => changes.push(platform.as_str()),
            _ => unknown.push(platform.as_str()),
        }
    }
    let mut parts = Vec::new();
    if !changes.is_empty() {
        parts.push(format!("changes [{}]", changes.join(", ")));
    }
    if !same.is_empty() {
        parts.push(format!("unchanged [{}]", same.join(", ")));
    }
    if !unknown.is_empty() {
        parts.push(format!("not computed [{}]", unknown.join(", ")));
    }
    format!(
        "Launch measurement {} (from the computed digests below).",
        parts.join("; ")
    )
}

/// Renders [`crate::Attestation`]: what the change means for remote attestation.
pub(crate) fn attestation(report: &Report, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let Some(impact) = &report.attestation else {
        return Ok(());
    };
    writeln!(f, "\nAttestation impact:")?;
    // The verdict comes from the computed digests when there are any: page records alone miss
    // address-only changes of unmeasured pages and flag mask-only changes.
    let verdict = report.launch_measurement.as_ref().map(digest_verdict);
    if let Some(verdict) = &verdict {
        writeln!(f, "  {verdict}")?;
    }
    let mut unchanged = Vec::new();
    if impact.measured_page_changes.is_empty() {
        unchanged.push("measured pages");
    } else {
        writeln!(
            f,
            "  Measured page data changed: {}.{}",
            platform_counts(&impact.measured_page_changes),
            if verdict.is_none() {
                " The launch measurement changes."
            } else {
                ""
            }
        )?;
    }
    if impact.unmeasured_page_changes.is_empty() {
        unchanged.push("unmeasured/shared pages");
    } else {
        writeln!(
            f,
            "  Unmeasured or shared page data changed: {}. IGVM excludes their contents from the launch measurement; an unmeasured page's address still counts.",
            platform_counts(&impact.unmeasured_page_changes)
        )?;
    }
    for area in Area::ALL {
        let label = area_label(area);
        match impact.changed.iter().find(|c| c.area == area) {
            None => unchanged.push(area_short(area)),
            Some(c) if c.platforms.is_empty() => writeln!(f, "  {} changed.", capitalized(label))?,
            Some(c) => writeln!(
                f,
                "  {} changed [{}].",
                capitalized(label),
                c.platforms.join(", ")
            )?,
        }
    }
    if !unchanged.is_empty() {
        writeln!(f, "  Unchanged: {}.", unchanged.join(", "))?;
    }
    Ok(())
}

/// Lists recognized payloads that contain changed pages.
pub(crate) fn payloads(report: &Report, f: &mut fmt::Formatter<'_>, verbose: bool) -> fmt::Result {
    let content = &report.content;
    if content.components.is_empty() && content.unidentified.is_empty() && content.notes.is_empty()
    {
        return Ok(());
    }
    let shown = if verbose {
        content.components.len()
    } else {
        content.components.len().min(RANGE_LIMIT)
    };
    for component in &content.components[..shown] {
        writeln!(f, "  {}", component_heading(component))?;
        if let Some(functions) = &component.function_changes {
            let mut parts = Vec::new();
            for (label, names) in [
                ("changed", &functions.changed),
                ("added", &functions.added),
                ("removed", &functions.removed),
            ] {
                if names.is_empty() {
                    continue;
                }
                let shown = if verbose || names.len() <= NAME_LIMIT + 2 {
                    names.len()
                } else {
                    NAME_LIMIT
                };
                let mut list = names[..shown].join(", ");
                if shown < names.len() {
                    list.push_str(&format!(", ... {} more", names.len() - shown));
                }
                parts.push(format!("{} {label}: {list}", names.len()));
            }
            if parts.is_empty() {
                writeln!(f, "    functions (symbol table): none changed")?;
            } else {
                for part in parts {
                    writeln!(f, "    functions {part}")?;
                }
            }
        }
        for change in &component.text_changes {
            let mut parts = Vec::new();
            if !change.removed.is_empty() {
                parts.push(format!("removed {}", change.removed.join(" ")));
            }
            if !change.added.is_empty() {
                parts.push(format!("added {}", change.added.join(" ")));
            }
            if parts.is_empty() {
                parts.push("same words, different spacing or order".into());
            }
            writeln!(f, "    {}: {}", change.section, parts.join("; "))?;
        }
    }
    if shown < content.components.len() {
        writeln!(
            f,
            "  ... {} more payloads (--verbose)",
            content.components.len() - shown
        )?;
    }
    if !content.unidentified.is_empty() {
        let groups: Vec<_> = content
            .unidentified
            .iter()
            .map(|u| format!("{} [{}]", u.changed_pages, u.platforms.join(", ")))
            .collect();
        writeln!(f, "  outside recognized payloads: {}", groups.join(", "))?;
    }
    for note in &content.notes {
        writeln!(f, "  Note: {note}")?;
    }
    Ok(())
}

const SMALL_DIFFERENCE: usize = 64;
const PHASES: [&str; 6] = [
    "SEC",
    "PEI",
    "DXE",
    "MM",
    "UEFI applications",
    "Other files",
];

/// Lists firmware module changes, grouped by the PI boot phase that runs them.
/// Names shown per boot phase in the default output.
const NAME_LIMIT: usize = 8;

/// Short module label for the default output: the UI name (or GUID), with a note for files
/// that are not drivers.
fn short_name(change: &ModuleChange) -> String {
    let name = change.name.clone().unwrap_or_else(|| change.guid.clone());
    match change.file_type {
        FileType::Freeform => format!("{name} (freeform file)"),
        FileType::Raw if change.name.is_none() => format!("{name} (raw file)"),
        _ => name,
    }
}

pub(crate) fn modules(report: &Report, f: &mut fmt::Formatter<'_>, verbose: bool) -> fmt::Result {
    for firmware in &report.content.firmware {
        let platforms = firmware.platforms.join(", ");
        let Some(modules) = &firmware.modules else {
            if let Some(error) = &firmware.error {
                writeln!(f, "\nFirmware modules [{platforms}]: not decoded ({error})")?;
            }
            continue;
        };
        let count = |kind| modules.changes.iter().filter(|c| c.change == kind).count();
        let mut counts = Vec::new();
        for (kind, text) in [
            (ModuleChangeKind::Modified, "modified"),
            (ModuleChangeKind::Added, "added"),
            (ModuleChangeKind::Removed, "removed"),
            (
                ModuleChangeKind::DebugDataOnly,
                "changed only in PE debug data (timestamps, checksum, CodeView path)",
            ),
        ] {
            let n = count(kind);
            if n > 0 {
                counts.push(format!("{n} {text}"));
            }
        }
        counts.push(format!("{} unchanged", modules.unchanged));
        writeln!(f, "\nFirmware modules [{platforms}]: {}", counts.join(", "))?;
        if verbose && count(ModuleChangeKind::Modified) > 0 {
            writeln!(
                f,
                "  Modified modules show a byte count when they kept their size; the rest changed size. Counts are taken with PE debug data masked, and counts of {SMALL_DIFFERENCE} or fewer can come from embedded strings such as build paths."
            )?;
        }
        for (kind, title) in [
            (ModuleChangeKind::Modified, ""),
            (ModuleChangeKind::Added, "added "),
            (ModuleChangeKind::Removed, "removed "),
            (ModuleChangeKind::DebugDataOnly, "debug data only "),
        ] {
            let changes: Vec<&ModuleChange> = modules
                .changes
                .iter()
                .filter(|c| c.change == kind)
                .collect();
            if changes.is_empty() {
                continue;
            }
            let mut seen = BTreeMap::<&str, usize>::new();
            for change in &changes {
                if let Some(name) = &change.name {
                    *seen.entry(name).or_default() += 1;
                }
            }
            for phase in PHASES {
                let in_phase: Vec<&&ModuleChange> =
                    changes.iter().filter(|c| c.boot_phase == phase).collect();
                if in_phase.is_empty() {
                    continue;
                }
                let names: Vec<String> = if verbose {
                    in_phase
                        .iter()
                        .map(|c| {
                            let duplicate = c.name.as_deref().is_some_and(|n| seen[n] > 1);
                            module_name(c, duplicate)
                        })
                        .collect()
                } else {
                    // One entry per name, with a count when several files share it.
                    let mut names: Vec<String> = Vec::new();
                    let mut counted = BTreeMap::<String, usize>::new();
                    for c in &in_phase {
                        let name = short_name(c);
                        if *counted.entry(name.clone()).or_default() == 0 {
                            names.push(name.clone());
                        }
                        *counted.get_mut(&name).expect("inserted") += 1;
                    }
                    names
                        .into_iter()
                        .map(|n| match counted[&n] {
                            1 => n,
                            k => format!("{n} ({k})"),
                        })
                        .collect()
                };
                // Large debug-data-only sets are counted, not listed, unless --verbose.
                if kind == ModuleChangeKind::DebugDataOnly && !verbose && changes.len() > NAME_LIMIT
                {
                    continue;
                }
                let shown = if verbose || names.len() <= NAME_LIMIT + 2 {
                    names.len()
                } else {
                    NAME_LIMIT
                };
                write!(
                    f,
                    "  {title}{phase} ({}): {}",
                    in_phase.len(),
                    names[..shown].join(", ")
                )?;
                if shown < names.len() {
                    write!(f, ", ... {} more", names.len() - shown)?;
                }
                writeln!(f)?;
            }
            if kind == ModuleChangeKind::DebugDataOnly && !verbose && changes.len() > NAME_LIMIT {
                writeln!(
                    f,
                    "  debug data only: {} module{} (names with --verbose)",
                    changes.len(),
                    if changes.len() == 1 { "" } else { "s" }
                )?;
            }
        }
    }
    Ok(())
}

struct MeasurementRow {
    label: String,
    before: Option<Result<String, String>>,
    after: Option<Result<String, String>>,
}

fn measurement_rows(launch: &LaunchMeasurement) -> Vec<MeasurementRow> {
    let platforms: BTreeSet<&String> = launch
        .before
        .igvm
        .keys()
        .chain(launch.after.igvm.keys())
        .collect();
    let mut rows = Vec::new();
    for platform in platforms {
        let register = match platform.as_str() {
            "sev-snp" => "launch digest",
            "tdx" => "MRTD",
            _ => "boot measurement digest",
        };
        rows.push(MeasurementRow {
            label: format!("{platform} {register}, igvm crate"),
            before: launch.before.igvm.get(platform).cloned(),
            after: launch.after.igvm.get(platform).cloned(),
        });
        if platform != "sev-snp" {
            continue;
        }
        let sides = [&launch.before, &launch.after];
        // When every SNP ID block in the files confirms the igvm crate's value, the vendor's
        // loader is known to measure that way, and the alternative conventions are noise.
        let confirmed = sides.iter().any(|f| f.igvmmeasure.is_some())
            && sides.iter().all(|f| match &f.igvmmeasure {
                None => true,
                Some(m) => m.id_block_launch_digest.as_ref().is_some_and(|declared| {
                    f.igvm.get("sev-snp").and_then(|r| r.as_ref().ok()) == Some(declared)
                }),
            });
        if confirmed {
            continue;
        }
        let zero_pages = sides
            .iter()
            .any(|f| f.igvmmeasure.as_ref().is_some_and(|m| m.zero_pages > 0));
        let value = |f: &FileMeasurements, pick: fn(&SnpMeasurement) -> &String| {
            f.igvmmeasure.as_ref().map(|m| Ok(pick(m).clone()))
        };
        if zero_pages {
            rows.push(MeasurementRow {
                label: "sev-snp launch digest, igvmmeasure --native-zero (zero-filled pages as ZERO pages)".into(),
                before: value(&launch.before, |m| &m.native_zero),
                after: value(&launch.after, |m| &m.native_zero),
            });
        }
        // igvmmeasure's default differs from the igvm crate only for shared pages and
        // multi-page parameter areas; show it only when it gives a different value.
        let default_differs = sides.iter().any(|f| {
            f.igvmmeasure.as_ref().is_some_and(|m| {
                f.igvm.get("sev-snp").and_then(|r| r.as_ref().ok()) != Some(&m.zero_as_normal)
            })
        });
        if default_differs {
            rows.push(MeasurementRow {
                label: "sev-snp launch digest, igvmmeasure default".into(),
                before: value(&launch.before, |m| &m.zero_as_normal),
                after: value(&launch.after, |m| &m.zero_as_normal),
            });
        }
    }
    rows
}

/// Renders the computed launch digests.
pub(crate) fn launch(report: &Report, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let Some(launch) = &report.launch_measurement else {
        return Ok(());
    };
    writeln!(
        f,
        "\nLaunch measurements (compare with the vendor's published values and your attestation reports):"
    )?;
    let show = |value: &Option<Result<String, String>>| match value {
        None => "platform not in this file".to_string(),
        Some(Ok(digest)) => digest.clone(),
        Some(Err(error)) => format!("not computed ({error})"),
    };
    let rows = measurement_rows(launch);
    for row in &rows {
        writeln!(f, "  {}:", row.label)?;
        if matches!(row.before, Some(Ok(_))) && row.before == row.after {
            writeln!(f, "    unchanged: {}", show(&row.before))?;
        } else if row.before.is_some() && row.before == row.after {
            writeln!(f, "    {}", show(&row.before))?;
        } else {
            writeln!(f, "    before: {}", show(&row.before))?;
            writeln!(f, "    after:  {}", show(&row.after))?;
        }
    }
    let same = launch
        .before
        .igvmmeasure
        .as_ref()
        .map(|b| (&b.id_block_launch_digest, b.shared_pages))
        == launch
            .after
            .igvmmeasure
            .as_ref()
            .map(|a| (&a.id_block_launch_digest, a.shared_pages));
    for (side, file) in [("before", &launch.before), ("after", &launch.after)] {
        let Some(m) = &file.igvmmeasure else { continue };
        if same && side == "after" {
            continue;
        }
        let label = if same { "before and after" } else { side };
        if let Some(declared) = &m.id_block_launch_digest {
            let matches: Vec<&str> = rows
                .iter()
                .filter(|row| row.label.starts_with("sev-snp"))
                .filter(|row| {
                    let value = if side != "after" {
                        &row.before
                    } else {
                        &row.after
                    };
                    matches!(value, Some(Ok(digest)) if digest == declared)
                })
                .map(|row| row.label.split(", ").nth(1).unwrap_or(&row.label))
                .collect();
            if matches.is_empty() {
                writeln!(
                    f,
                    "  SNP ID block launch digest ({label}): {declared}; differs from every computed value. The vendor's loader may measure differently or the ID block may be stale; confirm with the vendor."
                )?;
            } else {
                writeln!(
                    f,
                    "  SNP ID block launch digest ({label}): matches the {} value.",
                    matches.join(" and ")
                )?;
            }
        }
        if m.shared_pages > 0 && rows.iter().any(|r| r.label.contains("igvmmeasure")) {
            writeln!(
                f,
                "  Note ({label}): {} sev-snp pages are flagged shared. igvmmeasure measures them; the igvm crate skips them, as the IGVM definition says shared pages are not part of the launch measurement.",
                m.shared_pages
            )?;
        }
    }
    let vmsas: BTreeSet<usize> = [&launch.before, &launch.after]
        .iter()
        .filter_map(|f| f.igvmmeasure.as_ref().map(|m| m.vmsa_count))
        .collect();
    if !vmsas.is_empty() {
        let counts: Vec<String> = vmsas.iter().map(usize::to_string).collect();
        writeln!(
            f,
            "  SEV-SNP values measure the file's VMSAs ({}) as stored. QEMU/KVM does not: QEMU copies selected registers into each vCPU and KVM measures the VMSA it builds (QEMU target/i386/sev.c, sev_apply_cpu_context), and more vCPUs add VMSAs. If your guest's MEASUREMENT differs, use the vendor's published value for your vCPU count.",
            counts.join(" / ")
        )?;
    }
    Ok(())
}
