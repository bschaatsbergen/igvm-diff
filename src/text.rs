use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde_json::Value;

use crate::{Artifact, Change, ChangeKind, Record, Report};

const DETAIL_LIMIT: usize = 12;
const RANGE_LIMIT: usize = 8;

pub(crate) fn summary(report: &Report, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    if report.has_changes() {
        let count = report.findings.len();
        let noun = if count == 1 { "change" } else { "changes" };
        writeln!(f, "Files differ: {count} record {noun}")?;
    } else {
        writeln!(f, "Files are identical")?;
    }
    artifact(f, "Before", &report.inputs.before)?;
    artifact(f, "After", &report.inputs.after)?;
    writeln!(f, "Scope: whole file")?;

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
    )?;
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
        writeln!(f, "\nMemory pages (4 KiB each): {}", counts.join(", "))?;
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
        details(f, "Page attribute changes", &attributes, &mut references)?;
        ranges(f, &pages)?;
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
    writeln!(f, "\nLaunch measurement: not computed")?;
    writeln!(
        f,
        "Full details and hashes: --verbose; machine-readable: --format json"
    )
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
    if areas.len() == 1 && areas.contains("page contents") {
        let count = report.findings.len();
        let noun = if count == 1 { "page" } else { "pages" };
        writeln!(
            f,
            "\nContents changed in {count} memory {noun} (4 KiB each)."
        )?;
        writeln!(
            f,
            "No changes found to page addresses, page attributes or boot-setting records."
        )?;
    } else {
        let (pages, settings): (Vec<_>, Vec<_>) = areas
            .iter()
            .copied()
            .partition(|area| area.starts_with("page "));
        writeln!(f)?;
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
    let next = if areas.contains("guest policy") {
        "compare the changed guest policy with the restrictions required by your verifier."
    } else if areas.contains("CPU startup state") || areas.contains("platform settings") {
        "review startup configuration and memory layout in the image builder's source/build diff."
    } else if areas.contains("identity/measurement metadata") {
        "verify the changed identity/measurement metadata against your trust policy."
    } else if areas.contains("relocation settings") {
        "review allowed load addresses and register/page-table adjustments in the image builder and loader."
    } else if areas.contains("page attributes") {
        "review changes to page sharing, measurement flags and page types."
    } else if areas.contains("page addresses or platform coverage") {
        "check the build's memory layout and which platforms load the added/removed pages."
    } else if areas.contains("boot parameters") || areas.contains("memory requirements") {
        "check the image builder's memory requirements and boot-parameter layout."
    } else if areas.contains("platform masks") {
        "check how the platform masks select records for the intended platform."
    } else if areas.contains("page storage") {
        "compare explicit page bytes with zero-filled pages; storage changes may preserve contents."
    } else if areas.contains("page contents") {
        "identify the changed component using the build's symbols/linker map, then review its source diff."
    } else if areas.contains("record loading order") {
        "review the loader/build changes that alter record order."
    } else {
        "review the image-format change and loader compatibility."
    };
    writeln!(f, "Next: {next}")
}

fn artifact(f: &mut fmt::Formatter<'_>, label: &str, artifact: &Artifact) -> fmt::Result {
    writeln!(
        f,
        "{label}: IGVM v{}, {}, {} records",
        artifact.format_version,
        size(artifact.size as u64),
        artifact.record_count
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
) -> fmt::Result {
    if changes.is_empty() {
        return Ok(());
    }
    writeln!(f, "\n{title}: {}", changes.len())?;
    for change in changes.iter().take(DETAIL_LIMIT) {
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
    if changes.len() > DETAIL_LIMIT {
        writeln!(
            f,
            "  ... {} more changes; use --verbose",
            changes.len() - DETAIL_LIMIT
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

fn ranges(f: &mut fmt::Formatter<'_>, pages: &[&Change]) -> fmt::Result {
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
    for (start, end, (description, platforms, _, _)) in ranges.iter().take(RANGE_LIMIT) {
        writeln!(
            f,
            "  {start:#x}..{end:#x}: {} {}, {description} [{}]",
            (end - start) / 4096,
            if end - start == 4096 { "page" } else { "pages" },
            platforms.join(", ")
        )?;
    }
    if ranges.len() > RANGE_LIMIT {
        writeln!(
            f,
            "  ... {} more ranges; use --verbose for every record",
            ranges.len() - RANGE_LIMIT
        )?;
    }
    Ok(())
}
