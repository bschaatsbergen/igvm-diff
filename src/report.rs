use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::Serialize;
use serde_json::Value;

use crate::{content::Content, image::Image};

#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    pub sha256: String,
    pub size: usize,
    pub format_version: u32,
    pub record_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub index: usize,
    pub kind: &'static str,
    pub platforms: Vec<String>,
    pub compatibility_mask: Option<u32>,
    pub identity: String,
    pub fields: Value,
}

impl Record {
    fn key(&self) -> (&str, &[String], &str) {
        (self.kind, &self.platforms, &self.identity)
    }

    fn equivalent(&self, other: &Self) -> bool {
        self.key() == other.key() && self.fields == other.fields
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
    Reordered,
    MaskReassigned,
}

#[derive(Debug, Serialize)]
pub struct Change {
    pub kind: ChangeKind,
    pub before: Option<Record>,
    pub after: Option<Record>,
    pub fields: Vec<String>,
    pub order_changed: bool,
}

#[derive(Debug, Serialize)]
pub struct Inputs {
    pub before: Artifact,
    pub after: Artifact,
}

#[derive(Debug, Serialize)]
pub struct Tool {
    pub version: &'static str,
    pub parser: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Comparison {
    pub file_bytes_changed: bool,
    pub format_changed: bool,
    pub changed_records: usize,
    pub order_changed: bool,
}

/// A group of non-page records whose change can matter for attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Area {
    VpContext,
    GuestPolicy,
    IdentityRecords,
    PlatformDefinitions,
    BootParameters,
}

impl Area {
    pub const ALL: [Area; 5] = [
        Area::VpContext,
        Area::GuestPolicy,
        Area::IdentityRecords,
        Area::PlatformDefinitions,
        Area::BootParameters,
    ];
}

#[derive(Debug, Serialize)]
pub struct ChangedArea {
    pub area: Area,
    /// Affected isolation platforms; empty for records without a compatibility mask.
    pub platforms: Vec<String>,
}

/// What the change means for remote attestation, derived only from the IGVM page data flags:
/// `unmeasured` pages are imported unmeasured and `shared` pages are not part of the launch
/// measurement. Platforms without a launch measurement (`native`) are left out.
#[derive(Debug, Serialize)]
pub struct Attestation {
    /// Changed page records that are measured in at least one of the two files, per platform.
    pub measured_page_changes: BTreeMap<String, usize>,
    /// Changed page records that are unmeasured or shared in both files, per platform.
    pub unmeasured_page_changes: BTreeMap<String, usize>,
    pub changed: Vec<ChangedArea>,
}

fn attestation(findings: &[Change]) -> Option<Attestation> {
    let mut impact = Attestation {
        measured_page_changes: BTreeMap::new(),
        unmeasured_page_changes: BTreeMap::new(),
        changed: Vec::new(),
    };
    let mut areas = BTreeMap::<Area, BTreeSet<String>>::new();
    let mut any = false;
    for change in findings {
        let records: Vec<&Record> = change.before.iter().chain(&change.after).collect();
        let platforms: BTreeSet<&String> = records
            .iter()
            .flat_map(|r| &r.platforms)
            .filter(|p| p.as_str() != "native")
            .collect();
        if records.iter().any(|r| !r.platforms.is_empty()) && platforms.is_empty() {
            continue;
        }
        any = true;
        let kind = records[0].kind;
        if kind == "page_data" {
            let measured = records
                .iter()
                .any(|r| r.fields["unmeasured"] != true && r.fields["shared"] != true);
            let target = if measured {
                &mut impact.measured_page_changes
            } else {
                &mut impact.unmeasured_page_changes
            };
            for platform in platforms {
                *target.entry(platform.clone()).or_default() += 1;
            }
            continue;
        }
        let area = match kind {
            "vp_context" => Area::VpContext,
            "guest_policy" => Area::GuestPolicy,
            "snp_id_block" | "vbs_measurement" | "corim_document" | "corim_signature" => {
                Area::IdentityRecords
            }
            "supported_platform" => Area::PlatformDefinitions,
            _ => Area::BootParameters,
        };
        areas
            .entry(area)
            .or_default()
            .extend(platforms.into_iter().cloned());
    }
    impact.changed = areas
        .into_iter()
        .map(|(area, platforms)| ChangedArea {
            area,
            platforms: platforms.into_iter().collect(),
        })
        .collect();
    any.then_some(impact)
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    pub scope: &'static str,
    pub inputs: Inputs,
    pub comparison: Comparison,
    pub findings: Vec<Change>,
    /// Absent when no isolation platform is affected.
    pub attestation: Option<Attestation>,
    /// Payloads that contain changed page contents, per platform.
    pub content: Content,
    /// `computed` when `launch_measurement` holds launch digests, otherwise `not_computed`.
    pub measurement: &'static str,
    pub launch_measurement: Option<crate::LaunchMeasurement>,
    pub diagnostics: Vec<String>,
    /// Platforms defined in either file.
    pub platforms: BTreeSet<String>,
    /// The platform the report is restricted to, if any (`--platform`).
    pub focus: Option<String>,
}

impl Report {
    pub fn has_changes(&self) -> bool {
        self.comparison.file_bytes_changed
    }

    /// Restricts the report to one platform: findings for other platforms, their payload and
    /// module analysis, and their launch measurements are removed. Records that apply to every
    /// platform (no compatibility mask) are kept. File-level facts (hashes, `has_changes`) stay.
    pub fn focus(&mut self, platform: &str) {
        let keep = |platforms: &mut Vec<String>| {
            if platforms.is_empty() {
                return true;
            }
            let selected = platforms.iter().any(|p| p == platform);
            platforms.retain(|p| p == platform);
            selected
        };
        self.findings.retain_mut(|change| {
            let mut kept = false;
            for record in change.before.iter_mut().chain(change.after.iter_mut()) {
                kept |= keep(&mut record.platforms);
            }
            kept
        });
        self.comparison.changed_records = self.findings.len();
        self.attestation = attestation(&self.findings);
        self.content
            .components
            .retain_mut(|c| keep(&mut c.platforms) && !c.platforms.is_empty());
        self.content
            .firmware
            .retain_mut(|c| keep(&mut c.platforms) && !c.platforms.is_empty());
        self.content
            .unidentified
            .retain_mut(|c| keep(&mut c.platforms) && !c.platforms.is_empty());
        self.content
            .notes
            .retain(|note| note.starts_with(&format!("{platform}:")));
        if let Some(launch) = &mut self.launch_measurement {
            for side in [&mut launch.before, &mut launch.after] {
                side.igvm.retain(|name, _| name == platform);
                if platform != "sev-snp" {
                    side.igvmmeasure = None;
                }
            }
            let sides = [&launch.before, &launch.after];
            self.measurement = if sides.iter().any(|f| f.igvm.values().any(Result::is_ok)) {
                "computed"
            } else {
                "not_computed"
            };
            if sides.iter().all(|f| f.igvm.is_empty()) {
                self.launch_measurement = None;
            }
        }
        self.focus = Some(platform.to_string());
    }
}

pub(crate) fn compare(before: Image, after: Image) -> Report {
    let mut groups = BTreeMap::<_, (Vec<usize>, Vec<usize>)>::new();
    for record in &before.records {
        groups.entry(record.key()).or_default().0.push(record.index);
    }
    for record in &after.records {
        groups.entry(record.key()).or_default().1.push(record.index);
    }
    let mut pairs = Vec::new();
    let mut findings = Vec::new();
    let mut diagnostics = Vec::new();
    for ((kind, _, identity), (left, right)) in groups {
        let duplicate = left.len() > 1 || right.len() > 1;
        let same_sequence = left.len() == right.len()
            && left
                .iter()
                .zip(&right)
                .all(|(&a, &b)| before.records[a].equivalent(&after.records[b]));
        if !left.is_empty() && !right.is_empty() && (!duplicate || same_sequence) {
            pairs.extend(left.into_iter().zip(right));
        } else {
            if duplicate && !left.is_empty() && !right.is_empty() {
                diagnostics.push(format!("Ambiguous alignment for {kind} {identity}: repeated identities are shown as removals and additions."));
            }
            for index in left {
                findings.push(Change {
                    kind: ChangeKind::Removed,
                    before: Some(before.records[index].clone()),
                    after: None,
                    fields: Vec::new(),
                    order_changed: false,
                });
            }
            for index in right {
                findings.push(Change {
                    kind: ChangeKind::Added,
                    before: None,
                    after: Some(after.records[index].clone()),
                    fields: Vec::new(),
                    order_changed: false,
                });
            }
        }
    }
    pairs.sort_unstable();
    let mut after_order = pairs.clone();
    after_order.sort_unstable_by_key(|(_, right)| *right);
    let ranks: BTreeMap<_, _> = after_order
        .into_iter()
        .enumerate()
        .map(|(rank, pair)| (pair, rank))
        .collect();
    let mut order_changed = false;
    for (rank, &(left, right)) in pairs.iter().enumerate() {
        let a = &before.records[left];
        let b = &after.records[right];
        let moved = ranks[&(left, right)] != rank;
        order_changed |= moved;
        let fields: Vec<String> = a
            .fields
            .as_object()
            .expect("record fields are objects")
            .keys()
            .filter(|key| a.fields[*key] != b.fields[*key])
            .cloned()
            .collect();
        let kind = if !fields.is_empty() {
            ChangeKind::Modified
        } else if moved {
            ChangeKind::Reordered
        } else if a.compatibility_mask != b.compatibility_mask {
            ChangeKind::MaskReassigned
        } else {
            continue;
        };
        findings.push(Change {
            kind,
            before: Some(a.clone()),
            after: Some(b.clone()),
            fields,
            order_changed: moved,
        });
    }
    findings.sort_by_key(|change| {
        (
            change
                .before
                .as_ref()
                .map(|record| record.index)
                .unwrap_or(usize::MAX),
            change
                .after
                .as_ref()
                .map(|record| record.index)
                .unwrap_or(usize::MAX),
        )
    });
    let file_bytes_changed = before.artifact.sha256 != after.artifact.sha256;
    let format_changed = before.artifact.format_version != after.artifact.format_version;
    if before.unreferenced_sha256 != after.unreferenced_sha256 {
        diagnostics.push("Changes to unreferenced data are outside the records and payloads compared by this report. Review the file layout and build output.".into());
    } else if file_bytes_changed && findings.is_empty() && !format_changed {
        diagnostics.push("File bytes differ without supported record changes. File offsets, padding, or unreferenced data may differ; this does not establish semantic equivalence.".into());
    }
    Report {
        schema_version: 2,
        tool: Tool {
            version: env!("CARGO_PKG_VERSION"),
            parser: "igvm 0.5.0",
        },
        scope: "whole_file",
        inputs: Inputs {
            before: before.artifact,
            after: after.artifact,
        },
        comparison: Comparison {
            file_bytes_changed,
            format_changed,
            changed_records: findings.len(),
            order_changed,
        },
        attestation: attestation(&findings),
        findings,
        content: Content::default(),
        measurement: "not_computed",
        launch_measurement: None,
        platforms: before
            .platforms
            .values()
            .chain(after.platforms.values())
            .map(|p| p.to_string())
            .collect(),
        focus: None,
        diagnostics,
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            return crate::text::summary(self, f, false);
        }
        crate::text::summary(self, f, true)?;
        if !self.findings.is_empty() {
            writeln!(f, "\nEvery record change (record index before -> after):")?;
        }
        for change in &self.findings {
            let record = change
                .after
                .as_ref()
                .or(change.before.as_ref())
                .expect("change has a record");
            let action = match change.kind {
                ChangeKind::Added => "+",
                ChangeKind::Removed => "-",
                ChangeKind::Modified => "~",
                ChangeKind::Reordered => ">",
                ChangeKind::MaskReassigned => "=",
            };
            writeln!(
                f,
                "{action} {} {} [{}] (record {} -> {})",
                record.kind,
                record.identity,
                record.platforms.join(", "),
                position(change.before.as_ref()),
                position(change.after.as_ref())
            )?;
            match (&change.before, &change.after) {
                (Some(a), Some(b)) => {
                    for field in &change.fields {
                        writeln!(f, "    {field}: {} -> {}", a.fields[field], b.fields[field])?;
                    }
                    if a.compatibility_mask != b.compatibility_mask {
                        writeln!(
                            f,
                            "    compatibility_mask: {:?} -> {:?}",
                            a.compatibility_mask, b.compatibility_mask
                        )?;
                    }
                    if change.order_changed {
                        writeln!(f, "    relative record order changed")?;
                    }
                }
                _ => writeln!(f, "    {}", record.fields)?,
            }
        }
        Ok(())
    }
}

fn position(record: Option<&Record>) -> String {
    record
        .map(|record| record.index.to_string())
        .unwrap_or_else(|| "-".into())
}
