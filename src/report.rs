use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use serde_json::Value;

use crate::image::Image;

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

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    pub scope: &'static str,
    pub inputs: Inputs,
    pub comparison: Comparison,
    pub findings: Vec<Change>,
    pub measurement: &'static str,
    pub diagnostics: Vec<String>,
}

impl Report {
    pub fn has_changes(&self) -> bool {
        self.comparison.file_bytes_changed
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
    if file_bytes_changed && findings.is_empty() && !format_changed {
        diagnostics.push("File bytes differ without supported record changes. File offsets, padding, or unreferenced data may differ; this does not establish semantic equivalence.".into());
    }
    Report {
        schema_version: 1,
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
        findings,
        measurement: "not_requested",
        diagnostics,
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            return crate::text::summary(self, f);
        }
        writeln!(
            f,
            "{}",
            if self.has_changes() {
                "Files differ"
            } else {
                "Files are identical"
            }
        )?;
        writeln!(
            f,
            "Before: {} ({} bytes, {} records)",
            self.inputs.before.sha256, self.inputs.before.size, self.inputs.before.record_count
        )?;
        writeln!(
            f,
            "After:  {} ({} bytes, {} records)",
            self.inputs.after.sha256, self.inputs.after.size, self.inputs.after.record_count
        )?;
        writeln!(
            f,
            "Changed records: {}; measurement not requested",
            self.findings.len()
        )?;
        if self.comparison.format_changed {
            writeln!(
                f,
                "Format version: {} -> {}",
                self.inputs.before.format_version, self.inputs.after.format_version
            )?;
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
        for diagnostic in &self.diagnostics {
            writeln!(f, "Note: {diagnostic}")?;
        }
        Ok(())
    }
}

fn position(record: Option<&Record>) -> String {
    record
        .map(|record| record.index.to_string())
        .unwrap_or_else(|| "-".into())
}
