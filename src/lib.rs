//! Structural comparisons of IGVM files.

mod annotations;
mod content;
mod firmware;
mod image;
mod measure;
mod report;
mod text;

pub use content::{Component, Content, FirmwareModules, Format, TextChange, Unidentified};
pub use firmware::{FileType, ModuleChange, ModuleChangeKind, ModuleDiff};
pub use measure::{FileMeasurements, LaunchMeasurement, SnpMeasurement};
pub use report::{
    Area, Artifact, Attestation, Change, ChangeKind, ChangedArea, Comparison, Inputs, Record,
    Report, Tool,
};

/// Maximum size of each input, including unreferenced bytes.
pub const MAX_FILE_SIZE: usize = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid IGVM: {0}")]
    Invalid(String),
    #[error("unsupported IGVM: {0}")]
    Unsupported(String),
    #[error("input limit exceeded: {0}")]
    Limit(&'static str),
    #[error("IGVM validation failed: {0}")]
    Validation(#[from] igvm::Error),
    #[error("record {index}: {source}")]
    Record { index: usize, source: Box<Error> },
    #[error("platform {0} is not defined in either file (defined: {1})")]
    UnknownPlatform(String, String),
    #[error("{side} input: {source}")]
    Input {
        side: &'static str,
        source: Box<Error>,
    },
}

/// Compare two complete files. Neither input is treated as trusted.
pub fn diff(before: &[u8], after: &[u8]) -> Result<Report, Error> {
    diff_platform(before, after, None)
}

/// Like [`diff`], restricted to one platform (for example `sev-snp`) when `platform` is set.
pub fn diff_platform(before: &[u8], after: &[u8], platform: Option<&str>) -> Result<Report, Error> {
    let parse = |bytes: &[u8], side| {
        image::parse(bytes).map_err(|source| Error::Input {
            side,
            source: Box::new(source),
        })
    };
    let before_image = parse(before, "before")?;
    let after_image = parse(after, "after")?;
    let content = if before_image.artifact.sha256 == after_image.artifact.sha256 {
        Content::default()
    } else {
        content::analyze(before, &before_image, after, &after_image)
    };
    let launch_measurement = LaunchMeasurement {
        before: measure::measurements(before, &before_image),
        after: measure::measurements(after, &after_image),
    };
    let mut report = report::compare(before_image, after_image);
    report.content = content;
    let sides = [&launch_measurement.before, &launch_measurement.after];
    if sides.iter().any(|f| !f.igvm.is_empty()) {
        if sides.iter().any(|f| f.igvm.values().any(Result::is_ok)) {
            report.measurement = "computed";
        }
        report.launch_measurement = Some(launch_measurement);
    }
    if let Some(platform) = platform {
        if !report.platforms.contains(platform) {
            let defined: Vec<_> = report.platforms.iter().cloned().collect();
            return Err(Error::UnknownPlatform(platform.into(), defined.join(", ")));
        }
        report.focus(platform);
    }
    Ok(report)
}
