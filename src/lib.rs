//! Structural comparisons of IGVM files.

mod annotations;
mod image;
mod report;
mod text;

pub use report::{Artifact, Change, ChangeKind, Comparison, Inputs, Record, Report, Tool};

/// Maximum size of each input, including unreferenced bytes.
pub const MAX_FILE_SIZE: usize = 64 * 1024 * 1024;

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
    #[error("{side} input: {source}")]
    Input {
        side: &'static str,
        source: Box<Error>,
    },
}

/// Compare two complete files. Neither input is treated as trusted.
pub fn diff(before: &[u8], after: &[u8]) -> Result<Report, Error> {
    let parse = |bytes: &[u8], side| {
        image::parse(bytes).map_err(|source| Error::Input {
            side,
            source: Box::new(source),
        })
    };
    let before = parse(before, "before")?;
    let after = parse(after, "after")?;
    Ok(report::compare(before, after))
}
