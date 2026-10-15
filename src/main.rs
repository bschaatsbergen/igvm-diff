use std::{
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand, ValueEnum};
use igvm_diff::{MAX_FILE_SIZE, diff};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Compare the records and payloads of two local IGVM files.
    #[command(visible_alias = "compare")]
    Diff {
        before: PathBuf,
        after: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Show every record change and full hashes in text output.
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_FILE_SIZE as u64 + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if bytes.len() > MAX_FILE_SIZE {
        return Err(format!("{}: file is larger than 64 MiB", path.display()));
    }
    Ok(bytes)
}

fn run(args: Args) -> Result<ExitCode, String> {
    let Command::Diff {
        before,
        after,
        format,
        verbose,
    } = args.command;
    let before = read_file(&before)?;
    let after = read_file(&after)?;
    let report = diff(&before, &after).map_err(|error| error.to_string())?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    match format {
        Format::Text => {
            if verbose {
                write!(out, "{report:#}")
            } else {
                write!(out, "{report}")
            }
            .map_err(|error| error.to_string())?;
        }
        Format::Json => {
            serde_json::to_writer_pretty(&mut out, &report).map_err(|error| error.to_string())?;
            writeln!(out).map_err(|error| error.to_string())?;
        }
    }
    out.flush().map_err(|error| error.to_string())?;
    Ok(ExitCode::from(u8::from(report.has_changes())))
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}
