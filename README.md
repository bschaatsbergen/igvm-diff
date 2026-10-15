# igvm-diff

Compare two IGVM files and see what changed in memory pages, boot settings, and CPU startup state. Written in Rust, with a CLI and library.

## Usage

```sh
cargo run -- diff A.igvm B.igvm
cargo run -- diff A.igvm B.igvm --verbose
cargo run -- diff A.igvm B.igvm --format json
```

The default output summarizes the changes and suggests where to start reviewing. Use `--verbose` for every change and full hashes, or `--format json` for the complete report in JSON.

Exit codes: `0` for identical files, `1` for differences, `2` for errors. `compare` is an alias for `diff`.

Try the small test files included in the repository:

```sh
cargo run -- diff tests/fixtures/before.igvm tests/fixtures/after.igvm
```

There are also three [COCONUT-SVSM images](tests/fixtures/coconut-svsm/README.md) from community COPR builds to compare.

## Reading the report

`modified` shows changes to an existing record. `added` and `removed` list that record's values. A flag shown as `false` on an added record does not mean it changed from `true`.

Labels such as `[native, sev-snp, tdx]` show which platforms a record applies to. For an SEV-SNP deployment, look at records that include `sev-snp`.

Known EFER and SEV feature bits have short explanations and references to the manual. Unknown bits stay visible as hexadecimal values. The [mapping notes](docs/mappings.md) list the fields and their sources.

Use the report alongside a review of the source and build changes. It does not calculate launch measurements, verify signatures, or decide whether a build is safe to accept.

## Supported files

Supports x64 IGVM v1 and v2 with 4 KiB pages, up to 64 MiB per file. Unsupported records and CPU contexts return an error. This includes relocation records, VBS CPU contexts, and VMSAs with obfuscated registers.

For library use, `igvm_diff::diff(&before, &after)` returns the same report as the CLI. Format it with `{report}` for the summary or `{report:#}` for full details.

## Development

Install Rust through [rustup](https://rustup.rs/), then run:

```sh
rustup toolchain install --profile minimal
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
```

## License

Licensed under the [MIT License](LICENSE).

## Contributions

Issues and pull requests are welcome. Keep changes focused and run the development checks above before submitting a pull request.
