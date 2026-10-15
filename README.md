# igvm-diff

A Rust CLI and library for comparing IGVM files. It shows changes to memory pages, boot configuration, and initial CPU state between builds.

```sh
cargo run -- diff A.igvm B.igvm
cargo run -- diff A.igvm B.igvm --verbose
cargo run -- diff A.igvm B.igvm --format json
```

Use `--verbose` for every record change and full hashes, or `--format json` for JSON output.

`compare` is an alias for `diff`. Exit codes are `0` for identical files, `1` for differences, and `2` for invalid or unsupported input. Errors go to stderr.

## Examples

The fixtures include a small pair that differs in one 4 KiB page:

```sh
cargo run -- diff tests/fixtures/before.igvm tests/fixtures/after.igvm
```

Compare two COCONUT-SVSM community builds:

```sh
cargo run -- diff \
  tests/fixtures/coconut-svsm/coconut-fedora-9065337.igvm \
  tests/fixtures/coconut-svsm/coconut-fedora-10828816.igvm
```

Compare OpenHCL's standard and confidential-VM variants from the same build:

```sh
cargo run -- diff \
  tests/fixtures/openhcl/38639549342/x64-openhcl-igvm/openhcl-x64.bin \
  tests/fixtures/openhcl/38639549342/x64-openhcl-igvm-cvm/openhcl-x64-cvm.bin
```

## What it compares

- Platform definitions and guest policies, resolving compatibility masks by platform type.
- Page addresses, types, shared/unmeasured flags, and payload SHA-256 digests.
- Parameter areas, parameter directives, insertions, memory requirements, and relocation settings.
- SNP/SEV-ES, VBS, and native/SEV CPU state payloads. SNP and VBS reports also show selected registers, including RIP, CR3, and EFER.
- SNP ID blocks, VBS measurement records, and CoRIM document/signature payloads. CoRIM contents are compared as opaque bytes.

## Current scope

Supports x64 IGVM v1 and v2 with 4 KiB pages, using the `igvm` parser. AArch64/CCA and 2 MiB pages are not supported. Unknown records and VMSAs with obfuscated registers return an error.

Each input is limited to 64 MiB, 32,768 records, and 128 MiB of referenced or implicit payloads. VBS contexts support the boot processor with up to 256 registers per context. Comparisons run locally and leave both files unchanged.

The report helps focus a source and build review. It does not calculate launch measurements, verify signatures, or decide whether a build is safe to accept.

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
