# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust implementation of the PSP (PSP Security Protocol), which is a security protocol by Google. The codebase provides both a library (`psp_security`) and a command-line utility (`psp`) for PSP packet encryption, decryption, and testing.

## Core Architecture

### Main Components

- **Library**: `src/lib.rs` - Core PSP functionality including packet encapsulation, decapsulation, encryption/decryption
- **CLI Tool**: `src/bin/psp.rs` - Command-line interface with subcommands for create, encrypt, decrypt, client, and server
- **Packet Module**: `src/packet/` - PSP packet structure definitions and parsing
- **Test Suite**: `test/` directory - Comprehensive shell-based integration tests

### Key Modules

- **PSP Encapsulation**: Supports both Transport and Tunnel modes
- **Crypto Algorithms**: AES-GCM-128 and AES-GCM-256 using `aws-lc-rs` 
- **Socket Interface**: `PspSocket` for client/server communication
- **Configuration**: JSON and text-based configuration file support

## Development Commands

### Building and Testing

```bash
# Build the project
cargo build

# Run unit tests
cargo test

# Install CLI tool locally
cargo install --path .

# Run comprehensive integration tests
cd test && ./all_tests.sh
```

### CLI Usage Patterns

The `psp` binary provides several subcommands:

```bash
# Create test data
psp create pcap -n 10 -v ipv4 -o cleartext.pcap
psp create config --spi 98234567 --mode transport --alg aes-gcm128 -c example.cfg

# Encrypt/decrypt packets
psp encrypt -c example.cfg -i cleartext.pcap -o encrypted.pcap
psp decrypt -c example.cfg -i encrypted.pcap -o decrypted.pcap

# Client/server example
psp server -p 10001
psp client -p 10001
```

## Test Infrastructure

The project has extensive integration testing via shell scripts in `test/`:

- Tests cover IPv4/IPv6, Transport/Tunnel modes, different crypto algorithms
- Each test creates configuration files, encrypts packets, decrypts them, and verifies results
- Run individual tests: `./v4_transport_crypt_off_128.sh`
- Run all tests: `./all_tests.sh`

## Configuration Files

PSP operations require configuration files specifying:
- SPI (Security Parameters Index)
- Encapsulation mode (Transport/Tunnel)
- Crypto algorithm (AES-GCM-128/256)
- Crypto offset and virtual cookie settings

Configuration supports both JSON format and text format (compatible with Google's C implementation).

## Network Packet Handling

The codebase extensively uses:
- `etherparse` for packet parsing
- `pnet` for packet manipulation
- `pcap-file` for reading/writing packet capture files
- Custom PSP packet structures with bitfield definitions

When working with network code, be aware that the PSP protocol operates at Layer 3/4 and modifies IP packet headers for encapsulation.

## Development Workflow

### Branch Management

- **Always create feature branches** for any changes using the naming convention: `feature-[short-description]`
- Work on feature branches, never directly on `main`
- Examples: `feature-fix-tunnel-mode`, `feature-add-cipher-suite`, `feature-improve-error-handling`

### Pre-commit Requirements

Before committing any code changes:

```bash
# 1. Ensure code builds successfully
cargo build

# 2. Run unit tests
cargo test

# 3. Run integration tests
cd test && ./all_tests.sh
```

**All builds and tests must pass before committing code.** This ensures code quality and prevents breaking changes from entering the repository.

### Release Workflow

Releases are prepared using a temporary release branch:

```bash
# 1. Create release branch from main
git checkout main
git pull origin main
git checkout -b release-v[VERSION]

# 2. Update version in Cargo.toml
# Edit Cargo.toml to set the new version number

# 3. Verify release readiness
cargo build
cargo test
cd test && ./all_tests.sh

# 4. Commit version bump
git add Cargo.toml Cargo.lock
git commit -m "chore: bumping version to [VERSION]"

# 5. Create and push release branch
git push origin release-v[VERSION]

# 6. Create pull request from release branch to main
# After PR approval and merge, tag the release on main
```

The release branch is temporary and can be deleted after the release is complete.