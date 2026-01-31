# Merkle Tree

![Rust](https://img.shields.io/badge/Rust-000000?style=flat&logo=rust&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A Rust library implementation of a Merkle Tree data structure.

## Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Development](#development)
  - [Building](#building)
  - [Testing](#testing)
  - [Code Formatting](#code-formatting)
- [Contributing](#contributing)
- [License](#license)

## Overview

A **Merkle Tree** (also known as a hash tree) is a tree data structure where every leaf node is labeled with the cryptographic hash of a data block, and every non-leaf node is labeled with the cryptographic hash of the labels of its child nodes.

This crate provides a SHA-256-based Merkle tree with proof generation and verification.

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:

- **Rust** (1.92.0 or later recommended)
  ```bash
  # Install Rust using rustup
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  
  # Verify installation
  rustc --version
  cargo --version
  ```

- **Git** (for version control)
  ```bash
  # Verify Git installation
  git --version
  ```

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd merkle-tree
   ```

2. **Build the project**
   ```bash
   make build
   ```

## Usage

```rust
use merkle_tree::merkle_tree::MerkleTree;

let mut tree = MerkleTree::new(vec!["A", "B", "C"]);
let root = tree.get_root();

// Append new leaves
tree.push(vec!["D", "E"]);

// Generate a proof and verify it
let proof = tree.generate_merkle_proof(1).unwrap();
let leaf_hash = sha2::Sha256::digest(b"B");
assert!(proof.verify(leaf_hash.into()));
```

## API Reference

Generate docs locally with:

```bash
cargo doc --open
```

## Development

### Available Make Commands

| Command | Description |
|---------|-------------|
| `make set-up` | Configure git hooks for the project |
| `make build` | Compile the project |
| `make test` | Run all tests |
| `make clean` | Remove build artifacts |
| `make fmt` | Format code using rustfmt |
| `make check` | Check code for errors without building |

### Building

```bash
# Debug build
make build

# Release build (optimized)
cargo build --release
```

### Testing

```bash
# Run all tests
make test

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test test_name
```

### Documentation

```bash
make doc
```

### Code Formatting

```bash
# Format all code
make fmt

# Check formatting without modifying files
cargo fmt -- --check
```

## License
This project is licensed under the MIT License
