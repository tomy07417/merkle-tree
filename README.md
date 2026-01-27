# Merkle Tree

![Rust](https://img.shields.io/badge/Rust-000000?style=flat&logo=rust&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A Rust library implementation of a Merkle Tree data structure.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Project Setup](#project-setup)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Development](#development)
  - [Building](#building)
  - [Testing](#testing)
  - [Code Formatting](#code-formatting)
- [How Merkle Trees Work](#how-merkle-trees-work)
- [Resources](#resources)
- [Contributing](#contributing)
- [License](#license)

## Overview

A **Merkle Tree** (also known as a hash tree) is a tree data structure where every leaf node is labeled with the cryptographic hash of a data block, and every non-leaf node is labeled with the cryptographic hash of the labels of its child nodes.

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

2. **Set up Git hooks** (for code quality)
   ```bash
   make set-up
   ```

3. **Build the project**
   ```bash
   make build
   ```

## Development

### Available Make Commands

| Command | Description |
|---------|-------------|
| `make set-up` | Configure git hooks for the project |
| `make build` | Compile the project |
| `make test` | Run all tests |
| `make run` | Run the main binary |
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

### Code Formatting

```bash
# Format all code
make fmt

# Check formatting without modifying files
cargo fmt -- --check
```

## License
This project is licensed under the MIT License
