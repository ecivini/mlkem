# MLKEM

**Disclaimer: This implementation has not been audited externally and is not intended for production use. It is a personal project created for learning purposes.**

MLKEM is an implementation of the Modular Lattice-based Key Encapsulation Mechanism (MLKEM) following the [FIPS 203 public draft](https://csrc.nist.gov/pubs/fips/203/ipd), written in Rust.

## Getting Started

To get started with MLKEM, follow these steps:

### Prerequisites

No dependencies are needed to build mlkem. Only prerequisites are:

- Rust (tested with 1.75.0)

### Installation

Clone the MLKEM repository and build the project:

```bash
git clone https://github.com/ecivini/MLKEM.git
cd MLKEM
cargo build --release
```

## Usage
To execute MLKEM, run:
```bash
 ./target/release/mlkem --help
```

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.