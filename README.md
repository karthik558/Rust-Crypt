# Rust Crypt (File Encryptor)

A simple yet powerful file encryption tool built with Rust. Securely encrypt and decrypt files using AES-256-GCM encryption with password-based key derivation.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust Version](https://img.shields.io/badge/rust-1.65%2B-orange.svg)
![Last Updated](https://img.shields.io/badge/last%20updated-2025--03--01-green.svg)

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [From Source](#from-source)
  - [Using Cargo](#using-cargo)
- [Usage](#usage)
- [Technical Details](#technical-details)
  - [Encryption Process](#encryption-process)
  - [Security Considerations](#security-considerations)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Features

- **Strong Encryption**: Uses AES-256-GCM, a highly secure authenticated encryption algorithm
- **Password-Based**: Simple password-based protection for your sensitive files
- **Secure Key Derivation**: Implements Argon2 for secure key derivation from passwords
- **User-Friendly CLI**: Simple command-line interface for ease of use
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Installation

### From Source

1. Ensure you have [Rust installed](https://www.rust-lang.org/tools/install)
2. Clone the repository
   ```bash
   git clone https://github.com/karthik558/Rust-Crypt.git
   cd Rust-Crypt
    ```
3. Build the project
   ```bash
   cargo build --release
   ```
4. The binary will be available at `target/release/rust-crypt`

### Using Cargo

```bash
cargo install --git https://github.com/karthik558/Rust-Crypt.git
```

## Usage

Encrypting a file:

```bash
  rust-crypt encrypt --input <INPUT_FILE> --output <OUTPUT_FILE> --password <YOUR_PASSWORD>
```

Example:

```bash
  rust-crypt encrypt --input secret.txt --output secret.enc --password mysecretpassword@7%%%!
```

Decrypting a file:

```bash
  rust-crypt decrypt --input <ENCRYPTED_FILE> --output <OUTPUT_FILE> --password <YOUR_PASSWORD>
```

Example:

```bash
  rust-crypt decrypt --input secret.enc --output secret.txt --password mysecretpassword@7%%%!
```

## Technical Details

### Encryption Process

1. A unique salt is generated for each file encryption
2. An AES-256 key is derived from the user's password using Argon2
3. A random nonce is generated for the AES-GCM encryption
4. The file is encrypted using AES-256-GCM with the derived key and nonce
5. The encrypted file format is: [salt_length (4 bytes)][salt][nonce (12 bytes)][encrypted data]

### Security Considerations

1. Password Strength: The security of your encrypted files depends significantly on the strength of your password
2. File Format: The encrypted file contains the salt and nonce used for encryption, but these do not compromise security
3. Memory Safety: Built with Rust, providing memory safety guarantees

## Dependencies

1. ```aes-gcm:```: Provides the AES-GCM encryption algorithm
2. ```argon2:```: Secure password hashing and key derivation
3. ```clap:```: Command-line argument parsing
4. ```anyhow:```: Flexible error handling

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request for new features, improvements, or bug fixes.

1. Fork the repository
2. Create your feature branch (```git checkout -b feature/security-feature```)
3. Commit your changes (```git commit -m 'Add some security feature'```)
4. Push to the branch (```git push origin feature/security-feature```)
5. Open a Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

1. Inspired by the need for simple, secure file encryption tools
2. Thanks to the Rust cryptography community for maintaining excellent libraries