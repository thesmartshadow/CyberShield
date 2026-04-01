# CyberShield

CyberShield is a C++ security project focused on file protection, runtime monitoring, and defensive process control on POSIX-compatible systems.

It combines strong modern encryption with syscall-level interception to help protect sensitive files and reduce the risk of unauthorized access or unsafe process behavior.

Developed by **Ali Firas (thesmartshadow)** in collaboration with the **Phantom Force Team**.

---

## Overview

CyberShield was built to explore a practical security model that combines:

- file encryption for sensitive data
- runtime interception for defensive monitoring
- hardware-tied identity concepts
- memory-focused anti-tampering ideas
- lightweight integrity enforcement

The goal of the project is not just to encrypt data, but to add an additional defensive layer around how sensitive resources are accessed and handled at runtime.

---

## Features

- **Modern file encryption**
  - Uses authenticated encryption for protecting file contents

- **Syscall-level defensive monitoring**
  - Intercepts selected runtime behavior to restrict unsafe file access

- **Dynamic identity concept**
  - Uses host-linked attributes and timing-derived context as part of session logic

- **Ephemeral key handling**
  - Designed around short-lived cryptographic state

- **Integrity-oriented execution model**
  - Helps detect or disrupt suspicious interaction patterns during execution

- **Self-test mode**
  - Includes a built-in test path for quick validation after build

---

## Why CyberShield

Many small security tools focus on one thing only: encryption, access control, or monitoring.

CyberShield is an attempt to bring these ideas together in one project:

- encrypt data at rest
- monitor behavior at runtime
- limit risky access patterns
- keep the workflow simple enough to test locally

This makes it useful as a research-oriented security project, a learning resource, and a base for future defensive experimentation.

---

## Requirements

CyberShield is intended for **POSIX-compatible systems**.

Install the required dependencies:

```bash
sudo apt update
sudo apt install -y g++ libsodium-dev libssl-dev git
````

---

## Getting Started

Clone the repository:

```bash
git clone https://github.com/thesmartshadow/CyberShield.git
cd CyberShield
```

---

## Build

### Using the Makefile

Standard build:

```bash
make build
```

Build with a specific compiler:

```bash
make CXX=g++
make CXX=clang++
```

Other useful targets:

```bash
make debug
make sanity
make clean
```

### Manual build

Build the shared object:

```bash
g++ -std=c++20 -fPIC -shared -o CyberShield.so cyber_shield.cpp -ldl -lsodium
```

Build the standalone binary:

```bash
g++ -std=c++20 -o CyberShield cyber_shield.cpp -lsodium -ldl
```

---

## Usage

### Encrypt a file

```bash
./CyberShield /etc/passwd
```

This creates an encrypted output file such as:

```bash
passwd.enc
```

### Run the self-test

```bash
./CyberShield --self-test
```

This performs an internal validation flow to confirm that the encryption path is working as expected.

### Runtime interception with `LD_PRELOAD`

You can load the shared object into a target process:

```bash
sudo LD_PRELOAD=./CyberShield.so /usr/sbin/sshd
```

### Basic integrity check

Try opening a restricted file through a preloaded process:

```bash
LD_PRELOAD=./CyberShield.so nano /etc/shadow
```

If the interception logic is active, access should be denied by the defensive layer.

---

## Encrypted File Format

CyberShield writes encrypted output files using the `.enc` extension.

Current format:

* 4-byte magic: `CSH1`
* 1-byte version: `0x01`
* 1-byte nonce length
* nonce bytes
* ciphertext bytes using **ChaCha20-Poly1305**

Output file permissions are set to:

```text
0600
```

---

## Design Notes

CyberShield is built around a few core ideas:

### 1. Encryption first

Sensitive data should be protected with modern authenticated encryption, not plain obfuscation or reversible weak transformations.

### 2. Runtime awareness

Protection should not stop at file encryption. Runtime behavior matters too, especially when a process touches sensitive paths.

### 3. Short-lived cryptographic state

Reducing the lifetime of key material lowers exposure during inspection or tampering attempts.

### 4. Defensive experimentation

CyberShield is also a research-driven project. Some parts are intentionally built to explore stronger runtime security concepts and system-level hardening ideas.

---

## Example Workflow

Build the project:

```bash
make build
```

Run the self-test:

```bash
./CyberShield --self-test
```

Encrypt a file:

```bash
./CyberShield /etc/passwd
```

Test the interception layer:

```bash
LD_PRELOAD=./CyberShield.so nano /etc/shadow
```

---

## Use Cases

CyberShield may be useful for:

* local security research
* defensive systems experimentation
* file protection demonstrations
* runtime hardening prototypes
* educational work around encryption and process control

---

## Project Status

CyberShield is an actively structured security project and may continue evolving as new defensive ideas, hardening strategies, and runtime protections are explored.

---

## License

Distributed under the **MIT License**.

---

## Author

**Ali Firas (thesmartshadow)**
**Phantom Force Team**
