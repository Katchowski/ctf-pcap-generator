# CTF PCAP Generator

![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.12-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Required-blue.svg)

Generate realistic, flag-embedded PCAP files for CTF competitions. A PCAP (packet capture) file records network traffic that participants analyze using tools like [Wireshark](https://www.wireshark.org/) to find hidden flags.

## Features

- **12 scenarios** (10 attack + 2 tutorials) across 5 categories -- from SYN port scans and SQL injection to DNS tunneling and reverse shells
- **3 difficulty levels** controlling background noise ratio, flag encoding complexity, and flag splitting across packets
- **CTFd integration** for pushing challenges, flags, and PCAPs directly to a CTFd instance via its API
- **Batch generation** with ZIP download for producing multiple challenges at once
- **In-browser PCAP preview** with packet statistics, protocol breakdown, and flag verification
- **Auto-generated writeups** with scenario explanations and Wireshark display filters
- **Challenge export** as ctfcli-compatible `challenge.yml` files
- **Docker-first** -- the entire application runs in containers with no host dependencies beyond Docker
- **Built with** Flask, Scapy, HTMX, and Bootstrap 5

## Quick Start

1. **Clone the repository:**

   ```bash
   git clone https://github.com/profzeller/ctf-pcap-generator.git
   cd ctf-pcap-generator
   ```

2. **Configure environment:**

   ```bash
   cp .env.example .env
   ```

3. **Build the Docker image:**

   ```bash
   make build
   ```

4. **Start the application:**

   ```bash
   make run
   ```

5. **Open your browser** at [http://localhost:5000](http://localhost:5000). You should see a scenario selection page where you can pick an attack type, choose a difficulty, and generate your first PCAP.

For Windows commands (if `make` is not available), troubleshooting, and advanced configuration, see the [Deployment Guide](docs/deployment.md).

> **Windows note:** If you do not have `make` installed, you can use `docker compose build` and `docker compose up` directly. The deployment guide lists the `docker compose` equivalent for every `make` command.

## Documentation

| Guide | Description |
|-------|-------------|
| [Deployment Guide](docs/deployment.md) | Prerequisites, installation, first run, troubleshooting |
| [Scenario Reference](docs/scenarios.md) | All 12 scenarios with protocols, categories, and Wireshark filters |
| [Configuration Reference](docs/configuration.md) | Every environment variable with types, defaults, and valid values |
| [CTFd Integration Guide](docs/ctfd-integration.md) | Connect to CTFd, push challenges and flags via API |
| [For Professors](docs/for-professors.md) | Competition planning checklists and starter scenario packs |
| [Contributing](CONTRIBUTING.md) | Development setup, code style, and how to submit changes |
| [Changelog](CHANGELOG.md) | Release history and notable changes |

## License

This project is licensed under the Apache License 2.0 -- see [LICENSE](LICENSE) for details.
