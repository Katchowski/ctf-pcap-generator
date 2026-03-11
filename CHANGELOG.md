# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Project documentation: README, deployment guide, scenario reference, configuration reference, CTFd integration guide, professor's guide, contributing guide

## [1.1.0] - 2026-03-10

### Added

- 5 new attack scenarios: HTTP beaconing / C2, ICMP exfiltration, reverse shell, credential harvesting, FTP data theft
- 2 tutorial scenarios: simple TCP session, simple DNS lookup
- Flag splitting across multiple packets for harder challenges
- Batch generation with ZIP download for multiple challenges at once
- In-browser PCAP preview with packet statistics and protocol breakdown
- Auto-generated writeups with scenario explanations and Wireshark display filters
- Challenge export as ctfcli-compatible challenge.yml
- Generation history with persistent storage

## [1.0.0] - 2026-03-08

### Added

- 5 attack scenarios: SYN port scan, ARP spoofing / MITM, brute force login, SQL injection, DNS tunneling
- 3 difficulty levels (Easy, Medium, Hard) controlling noise ratio, encoding complexity, and flag splitting
- Flag embedding engine with configurable format, encoding chains, and split-flag support
- Realistic background traffic generation (DNS, HTTP, HTTPS, NTP noise patterns)
- CTFd integration for pushing challenges, PCAPs, flags, and hints via API
- Web UI for scenario selection, PCAP generation, and download
- Docker-based deployment with make command shortcuts
- Configurable via environment variables with .env file support

[Unreleased]: https://github.com/profzeller/ctf-pcap-generator/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/profzeller/ctf-pcap-generator/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/profzeller/ctf-pcap-generator/releases/tag/v1.0.0
