# CTF PCAP Generator

CTF PCAP Generator creates realistic network traffic captures with embedded flags for Capture the Flag competitions. It supports 10 attack scenarios across multiple difficulty levels, covering techniques like SQL injection, DNS tunneling, and ARP spoofing. The tool runs entirely in Docker and integrates with CTFd for automated challenge deployment.

Each generated PCAP file contains realistic background traffic alongside the attack pattern, giving students a true-to-life forensics experience. You configure scenarios through simple YAML templates and generate captures with a single click through the web interface.

## Where to Start

If you are setting up the tool for the first time, start with the [Deployment Guide](https://github.com/profzeller/ctf-pcap-generator/blob/main/docs/deployment.md). It walks you through installing Docker, building the application, and generating your first PCAP file.

## Documentation

| Guide | Description |
|-------|-------------|
| [Deployment Guide](https://github.com/profzeller/ctf-pcap-generator/blob/main/docs/deployment.md) | Install and run with Docker |
| [Configuration](https://github.com/profzeller/ctf-pcap-generator/blob/main/docs/configuration.md) | Environment variables and settings |
| [Scenario Reference](https://github.com/profzeller/ctf-pcap-generator/blob/main/docs/scenarios.md) | All 10 attack scenarios with Wireshark filters |
| [For Professors](https://github.com/profzeller/ctf-pcap-generator/blob/main/docs/for-professors.md) | Competition planning workflow |
| [CTFd Integration](https://github.com/profzeller/ctf-pcap-generator/blob/main/docs/ctfd-integration.md) | Push challenges to CTFd |
| [Contributing](https://github.com/profzeller/ctf-pcap-generator/blob/main/CONTRIBUTING.md) | Development setup and contribution process |
| [Changelog](https://github.com/profzeller/ctf-pcap-generator/blob/main/CHANGELOG.md) | Version history |
