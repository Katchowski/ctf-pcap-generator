# Contributing to CTF PCAP Generator

Thank you for your interest in contributing. This guide covers everything you need to set up a development environment, follow the project's code style, and submit changes.

## Development Setup

### Prerequisites

You need **Docker Desktop** installed and running. Download it from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) if you do not have it yet. No other dependencies (Python, Scapy, libpcap) are needed on your machine -- everything runs inside Docker.

### Getting Started

1. Fork and clone the repository:

   ```bash
   git clone https://github.com/profzeller/ctf-pcap-generator.git
   cd ctf-pcap-generator
   ```

2. Build the Docker image:

   ```bash
   make build
   ```

3. Start the application:

   ```bash
   make run
   ```

   The app is now running at [http://localhost:5000](http://localhost:5000).

For a detailed walkthrough including Windows-specific commands and troubleshooting, see the [Deployment Guide](docs/deployment.md).

### Make Targets

All development tasks have `make` shortcuts. Each one runs the corresponding command inside Docker.

| Command | Description |
|---------|-------------|
| `make build` | Build the Docker image |
| `make run` | Start the application (http://localhost:5000) |
| `make test` | Run all tests inside Docker |
| `make lint` | Run Ruff linter and formatter check |
| `make shell` | Open a bash shell inside the container |
| `make stop` | Stop running containers |
| `make clean` | Remove containers, volumes, and images |

## Code Style

This project uses [Ruff](https://docs.astral.sh/ruff/) for both linting and formatting, configured in `pyproject.toml`.

**Key settings:**

- **Python target:** 3.12
- **Line length:** 88 characters
- **Quote style:** Double quotes
- **Lint rules:** E (pycodestyle), F (pyflakes), I (isort), UP (pyupgrade), B (bugbear), SIM (simplify)

Run `make lint` before submitting any changes. To auto-format your code:

```bash
docker compose run --rm web uv run ruff format .
```

**Logging:** Use `structlog` for all application logging. Do not use `print()` or the standard `logging` module directly.

```python
import structlog

logger = structlog.get_logger()
logger.info("event_description", key="value")
```

## Architecture

The codebase follows a three-layer architecture with strict import boundaries:

```
ctf_pcaps/
  engine/       -- PCAP generation (Scapy) -- NEVER imports from web or integration
  web/          -- Flask routes, templates -- can import engine and integration
  integration/  -- CTFd API client -- NEVER imports from web
```

The rule is straightforward: `engine/` is fully independent, `integration/` can use `engine/`, and `web/` can use both. This keeps the PCAP generation engine testable without needing Flask or any external service running.

If you are adding new functionality, make sure your imports follow these boundaries.

## Running Tests

All tests run inside Docker (Scapy requires libpcap, which the container provides).

```bash
make test
```

The test structure mirrors the source layout:

- `tests/web/` -- Route and template tests
- `tests/engine/` -- Scapy and generation tests
- `tests/integration/` -- External service tests

To run a specific test directory:

```bash
docker compose run --rm web uv run pytest tests/engine/ -v
```

## Submitting Changes

1. **Fork** the repository and create a feature branch from `main`:

   ```bash
   git checkout -b my-feature
   ```

2. **Make your changes** following the code style and architecture rules above.

3. **Run linting and tests** -- both must pass:

   ```bash
   make lint
   make test
   ```

4. **Submit a pull request** with a clear description of what you changed and why.

Keep pull requests focused on a single concern. If you have multiple unrelated changes, submit them as separate PRs.

If you are interested in adding new scenarios, please open an issue first to discuss the approach.
