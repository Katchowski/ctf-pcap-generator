# Configuration Reference

This reference documents every environment variable the CTF PCAP Generator uses. All settings are controlled through a `.env` file in the project root. The repository includes a `.env.example` file with sensible defaults you can use as a starting point.

For setup instructions and getting the application running, see the [Deployment Guide](./deployment.md).

**Quick overview:** The application uses 11 environment variables, grouped by purpose:

| Group | Variables | Section |
|-------|-----------|---------|
| Flask Settings | `FLASK_ENV`, `FLASK_DEBUG`, `SECRET_KEY` | [Flask Settings](#flask-settings) |
| Logging | `LOG_FORMAT`, `LOG_LEVEL` | [Logging](#logging) |
| Engine Limits | `OUTPUT_DIR`, `CLEANUP_TTL_HOURS`, `MAX_PCAP_SIZE_MB`, `MAX_PACKET_COUNT` | [Engine Limits](#engine-limits) |
| Docker / Server | `PORT`, `GUNICORN_WORKERS` | [Docker / Server](#docker--server) |

## Flask Settings

Flask is the web framework that powers the application's interface.

| Variable | Type | Default | Valid Values | Description |
|----------|------|---------|--------------|-------------|
| `FLASK_ENV` | string | `production` | `development`, `production` | Selects the configuration profile. Use `development` for local work. |
| `FLASK_DEBUG` | string | `0` | `0`, `1` | Enables debug mode with automatic reloading when you change code. Set to `1` during development. |
| `SECRET_KEY` | string | `dev-secret-key-change-in-prod` | any string | Used by Flask to sign session cookies. Change this to a random string in production. |

## Logging

| Variable | Type | Default | Valid Values | Description |
|----------|------|---------|--------------|-------------|
| `LOG_FORMAT` | string | `json` | `json`, `console` | Controls the log output format. Use `console` for human-readable logs during development and `json` for machine-readable logs in production. |
| `LOG_LEVEL` | string | `info` | `debug`, `info`, `warning`, `error`, `critical` | Controls how much detail appears in logs. Lower levels like `debug` show more information. |

## Engine Limits

These variables control resource limits for PCAP generation. They protect the server from generating excessively large files.

| Variable | Type | Default | Valid Values | Description |
|----------|------|---------|--------------|-------------|
| `OUTPUT_DIR` | string | `/app/output` | any valid path | The directory where generated PCAP files are saved. Inside Docker, this defaults to `/app/output`. |
| `CLEANUP_TTL_HOURS` | integer | `24` | positive integer | How many hours generated PCAP files are kept before automatic cleanup removes them. |
| `MAX_PCAP_SIZE_MB` | integer | `100` | positive integer | Maximum allowed size in megabytes for a single generated PCAP file. |
| `MAX_PACKET_COUNT` | integer | `100000` | positive integer | Maximum number of packets allowed in a single generated PCAP file. |

## Docker / Server

Gunicorn is the web server that runs the application inside Docker.

| Variable | Type | Default | Valid Values | Description |
|----------|------|---------|--------------|-------------|
| `PORT` | integer | `5000` | `1`-`65535` | The port the application listens on. Change this if port 5000 is already in use on your machine. |
| `GUNICORN_WORKERS` | integer | `2` | positive integer | Number of web server worker processes. The default of 2 is appropriate for most setups. Increase only if you expect many simultaneous users. |

## Complete .env Example

Copy the block below into a file named `.env` in the project root. This gives you a development-friendly configuration that works out of the box.

```env
# === Flask Settings ===
FLASK_ENV=development              # "development" or "production"
FLASK_DEBUG=1                      # Set to 1 for auto-reload and debug pages
SECRET_KEY=change-me-in-production # Any random string; change for production use

# === Logging ===
LOG_FORMAT=console                 # "console" for readable output, "json" for machine logs
LOG_LEVEL=info                     # "debug", "info", "warning", "error", or "critical"

# === Engine Limits ===
OUTPUT_DIR=/app/output             # Where generated PCAP files are saved
CLEANUP_TTL_HOURS=24               # Hours before generated PCAPs are cleaned up
MAX_PCAP_SIZE_MB=100               # Maximum PCAP file size in megabytes
MAX_PACKET_COUNT=100000            # Maximum packets per generated PCAP

# === Docker / Server ===
PORT=5000                          # Application port (change if 5000 is taken)
GUNICORN_WORKERS=2                 # Web server worker processes
```
