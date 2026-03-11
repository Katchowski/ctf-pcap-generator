# Deployment Guide

This guide walks you through getting the CTF PCAP Generator running on your machine. By the end, you will have a working web application that generates PCAP files -- files that capture network traffic your students can analyze in [Wireshark](https://www.wireshark.org/), a free network analyzer.

The entire application runs inside Docker, so you do not need to install Python or any other dependencies on your computer.

## Prerequisites

You need two things installed before you start:

1. **Docker Desktop** -- Download it from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) and make sure it is running (you should see the Docker whale icon in your system tray or menu bar).

2. **`make` (macOS and Linux only)** -- This is included by default on macOS and most Linux distributions. Windows users do not need `make` -- see the Windows notes throughout this guide for direct `docker compose` commands that work the same way.

## Step 1: Clone the Repository

Open a terminal (Terminal on macOS, Command Prompt or PowerShell on Windows, or your preferred terminal on Linux) and run:

```bash
git clone https://github.com/profzeller/ctf-pcap-generator.git
cd ctf-pcap-generator
```

**Verification:** You should see a `ctf-pcap-generator/` directory containing a `Makefile` and a `docker-compose.yml` file. You can confirm by listing the directory contents:

```bash
ls Makefile docker-compose.yml
```

Both files should appear without errors.

## Step 2: Build the Application

Run the build command:

```bash
make build
```

> **Windows note:** If you see `make: command not found`, run `docker compose build` instead. All `make` commands have a `docker compose` equivalent listed in the [Command Reference](#command-reference) below.

This downloads the base Python image and installs all dependencies. The first build takes a few minutes because Docker needs to download everything from scratch. Subsequent builds use a cache and finish much faster.

**Verification:** You should see output ending with lines similar to:

```
 => exporting to image
 => => naming to docker.io/library/ctf-pcap-generator-web
```

## Step 3: Run the Application

Start the application:

```bash
make run
```

> **Windows note:** Run `docker compose up` instead if `make` is not available.

**Verification:** Open [http://localhost:5000](http://localhost:5000) in your browser. You should see the CTF PCAP Generator interface with a list of available scenarios.

To stop the application, press `Ctrl+C` in the terminal where it is running, or open a new terminal and run `make stop` (or `docker compose down` on Windows).

## Step 4: Generate Your First PCAP

Once the application is running:

1. Select a scenario from the list (for example, "SQL Injection" or "DNS Tunneling").
2. Choose a difficulty level -- Easy, Medium, or Hard.
3. Click **Generate** to create the PCAP file.
4. Download the generated file and open it in Wireshark to inspect the captured traffic.

For details on what each scenario contains, what protocols are involved, and which Wireshark filters to use, see the [Scenarios Guide](./scenarios.md).

## Command Reference

Every `make` command is a shortcut for a `docker compose` command. If you are on Windows or prefer to use Docker directly, use the equivalent command from the right column.

| `make` Command | `docker compose` Equivalent | Description |
|----------------|----------------------------|-------------|
| `make build` | `docker compose build` | Build the Docker image |
| `make run` | `docker compose up` | Start the application (http://localhost:5000) |
| `make test` | `docker compose run --rm web uv run pytest` | Run all tests inside Docker |
| `make lint` | `docker compose run --rm web uv run ruff check . && docker compose run --rm web uv run ruff format --check .` | Run linter and format checker |
| `make shell` | `docker compose run --rm web /bin/bash` | Open a bash shell inside the container |
| `make stop` | `docker compose down` | Stop running containers |
| `make clean` | `docker compose down -v --rmi local` | Remove containers, volumes, and images |

## Configuration

All application settings are controlled through environment variables in a `.env` file. To get started with sensible defaults:

```bash
cp .env.example .env
```

This copies the example configuration file, which includes development-friendly settings that work out of the box. You can edit `.env` at any time to change settings like the port number or log format.

For the complete list of every environment variable, what it does, and its valid values, see the [Configuration Reference](./configuration.md).

## Troubleshooting

### Port 5000 Already in Use

**Symptom:** You see an error about port binding, such as `Bind for 0.0.0.0:5000 failed: port is already allocated`.

**Fix:** Another application is using port 5000. Either stop the conflicting service, or change the port by editing your `.env` file:

```
PORT=8080
```

Then restart the application. It will now be available at [http://localhost:8080](http://localhost:8080).

### Docker Is Not Running

**Symptom:** You see `Cannot connect to the Docker daemon` or `docker: command not found`.

**Fix:** Open Docker Desktop and wait for it to finish starting. You should see the Docker whale icon in your system tray (Windows) or menu bar (macOS) before running any commands.

### Permission Denied on Linux

**Symptom:** You see `permission denied` errors when running `docker` or `docker compose` commands.

**Fix:** Add your user to the `docker` group so you can run Docker commands without `sudo`:

```bash
sudo usermod -aG docker $USER
```

Then log out and log back in for the change to take effect.

### Slow First Build

**Symptom:** The `make build` (or `docker compose build`) command takes 5 or more minutes.

**Fix:** This is normal for the first build. Docker needs to download the Python base image and install all project dependencies. Subsequent builds use Docker's layer cache and typically finish in seconds. If builds are consistently slow, make sure Docker Desktop has adequate resources allocated in its settings (at least 2 GB of memory).
