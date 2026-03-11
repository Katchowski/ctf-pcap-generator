# Source: https://gunicorn.org/guides/docker/
import os

# Bind to all interfaces on port 5000
bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"

# For containerized environments: 2 workers is appropriate
# (scale by adding containers, not workers)
workers = int(os.getenv("GUNICORN_WORKERS", "2"))

# Use gthread workers to support concurrent SSE streams
worker_class = "gthread"
threads = 4

# Log to stdout/stderr for Docker log collection
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")

# Graceful shutdown timeout (match Docker stop_grace_period)
graceful_timeout = 30

# Use /dev/shm for temporary files in Docker
worker_tmp_dir = "/dev/shm"
