"""Environment-based configuration classes."""

import os


class Config:
    """Base configuration loaded from environment variables."""

    FLASK_ENV = os.getenv("FLASK_ENV", "production")
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")
    LOG_FORMAT = os.getenv("LOG_FORMAT", "json")  # "json" or "console"
    OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/app/output")
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"

    # Engine limits
    CLEANUP_TTL_HOURS = int(os.getenv("CLEANUP_TTL_HOURS", "24"))
    MAX_PCAP_SIZE_MB = int(os.getenv("MAX_PCAP_SIZE_MB", "100"))
    MAX_PACKET_COUNT = int(os.getenv("MAX_PACKET_COUNT", "100000"))


class DevelopmentConfig(Config):
    """Development overrides."""

    DEBUG = True
    LOG_FORMAT = "console"


class ProductionConfig(Config):
    """Production defaults."""

    DEBUG = False
    LOG_FORMAT = "json"


def get_config():
    """Select configuration class based on FLASK_ENV environment variable."""
    env = os.getenv("FLASK_ENV", "production")
    configs = {
        "development": DevelopmentConfig,
        "production": ProductionConfig,
    }
    return configs.get(env, ProductionConfig)()
