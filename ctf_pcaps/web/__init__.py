"""Flask application factory for the CTF PCAP Generator."""

# Source: https://flask.palletsprojects.com/en/stable/patterns/appfactories/

from flask import Flask

from ctf_pcaps.config import get_config
from ctf_pcaps.logging import configure_logging


def create_app(config_override=None):
    """Application factory for the CTF PCAP Generator.

    Args:
        config_override: Optional dict of config values to override defaults.

    Returns:
        Configured Flask application instance.
    """
    app = Flask(__name__)

    # Load configuration
    config = get_config()
    app.config.from_object(config)
    if config_override:
        app.config.update(config_override)

    # Configure structured logging
    configure_logging(app.config.get("LOG_FORMAT", "console"))

    # Register blueprints
    from ctf_pcaps.web.routes import bp

    app.register_blueprint(bp)

    return app
