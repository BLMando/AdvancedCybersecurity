"""Flask web application for the PKI & identity module (blueprints router)."""

from __future__ import annotations

import logging
import os

from flask import Flask

from .pki import PKIService

logger = logging.getLogger(__name__)


def create_app(data_dir=None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["JSON_SORT_KEYS"] = False

    # Use /data/certs by default for persistence in Docker
    cert_dir = data_dir or os.environ.get("ZTA_PKI_DATA_DIR", "/data/certs")
    service = PKIService(cert_dir=cert_dir)

    # Store PKIService in application config for routes to access
    app.config["pki_service"] = service

    # Import blueprints semantically
    from .routes import admin_bp, auth_bp, oidc_bp, pki_bp, query_bp

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(pki_bp)
    app.register_blueprint(oidc_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(query_bp)

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    debug = os.environ.get("IDENTITY_APP_DEBUG", "false").lower() == "true"
    ssl_context = ("/data/server/envoy.crt", "/data/server/envoy.key")
    app.run(host="0.0.0.0", port=8080, debug=debug, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
