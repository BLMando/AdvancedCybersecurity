"""Flask web application for the PKI & identity module."""

from __future__ import annotations

import os

from flask import Flask, abort, jsonify, render_template, request, send_from_directory, url_for

from .pki import DEFAULT_ROLES, PKIService


def create_app(data_dir=None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["JSON_SORT_KEYS"] = False
    service = PKIService(data_dir=data_dir)
    
    # Generate Envoy server certificate on startup
    try:
        service.issue_server_certificate(cn="envoy", dns_names=["envoy", "localhost", "127.0.0.1"])
        print("✓ Envoy server certificate generated/verified")
    except Exception as e:
        print(f"⚠ Error generating server certificate: {e}")

    def render_home(error: str = "", form_values=None):
        form_values = form_values or {}
        return render_template(
            "index.html",
            ca=service.ca_summary(),
            roles=DEFAULT_ROLES,
            error=error,
            form_values=form_values,
        )

    @app.get("/")
    def index():
        return render_home()

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "ca": service.ca_summary()})

    @app.post("/certificates")
    def create_certificate():
        form = request.form or request.get_json(silent=True) or {}
        hardware_mode = form.get("hardware_mode", "local")
        try:
            bundle = service.issue_certificate(
                user=form.get("user", ""),
                role=form.get("role", "doctor"),
                department=form.get("department", ""),
                hardware_mode=hardware_mode,
                mac=form.get("mac", ""),
                cpu=form.get("cpu", ""),
            )
        except ValueError as exc:
            return render_home(str(exc), form_values=form), 400

        return render_template(
            "result.html",
            ca=service.ca_summary(),
            bundle=bundle.to_dict(),
            download_certificate=url_for(
                "download_issued_file",
                user_slug=bundle.slug,
                filename=bundle.paths.certificate.name,
            ),
            download_key=url_for(
                "download_issued_file",
                user_slug=bundle.slug,
                filename=bundle.paths.private_key.name,
            ),
            download_pem=url_for(
                "download_issued_file",
                user_slug=bundle.slug,
                filename=bundle.paths.pem_bundle.name,
            ),
            download_metadata=url_for(
                "download_issued_file",
                user_slug=bundle.slug,
                filename=bundle.paths.metadata.name,
            ),
        )

    @app.post("/api/certificates")
    def api_create_certificate():
        payload = request.get_json(silent=True) or {}
        bundle = service.issue_certificate(
            user=payload.get("user", ""),
            role=payload.get("role", "doctor"),
            department=payload.get("department", ""),
            hardware_mode=payload.get("hardware_mode", "local"),
            mac=payload.get("mac", ""),
            cpu=payload.get("cpu", ""),
        )
        return jsonify({"status": "created", "certificate": bundle.to_dict()})

    @app.get("/download/<user_slug>/<filename>")
    def download_issued_file(user_slug: str, filename: str):
        directory = service.issued_dir / user_slug
        if not directory.exists():
            abort(404)
        return send_from_directory(directory, filename, as_attachment=True)

    @app.get("/download/ca/<filename>")
    def download_ca_file(filename: str):
        return send_from_directory(service.ca_dir, filename, as_attachment=True)

    return app


def main() -> None:
    app = create_app()
    host = os.environ.get("IDENTITY_APP_HOST", "0.0.0.0")
    port = int(os.environ.get("IDENTITY_APP_PORT", "8080"))
    debug = os.environ.get("IDENTITY_APP_DEBUG", "0") == "1"
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
