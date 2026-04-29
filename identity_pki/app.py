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

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            ca=service.ca_summary(),
            roles=DEFAULT_ROLES,
        )

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "ca": service.ca_summary()})



    @app.post("/api/csr")
    def api_sign_csr():
        """Sign a Certificate Signing Request (CSR) from the client device.
        
        Client device generates its keypair locally, creates a CSR, and sends it here.
        This is the standard/secure enrollment flow.
        """
        payload = request.get_json(silent=True) or {}
        csr_pem = payload.get("csr", "")
        if not csr_pem:
            return jsonify({"error": "CSR required"}), 400
        
        try:
            bundle = service.sign_csr(
                csr_pem=csr_pem,
                user=payload.get("user", ""),
                role=payload.get("role", "doctor"),
                department=payload.get("department", ""),
                hardware_mac=payload.get("hardware_mac", ""),
                hardware_cpu=payload.get("hardware_cpu", ""),
            )
            return jsonify({
                "status": "signed",
                "certificate": bundle.to_dict(),
                "certificate_pem": bundle.paths.certificate.read_text(),
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

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
