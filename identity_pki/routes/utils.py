from flask import jsonify


def error_response(message: str, code: int = 400):
    """Return a standard structured error response with code."""
    return jsonify({"error": message, "code": code}), code
