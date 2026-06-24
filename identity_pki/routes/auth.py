"""Authentication semantic endpoints for AD logins, OTP verification and step-up auth."""

import random
import uuid
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, current_app

from ..auth import (
    AD_USERS,
    PENDING_OTPS,
    ENROLLMENT_SESSIONS,
    PRIMARY_SESSIONS,
)
from .utils import error_response

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/api/auth/login")
def api_auth_login():
    """Simulate Active Directory login and send OTP."""
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "").strip()
    password = payload.get("password", "")

    if not email or not password:
        return error_response("Email and Password are required", 400)

    user_info = AD_USERS.get(email)
    if not user_info or user_info["password"] != password:
        return error_response("Invalid email or password", 401)

    # Generate 6-digit OTP
    otp = f"{random.randint(100000, 999999)}"
    # Store in pending
    PENDING_OTPS[email] = {
        "otp": otp,
        "user_info": user_info,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
    }

    current_app.logger.info(f"Simulated AD Login Success for {email}. OTP Code Generated: {otp}")
    return jsonify({
        "status": "otp_required",
        "message": f"Simulated MFA OTP generated for {email}",
        "email": email,
        "simulated_otp": otp 
    })


@auth_bp.post("/api/auth/verify-otp")
def api_auth_verify_otp():
    """Verify the OTP and issue an enrollment session token."""
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "").strip()
    otp = payload.get("otp", "").strip()

    if not email or not otp:
        return error_response("Email and OTP are required", 400)

    pending = PENDING_OTPS.get(email)
    if not pending:
        return error_response("No pending authentication session found", 400)

    if datetime.now(timezone.utc) > pending["expires_at"]:
        PENDING_OTPS.pop(email, None)
        return error_response("OTP has expired", 401)

    if pending["otp"] != otp:
        return error_response("Invalid OTP code", 401)

    # Success: generate session token
    token = str(uuid.uuid4())
    user_cn = pending["user_info"]["cn"]
    ENROLLMENT_SESSIONS[token] = {
        "cn": user_cn,
        "role": pending["user_info"]["role"],
        "department": pending["user_info"]["department"],
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10)
    }

    # Establish/Refresh Primary Auth Session (valid for 12 hours)
    now = datetime.now(timezone.utc)
    PRIMARY_SESSIONS[user_cn] = {
        "login_time": now,
        "last_mfa_time": now
    }

    # Clean up pending
    PENDING_OTPS.pop(email, None)

    current_app.logger.info(f"MFA Verified for {email}. Enrollment session token issued (redacted)")
    return jsonify({
        "status": "success",
        "enrollment_session_token": token,
        "user_info": {
            "cn": ENROLLMENT_SESSIONS[token]["cn"],
            "role": ENROLLMENT_SESSIONS[token]["role"],
            "department": ENROLLMENT_SESSIONS[token]["department"]
        }
    })


@auth_bp.post("/api/auth/step-up")
def api_auth_step_up():
    """Verify the OTP and password to refresh the last_mfa_time for Step-up Authentication."""
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "").strip()
    otp = payload.get("otp", "").strip()
    password = payload.get("password", "")

    if not email or not otp or not password:
        return error_response("Email, OTP and Password are required", 400)

    # 1. Verify password matches Active Directory
    user_info = AD_USERS.get(email)
    if not user_info or user_info["password"] != password:
        return error_response("Invalid email or password", 401)

    # 2. Verify OTP
    pending = PENDING_OTPS.get(email)
    if not pending:
        return error_response("No pending authentication session found", 400)

    if datetime.now(timezone.utc) > pending["expires_at"]:
        PENDING_OTPS.pop(email, None)
        return error_response("OTP has expired", 401)

    if pending["otp"] != otp:
        return error_response("Invalid OTP code", 401)

    # Success: Refresh/Establish primary session with updated last_mfa_time
    user_cn = user_info["cn"]
    now = datetime.now(timezone.utc)
    
    orig_session = PRIMARY_SESSIONS.get(user_cn, {})
    login_time = orig_session.get("login_time", now)
    
    PRIMARY_SESSIONS[user_cn] = {
        "login_time": login_time,
        "last_mfa_time": now
    }
    
    PENDING_OTPS.pop(email, None)
    
    current_app.logger.info(f"Step-up Authentication successful for {user_cn} ({email})")
    return jsonify({
        "status": "success",
        "message": "Step-up Authentication successful. Session MFA timestamp refreshed."
    })
