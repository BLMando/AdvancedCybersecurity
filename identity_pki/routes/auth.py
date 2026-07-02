"""Authentication semantic endpoints for AD logins, OTP verification and step-up auth."""

import os
import random
import smtplib
import uuid
from datetime import UTC, datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import Blueprint, current_app, jsonify, request

from ..auth import (
    AD_USERS,
    ENROLLMENT_SESSIONS,
    PENDING_OTPS,
    PRIMARY_SESSIONS,
)
from .utils import error_response

auth_bp = Blueprint("auth", __name__)

SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


def send_otp_email(recipient_email: str, otp: str, user_cn: str) -> bool:
    """Send OTP code via Gmail SMTP."""
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        current_app.logger.warning("SMTP credentials not configured, skipping email send")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"ZTA Healthcare - OTP Code: {otp}"
    msg["From"] = f"ZTA Identity <{SMTP_EMAIL}>"
    msg["To"] = recipient_email

    html = f"""\
    <html>
    <body style="font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px;">
        <div style="max-width: 480px; margin: 0 auto; background: #1e293b; border-radius: 16px; padding: 40px; border: 1px solid #334155;">
            <h2 style="color: #38bdf8; margin-top: 0;">Identity Verification</h2>
            <p>Hello <strong>{user_cn}</strong>,</p>
            <p>Your OTP code for two-factor authentication is:</p>
            <div style="text-align: center; margin: 30px 0;">
                <span style="font-size: 2.5em; letter-spacing: 0.2em; color: #38bdf8; font-weight: 900; background: #0f172a; padding: 15px 30px; border-radius: 12px; border: 2px solid #38bdf8;">{otp}</span>
            </div>
            <p style="color: #94a3b8;">The code expires in <strong>5 minutes</strong>.</p>
            <hr style="border: none; border-top: 1px solid #334155; margin: 20px 0;">
            <p style="font-size: 0.8em; color: #64748b;">ZTA Healthcare Identity PKI — Zero Trust Architecture</p>
        </div>
    </body>
    </html>"""

    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, recipient_email, msg.as_string())
        current_app.logger.info(f"OTP email sent to {recipient_email}")
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send OTP email to {recipient_email}: {e}")
        return False


@auth_bp.get("/api/auth/users")
def api_auth_users():
    """Get simulated AD users for frontend login dropdown."""
    users = {
        email: {"cn": info["cn"], "role": info["role"], "department": info["department"]}
        for email, info in AD_USERS.items()
    }
    return jsonify(users)


@auth_bp.post("/api/auth/login")
def api_auth_login():
    """Active Directory login and send OTP via email."""
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
        "expires_at": datetime.now(UTC) + timedelta(minutes=5),
    }

    # Send OTP via email
    email_sent = send_otp_email(email, otp, user_info["cn"])

    current_app.logger.info(f"AD Login Success for {email}. OTP Generated (email_sent={email_sent})")
    return jsonify(
        {"status": "otp_required", "message": f"OTP code sent to {email}", "email": email, "email_sent": email_sent}
    )


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

    if datetime.now(UTC) > pending["expires_at"]:
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
        "expires_at": datetime.now(UTC) + timedelta(minutes=10),
    }

    # Establish/Refresh Primary Auth Session (valid for 12 hours)
    now = datetime.now(UTC)
    PRIMARY_SESSIONS[user_cn] = {"login_time": now, "last_mfa_time": now}

    # Clean up pending
    PENDING_OTPS.pop(email, None)

    current_app.logger.info(f"MFA Verified for {email}. Enrollment session token issued (redacted)")
    return jsonify(
        {
            "status": "success",
            "enrollment_session_token": token,
            "user_info": {
                "cn": ENROLLMENT_SESSIONS[token]["cn"],
                "role": ENROLLMENT_SESSIONS[token]["role"],
                "department": ENROLLMENT_SESSIONS[token]["department"],
            },
        }
    )


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

    if datetime.now(UTC) > pending["expires_at"]:
        PENDING_OTPS.pop(email, None)
        return error_response("OTP has expired", 401)

    if pending["otp"] != otp:
        return error_response("Invalid OTP code", 401)

    # Success: Refresh/Establish primary session with updated last_mfa_time
    user_cn = user_info["cn"]
    now = datetime.now(UTC)

    orig_session = PRIMARY_SESSIONS.get(user_cn, {})
    login_time = orig_session.get("login_time", now)

    PRIMARY_SESSIONS[user_cn] = {"login_time": login_time, "last_mfa_time": now}

    PENDING_OTPS.pop(email, None)

    current_app.logger.info(f"Step-up Authentication successful for {user_cn} ({email})")
    return jsonify(
        {"status": "success", "message": "Step-up Authentication successful. Session MFA timestamp refreshed."}
    )
