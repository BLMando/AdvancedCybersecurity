import urllib.request
import urllib.error
import json
import ssl
import sys

# Configure SSL context to trust self-signed certs for testing
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def main():
    print("=== Testing Trusted Proxy OIDC Query Flow ===")
    
    server_url = "https://localhost:8080"
    user_email = "paolo.roselli@ospedale.it"
    user_cn = "paolo.roselli"
    
    # Step 0: Perform Primary AD Authentication + MFA
    print(f"\n[*] Step 0: Simulating Primary Auth (AD Login) for {user_email}...")
    login_url = f"{server_url}/api/auth/login"
    login_payload = {"email": user_email, "password": "password123"}
    
    req_login = urllib.request.Request(
        login_url,
        data=json.dumps(login_payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req_login, context=ssl_context, timeout=10) as resp:
            login_data = json.loads(resp.read().decode('utf-8'))
            otp = login_data.get("simulated_otp")
            print(f"[✓] Login successful. Simulated OTP received: {otp}")
            
            # Verify OTP
            print(f"[*] Verifying MFA OTP for {user_email}...")
            verify_url = f"{server_url}/api/auth/verify-otp"
            verify_payload = {"email": user_email, "otp": otp}
            
            req_verify = urllib.request.Request(
                verify_url,
                data=json.dumps(verify_payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req_verify, context=ssl_context, timeout=10) as verify_resp:
                verify_data = json.loads(verify_resp.read().decode('utf-8'))
                print(f"[✓] MFA Verified! Primary session token: {verify_data.get('enrollment_session_token')}")
    except Exception as e:
        print(f"[✗] Primary Authentication failed: {e}")
        sys.exit(1)

    # 1. Start proxy session and get OIDC token from the local agent
    agent_url = "http://localhost:9090/oidc/token"
    payload = {"common_name": user_cn}
    
    print(f"\n[*] Fetching OIDC JWT token from local agent at {agent_url}...")
    req = urllib.request.Request(
        agent_url,
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            resp_data = json.loads(response.read().decode('utf-8'))
            jwt_token = resp_data.get("token") or resp_data.get("access_token")
            print(f"[✓] Successfully retrieved JWT token: {jwt_token[:50]}...{jwt_token[-50:] if len(jwt_token) > 100 else ''}")
    except urllib.error.HTTPError as e:
        print(f"[✗] Agent returned error: {e.read().decode()}")
        sys.exit(1)
    except Exception as e:
        print(f"[✗] Connection to agent failed: {e}")
        print("Please check if the macOS agent is running on port 9090.")
        sys.exit(1)
 
    # 2. Call Web Console API endpoint to perform the query
    query_url = "https://localhost:8080/api/query"
    query_payload = {
        "user": "paolo.roselli",
        "collection": "clinical_records",
        "filter": '{}',
        "jwt_token": jwt_token
    }
    
    print(f"\n[*] Sending query request to Flask backend at {query_url}...")
    req = urllib.request.Request(
        query_url,
        data=json.dumps(query_payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as response:
            result = json.loads(response.read().decode('utf-8'))
            print("[✓] Flask backend successfully connected and returned results!")
            print(json.dumps(result, indent=2))
    except urllib.error.HTTPError as e:
        print(f"[✗] Flask backend returned error status {e.code}: {e.read().decode()}")
        sys.exit(1)
    except Exception as e:
        print(f"[✗] Query request failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
