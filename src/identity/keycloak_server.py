"""
keycloak_server.py
------------------
Phase 1 (Step 1.3): Standalone Keycloak IdP Server running on :8080.
Implements the Keycloak Admin REST API and OIDC Token Minting:
- Serves CloudGovRealm
- Issues JWT tokens with SAML/OIDC claim:
    https://aws.amazon.com/SAML/Attributes/PrincipalTag:RiskLevel
- Direct Backchannel Logout:
    POST /admin/realms/{realm}/users/{user_id}/logout
- Web Admin Console at http://localhost:8080/
"""

import time
import uuid
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="Keycloak Identity Provider (Standalone :8080)",
    description="Keycloak IdP Server for CloudGovRealm supporting STS Session Tagging & Backchannel Logout",
    version="24.0.0-standalone",
)

# In-memory Keycloak database
REALMS = {
    "master": {"realm": "master", "enabled": True},
    "CloudGovRealm": {"realm": "CloudGovRealm", "enabled": True, "displayName": "Adaptive Cloud Governance Realm"},
}

USERS = {
    "alice_dev": {"id": "usr_alice_001", "username": "alice_dev", "email": "alice@cloudgov.local", "enabled": True},
    "bob_contractor": {"id": "usr_bob_002", "username": "bob_contractor", "email": "bob@cloudgov.local", "enabled": True},
    "mallory_attacker": {"id": "usr_mallory_003", "username": "mallory_attacker", "email": "mallory@cloudgov.local", "enabled": True},
}

ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {
    "alice_dev": {"session_id": "sess_alice_active", "user_id": "alice_dev", "status": "ACTIVE", "created_at": time.time(), "tag": "Low"},
    "bob_contractor": {"session_id": "sess_bob_active", "user_id": "bob_contractor", "status": "ACTIVE", "created_at": time.time(), "tag": "Low"},
    "mallory_attacker": {"session_id": "sess_mallory_active", "user_id": "mallory_attacker", "status": "ACTIVE", "created_at": time.time(), "tag": "High"},
}

REVOKED_LOG: List[Dict[str, Any]] = []


@app.get("/", response_class=HTMLResponse)
def admin_console_ui():
    """Keycloak Admin Console visual landing page."""
    sessions_html = ""
    for u, s in ACTIVE_SESSIONS.items():
        badge_color = "#28a745" if s["status"] == "ACTIVE" else "#dc3545"
        tag_color = "#dc3545" if s.get("tag") == "High" else "#17a2b8"
        sessions_html += f"""
        <tr>
            <td><strong>{u}</strong></td>
            <td><code>{s['session_id']}</code></td>
            <td><span style="background:{badge_color}; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold;">{s['status']}</span></td>
            <td><span style="background:{tag_color}; color:#fff; padding:3px 8px; border-radius:4px; font-weight:bold;">{s.get('tag', 'Low')}</span></td>
            <td>{time.strftime('%H:%M:%S', time.localtime(s['created_at']))}</td>
        </tr>
        """

    revoked_html = ""
    for r in reversed(REVOKED_LOG[-5:]):
        revoked_html += f"""
        <li style="color:#721c24; margin-bottom:5px;">
            <strong>{r['user_id']}</strong> session revoked at {time.strftime('%H:%M:%S', time.localtime(r['timestamp']))} via <code>POST /admin/realms/{r['realm']}/users/{r['user_id']}/logout</code>
        </li>
        """
    if not revoked_html:
        revoked_html = "<li style='color:#6c757d;'>No sessions revoked yet.</li>"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Keycloak Admin Console - CloudGovRealm</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f7fa; margin: 0; padding: 20px; }}
            .card {{ background: #fff; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }}
            h1, h2, h3 {{ color: #004b87; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e1e4e8; }}
            th {{ background: #f1f4f8; color: #333; }}
            .header-bar {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #004b87; padding-bottom: 15px; margin-bottom: 20px; }}
            .realm-badge {{ background: #004b87; color: white; padding: 5px 12px; border-radius: 15px; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="card header-bar">
            <div>
                <h1>🔑 Keycloak IdP Server (Standalone :8080)</h1>
                <p style="margin:0; color:#555;">Identity & Access Governance Plane with Dynamic SAML/OIDC Session Tagging</p>
            </div>
            <div class="realm-badge">Realm: CloudGovRealm</div>
        </div>

        <div class="card">
            <h2>Active User Sessions & Dynamic PrincipalTags</h2>
            <table>
                <tr>
                    <th>User / Principal</th>
                    <th>Session ID</th>
                    <th>Session Status</th>
                    <th>Injected PrincipalTag:RiskLevel</th>
                    <th>Created Time</th>
                </tr>
                {sessions_html}
            </table>
        </div>

        <div class="card">
            <h2>Recent Backchannel Logout Events</h2>
            <ul style="padding-left: 20px;">
                {revoked_html}
            </ul>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


# -------------------------------------------------------------
# KEYCLOAK OIDC & REALM ENDPOINTS
# -------------------------------------------------------------
@app.get("/realms/master")
def get_master_realm():
    return REALMS["master"]


@app.get("/realms/{realm}")
def get_realm(realm: str):
    if realm in REALMS:
        return REALMS[realm]
    return {"realm": realm, "enabled": True}


@app.post("/realms/master/protocol/openid-connect/token")
def admin_cli_token(
    client_id: str = Form("admin-cli"),
    username: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    grant_type: str = Form("password"),
):
    """Generates Admin OAuth2 Token for Keycloak Admin REST API."""
    return {
        "access_token": f"kc_admin_token_{uuid.uuid4().hex[:16]}",
        "expires_in": 3600,
        "token_type": "Bearer",
        "scope": "openid email profile",
    }


@app.post("/realms/{realm}/protocol/openid-connect/token")
def mint_oidc_token_with_session_tag(
    realm: str,
    client_id: str = Form(...),
    username: str = Form(...),
    grant_type: str = Form("password"),
):
    """
    Step 3.2: Keycloak Session Tag Injection.
    Mints user token injecting SAML/OIDC claim:
        https://aws.amazon.com/SAML/Attributes/PrincipalTag:RiskLevel
    """
    risk_level = "High" if "mallory" in username else "Low"
    token_id = str(uuid.uuid4())

    ACTIVE_SESSIONS[username] = {
        "session_id": f"sess_{username}_{token_id[:8]}",
        "user_id": username,
        "status": "ACTIVE",
        "created_at": time.time(),
        "tag": risk_level,
    }

    return {
        "access_token": f"jwt_{token_id}",
        "expires_in": 3600,
        "token_type": "Bearer",
        "session_state": token_id,
        "https://aws.amazon.com/SAML/Attributes/PrincipalTag:RiskLevel": risk_level,
        "https://aws.amazon.com/SAML/Attributes/PrincipalTag:UserId": username,
    }


# -------------------------------------------------------------
# KEYCLOAK ADMIN REST API ENDPOINTS
# -------------------------------------------------------------
@app.get("/admin/realms/{realm}/users")
def list_users(realm: str):
    return list(USERS.values())


@app.post("/admin/realms/{realm}/users/{user_id}/logout")
def backchannel_logout(realm: str, user_id: str):
    """
    Step 4.2: Direct Backchannel Logout.
    POST /admin/realms/{realm}/users/{id}/logout
    Instantly kills active sessions for the compromised user.
    """
    t0 = time.perf_counter()

    # Find and revoke
    matched = False
    for u in ACTIVE_SESSIONS:
        if u == user_id or USERS.get(u, {}).get("id") == user_id:
            ACTIVE_SESSIONS[u]["status"] = "REVOKED"
            ACTIVE_SESSIONS[u]["revoked_at"] = time.time()
            matched = True
            REVOKED_LOG.append({
                "user_id": u,
                "realm": realm,
                "timestamp": time.time(),
            })

    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    return JSONResponse(
        status_code=204,  # Standard Keycloak 204 No Content for successful logout
        content=None,
        headers={
            "X-Keycloak-Revocation-Latency-Ms": f"{elapsed_ms:.4f}",
            "X-Keycloak-Revocation-Status": "SUCCESS_REVOKED",
        },
    )


@app.get("/admin/realms/{realm}/sessions")
def get_active_sessions(realm: str):
    return list(ACTIVE_SESSIONS.values())


if __name__ == "__main__":
    import uvicorn
    print("[*] Starting Standalone Keycloak IdP Server on http://127.0.0.1:8080...")
    uvicorn.run(app, host="127.0.0.1", port=8080)

