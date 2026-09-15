from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
import re
import httpx
import urllib.parse
import os
import time
import hmac
import hashlib
import base64# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="Open Minds Daily Report Designer"
)

# Allow the GitHub Pages Daily Report frontend to call this Render API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://abhijeetraj22.github.io"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# ============================================================
# SERVER-SIDE PASSWORD PROTECTION
#
# IMPORTANT:
# The password is read ONLY from Render environment variables.
# It is never stored in the HTML/JavaScript.
#
# Render Environment Variable:
#   SECRET_KEY = your private login password
#
# The existing SECRET_KEY from your Render service is used directly as the
# Daily Report login password. No new DAILY_REPORT_PASSWORD variable is needed.
# ============================================================

# Render uses SECRET_KEY as the Daily Report login password.
# DAILY_REPORT_PASSWORD is accepted only as an optional override.
AUTH_PASSWORD = (
    os.getenv("SECRET_KEY", "").strip()
    or os.getenv("DAILY_REPORT_PASSWORD", "").strip()
)

# Prefer a separate signing secret when available; otherwise use the
# password itself so only one Render variable is required.
AUTH_SECRET = (
    os.getenv("DAILY_REPORT_AUTH_SECRET", "").strip()
    or AUTH_PASSWORD
)

AUTH_COOKIE = "daily_report_auth"
AUTH_MAX_AGE = 12 * 60 * 60  # 12 hours


def _auth_secret_bytes() -> bytes:
    # Fail closed if the deployment was not configured correctly.
    # SECRET_KEY is both the login password and cookie-signing secret.
    secret = AUTH_SECRET or AUTH_PASSWORD
    return secret.encode("utf-8")


def _make_auth_token() -> str:
    expires = int(time.time()) + AUTH_MAX_AGE
    payload = str(expires).encode("utf-8")
    signature = hmac.new(
        _auth_secret_bytes(),
        payload,
        hashlib.sha256,
    ).digest()

    return (
        base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        + "."
        + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    )


def _valid_auth_token(token: str | None) -> bool:
    if not token or "." not in token or not _auth_secret_bytes():
        return False

    encoded_expiry, encoded_signature = token.split(".", 1)

    try:
        payload = base64.urlsafe_b64decode(encoded_expiry + "===")
        supplied_signature = base64.urlsafe_b64decode(
            encoded_signature + "==="
        )
        expires = int(payload.decode("utf-8"))
    except (ValueError, TypeError, base64.binascii.Error):
        return False

    if expires < int(time.time()):
        return False

    expected_signature = hmac.new(
        _auth_secret_bytes(),
        payload,
        hashlib.sha256,
    ).digest()

    return hmac.compare_digest(
        supplied_signature,
        expected_signature,
    )


def _is_authenticated(request: Request) -> bool:
    if not AUTH_PASSWORD:
        return False

    # Render-hosted UI uses the normal HttpOnly cookie.
    if _valid_auth_token(request.cookies.get(AUTH_COOKIE)):
        return True

    # GitHub Pages uses a short-lived bearer token returned by /verify-code.
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        return _valid_auth_token(token)

    return False


LOGIN_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Daily Report — Login</title>
<style>
  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    min-height: 100%;
    font-family: Arial, Helvetica, sans-serif;
    background: linear-gradient(135deg, #edf3f8, #dfeaf3);
    color: #173f73;
  }
  body {
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 20px;
  }
  .login-card {
    width: min(430px, 100%);
    background: white;
    border: 1px solid #cbd9e5;
    border-radius: 18px;
    padding: 30px;
    box-shadow: 0 22px 60px rgba(20, 50, 80, .18);
  }
  h1 {
    margin: 0 0 8px;
    font-size: 26px;
  }
  p {
    margin: 0 0 24px;
    color: #60758a;
    font-size: 14px;
  }
  label {
    display: block;
    margin-bottom: 7px;
    font-size: 12px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: .4px;
  }
  input {
    width: 100%;
    padding: 13px 14px;
    border: 1px solid #c8d5e0;
    border-radius: 10px;
    font-size: 16px;
    outline: none;
  }
  input:focus {
    border-color: #557ca3;
    box-shadow: 0 0 0 3px rgba(85,124,163,.12);
  }
  button {
    width: 100%;
    margin-top: 14px;
    padding: 13px 14px;
    border: 0;
    border-radius: 10px;
    color: white;
    background: #173f73;
    font-size: 15px;
    font-weight: 800;
    cursor: pointer;
  }
  .error {
    margin: 0 0 16px;
    padding: 11px 12px;
    border-radius: 9px;
    color: #8c1d22;
    background: #fdebed;
    font-size: 13px;
  }
  .brand {
    margin-bottom: 22px;
    font-size: 13px;
    font-weight: 800;
    letter-spacing: .5px;
  }
</style>
</head>
<body>
  <main class="login-card">
    <div class="brand">OPEN MINDS • DAILY REPORT</div>
    <h1>Secure Access</h1>
    <p>Enter the password to open the Daily Report Designer.</p>
    __ERROR__
    <form method="post" action="/login">
      <label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="current-password" required autofocus>
      <button type="submit">Open Daily Report</button>
    </form>
  </main>
</body>
</html>
"""


# Public login page.
@app.get("/login", response_class=HTMLResponse)
async def login_page():
    if not AUTH_PASSWORD:
        return HTMLResponse(
            "<h1>Server authentication is not configured.</h1>"
            "<p>Set <b>SECRET_KEY</b> in Render Environment Variables.</p>",
            status_code=503,
        )

    return HTMLResponse(LOGIN_PAGE.replace("__ERROR__", ""))


@app.post("/login")
async def login(request: Request):
    if not AUTH_PASSWORD:
        return HTMLResponse(
            "<h1>Server authentication is not configured.</h1>"
            "<p>Set <b>SECRET_KEY</b> in Render Environment Variables.</p>",
            status_code=503,
        )

    body = await request.body()
    form = urllib.parse.parse_qs(
        body.decode("utf-8"),
        keep_blank_values=True,
    )
    password = form.get("password", [""])[0]

    if not hmac.compare_digest(password, AUTH_PASSWORD):
        return HTMLResponse(
            LOGIN_PAGE.replace(
                "__ERROR__",
                '<div class="error">Incorrect password. Please try again.</div>'
            ),
            status_code=401,
        )

    response = RedirectResponse(
        url="/",
        status_code=303,
    )

    response.set_cookie(
        key=AUTH_COOKIE,
        value=_make_auth_token(),
        max_age=AUTH_MAX_AGE,
        httponly=True,
        samesite="none",
        secure=True,
        path="/",
    )

    return response


@app.post("/verify-code")
async def verify_code(request: Request):
    """Verify the GitHub Pages secure code and return a signed short-lived token."""
    if not AUTH_PASSWORD:
        return Response(
            content='{"status":"error","message":"Authentication is not configured."}',
            status_code=503,
            media_type="application/json",
        )

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    code = str(payload.get("code", "")).strip()
    if not hmac.compare_digest(code, AUTH_PASSWORD):
        return Response(
            content='{"status":"error","message":"Incorrect secure code."}',
            status_code=401,
            media_type="application/json",
        )

    return {
        "status": "success",
        "token": _make_auth_token(),
    }


@app.get("/logout")
async def logout(request: Request):
    response = RedirectResponse(
        url="/login",
        status_code=303,
    )
    response.delete_cookie(
        key=AUTH_COOKIE,
        path="/",
    )
    return response


# Protect the Daily Report page and all application API endpoints.
# Static assets remain public so the login page and browser can load images.
@app.middleware("http")
async def password_gate(request: Request, call_next):
    path = request.url.path

    # ------------------------------------------------------------
    # CORS PREFLIGHT
    # ------------------------------------------------------------
    # Browser sends OPTIONS before cross-origin POST requests.
    # It must reach CORSMiddleware without authentication.
    if request.method == "OPTIONS":
        return await call_next(request)

    public_paths = {
        "/login",
        "/logout",
        "/health",
        "/verify-code",
    }

    if (
        path not in public_paths
        and (
            path == "/"
            or path.startswith("/api/")
            or path == "/save-report-json"
        )
    ):
        if not _is_authenticated(request):
            if path == "/" and request.method == "GET":
                return RedirectResponse(
                    url="/login",
                    status_code=303,
                )

            return Response(
                content="Authentication required.",
                status_code=401,
                media_type="text/plain",
            )

    return await call_next(request)


# ============================================================
# DIRECTORIES
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

TEMPLATES_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

(STATIC_DIR / "images").mkdir(exist_ok=True)


# ============================================================
# STATIC FILES
# ============================================================

app.mount(
    "/static",
    StaticFiles(directory=str(STATIC_DIR)),
    name="static"
)


# ============================================================
# MODELS
# ============================================================

class ParseRequest(BaseModel):
    text: str


class IconSearchRequest(BaseModel):
    q: str = "clipboard"
    limit: int = 90


class IconSvgRequest(BaseModel):
    name: str


# ============================================================
# HOME
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def home():
    """
    Serve index.html directly from the GitHub/Render project root.

    The application does NOT require templates/index.html.
    It supports both layouts:
        1. ./index.html
        2. ./templates/index.html
    The root index.html is preferred so the GitHub repository can keep
    main.py and index.html together.
    """

    candidate_files = [
        BASE_DIR / "index.html",
        TEMPLATES_DIR / "index.html",
    ]

    for html_file in candidate_files:
        if html_file.exists() and html_file.is_file():
            return HTMLResponse(
                html_file.read_text(encoding="utf-8")
            )

    return HTMLResponse(
        """
        <!doctype html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Daily Report</title>
        </head>
        <body style="font-family:Arial;padding:40px">
          <h1>index.html not found</h1>
          <p>
            Put <b>index.html</b> in the same GitHub repository folder
            as <b>main.py</b>.
          </p>
          <p>
            Expected:
            <code>/index.html</code>
          </p>
        </body>
        </html>
        """,
        status_code=500
    )




# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
async def health():
    index_root = BASE_DIR / "index.html"
    index_template = TEMPLATES_DIR / "index.html"

    return {
        "status": "ok",
        "index_root": index_root.exists(),
        "index_template": index_template.exists(),
        "authentication_configured": bool(AUTH_PASSWORD),
    }

# ============================================================
# PARSER
# ============================================================

def parse_report(text: str):

    lines = [
        line.strip()
        for line in text.splitlines()
    ]

    sections = []

    current_section = None

    for line in lines:

        if not line:
            continue

        # ----------------------------------------------------
        # SECTION
        # ----------------------------------------------------

        section_match = re.match(
            r"^\*(.+?)\*$",
            line
        )

        if section_match:

            title = section_match.group(1).strip()

            current_section = {
                "title": title,
                "items": []
            }

            sections.append(
                current_section
            )

            continue

        # ----------------------------------------------------
        # TASK
        # ----------------------------------------------------

        if line.startswith("*"):

            clean = line.lstrip("*").strip()

            if not clean:
                continue

            if current_section is None:

                current_section = {
                    "title": "DESCRIPTION",
                    "items": []
                }

                sections.append(
                    current_section
                )

            current_section["items"].append(
                {
                    "text": clean,
                    "icons": suggest_icons(clean)
                }
            )

    return {
        "sections": sections
    }


# ============================================================
# ICON SUGGESTION
# ============================================================

def suggest_icons(text: str):
    """Return icons ordered from most semantically relevant to least relevant."""
    t = text.lower().strip()

    # Highly specific phrases first.  The frontend uses icons[0] as the
    # automatic choice, so ordering matters.
    rules = [
        (("printed" , "question paper"), ["mdi:printer", "mdi:file-document-edit"]),
        (("formatted", "question paper"), ["mdi:file-document-edit", "mdi:format-align-left"]),
        (("collected notebooks",), ["mdi:notebook-multiple", "mdi:book-multiple"]),
        (("homework feedback", "google form"), ["mdi:form-select", "mdi:clipboard-check"]),
        (("dispersal duty",), ["mdi:account-multiple-check", "mdi:account-group"]),
        (("q/a",), ["mdi:clipboard-text", "mdi:help-circle"]),
        (("re-arranged", "bundle"), ["mdi:package-variant-closed", "mdi:archive-outline"]),
        (("distributed", "answer-copy"), ["mdi:account-multiple", "mdi:clipboard-check"]),
        (("transfer certificate", "correction"), ["mdi:certificate", "mdi:file-certificate"]),
        (("transfer certificate",), ["mdi:certificate", "mdi:file-certificate"]),
        (("marksheet",), ["mdi:file-chart", "mdi:certificate"]),
        (("caste certificate", "uploaded"), ["mdi:cloud-upload", "mdi:file-upload"]),
        (("caste certificate",), ["mdi:certificate", "mdi:file-certificate"]),
        (("migration certificate",), ["mdi:passport", "mdi:certificate"]),
        (("biometric", "attendance"), ["mdi:fingerprint", "mdi:account-check"]),
        (("attendance",), ["mdi:calendar-check", "mdi:account-check"]),
        (("student",), ["mdi:account-school", "mdi:account-group"]),
        (("teacher",), ["mdi:account-tie", "mdi:account-school"]),
        (("principal",), ["mdi:account-tie", "mdi:account-school"]),
        (("certificate",), ["mdi:certificate", "mdi:file-certificate"]),
        (("uploaded",), ["mdi:cloud-upload", "mdi:file-upload"]),
        (("verified",), ["mdi:clipboard-check", "mdi:check-decagram"]),
        (("verify",), ["mdi:clipboard-check", "mdi:check-decagram"]),
        (("bus",), ["mdi:bus", "mdi:bus-school"]),
        (("email",), ["mdi:email", "mdi:email-outline"]),
        (("message",), ["mdi:message-text", "mdi:message"]),
    ]

    for needles, icons in rules:
        if all(n in t for n in needles):
            return icons

    if "print" in t:
        return ["mdi:printer", "mdi:file-document"]
    if "question" in t or "exam" in t:
        return ["mdi:file-document-edit", "mdi:clipboard-text"]
    if "distributed" in t or "given" in t:
        return ["mdi:account-multiple", "mdi:clipboard-check"]
    if "bundle" in t or "arranged" in t:
        return ["mdi:package-variant-closed", "mdi:archive-outline"]
    if "check" in t or "correction" in t:
        return ["mdi:clipboard-check", "mdi:file-check"]

    return ["mdi:clipboard-text", "mdi:file-document", "mdi:clipboard-check"]




# ============================================================
# JSON REPORT SAVE
# ============================================================

class SaveReportRequest(BaseModel):
    date: str
    day: str = ""
    title: str = "DESCRIPTION"
    source: str = ""
    rows: list = []


GITHUB_OWNER = "abhijeetraj22"
GITHUB_REPO = "daily_report_storage"
GITHUB_BRANCH = "main"
GITHUB_JSON_DIR = "json"


@app.post("/save-report-json")
async def save_report_json(request: SaveReportRequest):
    """
    Save the current report JSON into:
    abhijeetraj22/daily_report_storage/json/DD-MM-YYYY.json

    Authentication is already enforced by password_gate.
    GITHUB_TOKEN remains server-side in Render Environment Variables.
    """

    token = os.getenv("GITHUB_TOKEN", "").strip()

    if not token:
        return Response(
            content="GITHUB_TOKEN is not configured on the Render server.",
            status_code=503,
            media_type="text/plain",
        )

    safe_date = str(request.date or "").strip()

    if not re.fullmatch(r"\d{2}-\d{2}-\d{4}", safe_date):
        return Response(
            content="Invalid report date. Expected DD-MM-YYYY.",
            status_code=400,
            media_type="text/plain",
        )

    payload = {
        "date": safe_date,
        "day": str(request.day or "").strip(),
        "title": str(request.title or "DESCRIPTION").strip(),
        "source": str(request.source or ""),
        "rows": request.rows if isinstance(request.rows, list) else [],
    }

    import json
    encoded_content = base64.b64encode(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
    ).decode("ascii")

    file_path = f"{GITHUB_JSON_DIR}/{safe_date}.json"
    api_url = (
        f"https://api.github.com/repos/"
        f"{GITHUB_OWNER}/{GITHUB_REPO}/contents/{file_path}"
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:

            # Check whether the file already exists so GitHub can receive
            # the required SHA for an update.
            existing_sha = None
            existing_response = await client.get(
                api_url,
                headers=headers,
                params={"ref": GITHUB_BRANCH},
            )

            if existing_response.status_code == 200:
                existing_data = existing_response.json()
                existing_sha = existing_data.get("sha")
            elif existing_response.status_code != 404:
                return Response(
                    content=(
                        "GitHub file lookup failed: "
                        + existing_response.text
                    ),
                    status_code=502,
                    media_type="text/plain",
                )

            commit_payload = {
                "message": f"Update Daily Report {safe_date}",
                "content": encoded_content,
                "branch": GITHUB_BRANCH,
            }

            if existing_sha:
                commit_payload["sha"] = existing_sha

            save_response = await client.put(
                api_url,
                headers=headers,
                json=commit_payload,
            )

            if save_response.status_code not in (200, 201):
                return Response(
                    content=(
                        "GitHub JSON save failed: "
                        + save_response.text
                    ),
                    status_code=502,
                    media_type="text/plain",
                )

            return {
                "success": True,
                "date": safe_date,
                "filename": f"{safe_date}.json",
                "path": file_path,
            }

    except Exception as exc:
        return Response(
            content=f"JSON save error: {exc}",
            status_code=502,
            media_type="text/plain",
        )


# ============================================================
# PARSE ENDPOINT
# ============================================================

@app.post("/api/parse")
async def parse_endpoint(
    request: ParseRequest
):

    return parse_report(
        request.text
    )


# ============================================================
# ICON SEARCH
# ============================================================

@app.post("/api/icons/search")
async def icon_search(
    request: IconSearchRequest
):

    query = request.q.strip()

    if not query:
        query = "clipboard"

    limit = max(
        10,
        min(request.limit, 120)
    )

    encoded = urllib.parse.quote(
        query
    )

    url = (
        "https://api.iconify.design/"
        f"collection?prefix=mdi&"
        f"query={encoded}"
    )

    # --------------------------------------------------------
    # Use Iconify search API
    # --------------------------------------------------------

    search_url = (
        "https://api.iconify.design/search"
        f"?query={encoded}"
        f"&limit={limit}"
    )

    try:

        async with httpx.AsyncClient(
            timeout=10
        ) as client:

            response = await client.get(
                search_url
            )

            response.raise_for_status()

            data = response.json()

            icons = []

            for name in data.get(
                "icons",
                []
            ):

                if ":" not in name:
                    name = f"mdi:{name}"

                icons.append(
                    {
                        "name": name
                    }
                )

            return {
                "icons": icons[:limit]
            }

    except Exception:

        # ----------------------------------------------------
        # Fallback icons
        # ----------------------------------------------------

        fallback = [
            "mdi:printer",
            "mdi:clipboard-text",
            "mdi:clipboard-check",
            "mdi:file-document",
            "mdi:file-certificate",
            "mdi:certificate",
            "mdi:account-group",
            "mdi:account-school",
            "mdi:school",
            "mdi:package-variant",
            "mdi:archive",
            "mdi:cloud-upload",
            "mdi:fingerprint",
            "mdi:calendar-check",
            "mdi:bus",
            "mdi:email",
            "mdi:message",
            "mdi:eye",
            "mdi:monitor",
            "mdi:help-circle"
        ]

        return {
            "icons": [
                {
                    "name": x
                }
                for x in fallback
            ]
        }


# ============================================================
# ICON SVG
#
# IMPORTANT:
# Instead of leaving <iconify-icon> in the report,
# this endpoint returns the actual SVG.
#
# Therefore PDF printing does NOT depend on Iconify
# web-component rendering.
# ============================================================

@app.post("/api/icons/svg")
async def icon_svg(
    request: IconSvgRequest
):

    name = request.name.strip()

    if ":" not in name:
        name = f"mdi:{name}"

    encoded = urllib.parse.quote(
        name,
        safe=""
    )

    url = (
        f"https://api.iconify.design/"
        f"{encoded}.svg"
        "?height=1em"
        "&width=1em"
    )

    try:

        async with httpx.AsyncClient(
            timeout=10
        ) as client:

            response = await client.get(
                url
            )

            response.raise_for_status()

            svg = response.text

            return {
                "name": name,
                "svg": svg
            }

    except Exception:

        return {
            "name": name,
            "svg": ""
        }
