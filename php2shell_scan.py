#!/usr/bin/env python3
"""
php2shell_scan.py — non-destructive exposure scanner for
CVE-2026-109618 / CVE-2026-109619 (PHP session.upload_progress RCE pair).

Fingerprints the PHP runtime, resolves the patch verdict against the fixed
version table, identifies the SAPI, and probes the shared preconditions
without crashing the target or writing executable session content.

Stdlib only.

    python3 php2shell_scan.py --target https://host.example
    python3 php2shell_scan.py --target https://host.example --json out.json
    python3 php2shell_scan.py --target https://host.example --passive

Exit: 0 no exposure, 1 indicators found, 2 unreachable.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse, urljoin

# Fixed releases per branch. Anything below is vulnerable on that branch.
FIXED = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

AFFECTED_MIN = (5, 4, 0)

UA = "Mozilla/5.0 (compatible; php2shell-scan/1.0; +authorized-testing)"

VER_RE = re.compile(r"PHP[/ ](\d+)\.(\d+)\.(\d+)", re.I)
HTML_VER_RE = re.compile(r"PHP Version\s*</td><td[^>]*>\s*(\d+)\.(\d+)\.(\d+)", re.I)


# --------------------------------------------------------------------------- #
# http
# --------------------------------------------------------------------------- #

@dataclass
class Response:
    status: int = 0
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    error: Optional[str] = None

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


def _recv_all(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while True:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
        except OSError:
            break
    return bytes(buf)


def request(url: str,
            method: str = "GET",
            body: Optional[bytes] = None,
            headers: Optional[dict] = None,
            timeout: float = 10.0,
            verify_tls: bool = True) -> Response:
    """Minimal HTTP/1.1 client. Keeps raw control so we can send bodies that
    urllib would normalise (this matters for multipart probes)."""
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        return Response(error=f"unsupported scheme {u.scheme!r}")

    host = u.hostname
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query

    hdrs = {
        "Host": u.netloc,
        "User-Agent": UA,
        "Accept": "*/*",
        "Connection": "close",
    }
    if headers:
        hdrs.update(headers)
    if body is not None:
        hdrs.setdefault("Content-Length", str(len(body)))

    head = f"{method} {path} HTTP/1.1\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
    head += "\r\n"
    payload = head.encode("latin-1") + (body or b"")

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout)
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            if not verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        sock.sendall(payload)
        data = _recv_all(sock, timeout)

        # read trailing response once more in case of connection: close race
        if not data:
            data = _recv_all(sock, timeout)
        sock.close()
    except (socket.timeout, socket.error, ssl.SSLError) as exc:
        return Response(error=str(exc))

    if not data:
        return Response(error="empty response")

    head_bytes, _, body_bytes = data.partition(b"\r\n\r\n")
    lines = head_bytes.split(b"\r\n")
    status = 0
    if lines and lines[0].startswith(b"HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])

    hdr_map = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            hdr_map[k.decode("latin-1").strip()] = v.decode("latin-1").strip()

    return Response(status=status, headers=hdr_map, body=body_bytes)


# --------------------------------------------------------------------------- #
# fingerprint
# --------------------------------------------------------------------------- #

def parse_version(texts: list[str]) -> Optional[tuple]:
    for text in texts:
        if not text:
            continue
        m = VER_RE.search(text)
        if m:
            return tuple(int(x) for x in m.groups())
    return None


def php_verdict(ver: Optional[tuple]) -> tuple[str, str]:
    """(verdict, rationale). verdict in VULNERABLE / PATCHED / UNKNOWN."""
    if not ver:
        return "UNKNOWN", "no PHP version observable"

    major, minor, patch = ver
    if ver < AFFECTED_MIN:
        return "UNKNOWN", f"{major}.{minor}.{patch} predates the affected range"

    if (major, minor) in FIXED:
        fixed = FIXED[(major, minor)]
        if patch >= fixed:
            return "PATCHED", f"{major}.{minor}.{patch} >= fixed {major}.{minor}.{fixed}"
        return "VULNERABLE", f"{major}.{minor}.{patch} < fixed {major}.{minor}.{fixed}"

    if major == 8 and minor > 5:
        return "UNKNOWN", f"{major}.{minor}.{patch} newer than the known fixed table"

    if major < 8 or (major == 8 and minor < 2):
        return "VULNERABLE", (
            f"{major}.{minor}.{patch} is on an EOL branch — vulnerable unless a "
            f"vendor backport is installed"
        )

    return "UNKNOWN", f"{major}.{minor}.{patch} outside the known table"


def guess_sapi(server: str, powered: str) -> str:
    s = f"{server} {powered}".lower()
    if "apache" in s:
        # Apache can proxy to FPM; mod_php cannot be told apart from headers alone.
        return "apache (mod_php or proxy-pass to FPM)"
    if "nginx" in s:
        return "nginx (almost always proxied to FPM)"
    if "litespeed" in s:
        return "litespeed"
    if "frankenphp" in s or "caddy" in s:
        return "frankenphp/caddy"
    if "php" in s:
        return "php built-in server / cgi"
    return "unknown"


# --------------------------------------------------------------------------- #
# probes
# --------------------------------------------------------------------------- #

def multipart_upload(progress: str, sid_field: str, filename: str,
                     content: bytes = b"Z") -> tuple[bytes, str]:
    boundary = "----php2shellscan" + str(int(time.time()) % 100000)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid_field}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{progress}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("latin-1") + content + f"\r\n--{boundary}--\r\n".encode("latin-1")

    ctype = f"multipart/form-data; boundary={boundary}"
    return body, ctype


def probe_upload_progress(target: str, timeout: float) -> dict:
    """Send one benign multipart upload_progress request and read the signals.

    Does not crash the target and does not put executable content in the
    filename. Only establishes that the handler is reachable."""
    sid = "php2shellscan" + str(int(time.time()))
    body, ctype = multipart_upload("scanprogress", sid, "probe.txt")

    resp = request(target, "POST", body,
                   {"Content-Type": ctype}, timeout=timeout)

    if resp.error:
        return {"reachable": False, "error": resp.error}

    text = resp.body.decode("latin-1", "replace")
    signals = {
        "reachable": True,
        "status": resp.status,
        "fixed_sid_cookie": False,
        "reflects_sid": sid in text,
        "session_warning": bool(re.search(
            r"(upload_progress|session_start|session\.|multipart)", text, re.I)),
        "set_cookie": resp.header("Set-Cookie"),
    }
    set_cookie = resp.header("Set-Cookie")
    if "PHPSESSID" in set_cookie and sid not in set_cookie:
        signals["fixed_sid_cookie"] = True

    return signals


def probe_session_fixation(target: str, timeout: float) -> str:
    """Check whether a POST-body PHPSESSID is honoured (the fixation primitive).

    accepted -> server issued no replacement cookie for our SID
    rejected -> server forced a different PHPSESSID
    unknown  -> cannot tell from headers alone
    """
    sid = "php2shellfix" + str(int(time.time()))
    body, ctype = multipart_upload("fix", sid, "probe.txt")

    resp = request(target, "POST", body,
                   {"Content-Type": ctype, "Cookie": f"PHPSESSID={sid}"},
                   timeout=timeout)
    if resp.error:
        return "unknown"

    set_cookie = resp.header("Set-Cookie")
    if not set_cookie:
        return "accepted"
    if "PHPSESSID" in set_cookie and sid not in set_cookie:
        return "rejected"
    return "unknown"


def probe_lfi(target: str, param: str, timeout: float) -> dict:
    """Optional: test whether a known query parameter behaves as an include() sink."""
    probe = "php://filter/convert.base64-encode/resource=/etc/passwd"
    sep = "&" if "?" in target else "?"
    url = f"{target}{sep}{param}={probe}"

    resp = request(url, timeout=timeout)
    if resp.error:
        return {"sink": "unknown", "error": resp.error}

    text = resp.body.decode("latin-1", "replace")
    # /etc/passwd base64 always ends with the 'root:' record marker once decoded.
    looks_like_b64 = bool(re.fullmatch(r"[A-Za-z0-9+/=\s]{80,}", text.strip()[:2000]))
    hit = "cm9vd" in text or looks_like_b64
    return {
        "sink": "likely" if hit else "no",
        "status": resp.status,
        "note": "base64 of /etc/passwd returned" if hit else "no include evidence",
    }


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #

def scan(target: str, timeout: float, passive: bool,
         lfi_param: Optional[str]) -> dict:
    report = {
        "target": target,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "passive_only": passive,
    }

    base = request(target, timeout=timeout)
    if base.error:
        report["reachable"] = False
        report["error"] = base.error
        return report

    report["reachable"] = True
    report["http_status"] = base.status
    report["server"] = base.header("Server")
    report["x_powered_by"] = base.header("X-Powered-By")

    body_text = base.body[:65536].decode("latin-1", "replace")
    m = HTML_VER_RE.search(body_text)
    html_ver = tuple(int(x) for x in m.groups()) if m else None

    ver = parse_version([
        base.header("X-Powered-By"),
        base.header("Server"),
        body_text if html_ver else "",
    ]) or html_ver

    report["php_version"] = ".".join(map(str, ver)) if ver else None
    verdict, reason = php_verdict(ver)
    report["verdict"] = verdict
    report["verdict_reason"] = reason
    report["sapi"] = guess_sapi(base.header("Server"), base.header("X-Powered-By"))
    report["chain_d_possible"] = "apache" in report["sapi"].lower()

    if not passive:
        report["upload_progress"] = probe_upload_progress(target, timeout)
        report["session_fixation"] = probe_session_fixation(target, timeout)
    else:
        report["upload_progress"] = {"skipped": True}
        report["session_fixation"] = "skipped"

    if lfi_param and not passive:
        report["lfi"] = probe_lfi(target, lfi_param, timeout)

    findings = []
    if verdict == "VULNERABLE":
        findings.append(reason)
    up = report.get("upload_progress", {})
    if up.get("reachable") and up.get("status") in (200, 201, 204, 302, 400, 500):
        findings.append("multipart upload_progress endpoint reachable")
    if report.get("session_fixation") == "accepted":
        findings.append("POST-body PHPSESSID accepted (session fixation primitive)")
    if report.get("lfi", {}).get("sink") == "likely":
        findings.append("LFI sink confirmed — Chain A is directly exploitable")

    report["findings"] = findings
    report["exposed"] = bool(findings)
    return report


def render(report: dict) -> str:
    lines = []
    lines.append(f"target        {report.get('target')}")
    if not report.get("reachable"):
        lines.append(f"reachable     no  ({report.get('error')})")
        return "\n".join(lines)

    lines.append(f"reachable     yes (HTTP {report.get('http_status')})")
    lines.append(f"server        {report.get('server') or '-'}")
    lines.append(f"x-powered-by  {report.get('x_powered_by') or '-'}")
    lines.append(f"php version   {report.get('php_version') or 'not disclosed'}")
    lines.append(f"verdict       {report.get('verdict')}  [{report.get('verdict_reason')}]")
    lines.append(f"sapi          {report.get('sapi')}")
    lines.append(f"chain d       {'possible (mod_php)' if report.get('chain_d_possible') else 'not on mod_php'}")

    up = report.get("upload_progress", {})
    if up.get("skipped"):
        lines.append("upload_prog   skipped (passive)")
    elif up.get("reachable"):
        lines.append(f"upload_prog   HTTP {up.get('status')}")
    else:
        lines.append(f"upload_prog   unreachable ({up.get('error')})")

    lines.append(f"session fix   {report.get('session_fixation')}")
    if "lfi" in report:
        lines.append(f"lfi sink      {report['lfi'].get('sink')}")

    lines.append("")
    if report.get("findings"):
        lines.append("FINDINGS")
        for f in report["findings"]:
            lines.append(f"  - {f}")
        lines.append("")
        lines.append("exposure indicators present — validate in an authorized lab, patch to "
                     "8.2.35/8.3.36/8.4.27/8.5.12")
    else:
        lines.append("no exposure indicators from this pass")
        lines.append("note: stripped X-Powered-By means the verdict is UNKNOWN, not clean")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="CVE-2026-109618/109619 non-destructive exposure scanner")
    ap.add_argument("--target", required=True, help="base URL, e.g. https://host/")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--passive", action="store_true", help="headers/body only, no probes")
    ap.add_argument("--lfi-param", default=None,
                    help="optional query parameter to test as an include() sink")
    ap.add_argument("--json", default=None, help="write JSON report to path")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    args = ap.parse_args(argv)

    global request
    if args.insecure:
        _orig = request
        def request(url, method="GET", body=None, headers=None, timeout=10.0, verify_tls=True):
            return _orig(url, method, body, headers, timeout, verify_tls=False)

    report = scan(args.target, args.timeout, args.passive, args.lfi_param)
    print(render(report))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\njson report -> {args.json}")

    if not report.get("reachable"):
        return 2
    return 1 if report.get("exposed") else 0


if __name__ == "__main__":
    sys.exit(main())
