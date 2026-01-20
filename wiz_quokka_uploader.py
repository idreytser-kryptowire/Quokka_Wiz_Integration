
#!/usr/bin/env python3
"""
upload_sarif.py

Converts a Quokka (or any SARIF 2.1.0) results file into Wiz SAST Application
Vulnerability Findings Schema (v2), then uploads it via Wiz Enrichment v2 API.

Features:
- Form-encoded OAuth token request (Client Credentials, audience "wiz-api").
- Request upload slot, PUT to presigned S3, poll SystemActivity.
- Poll-only mode: query a SystemActivity ID without uploading.
- Deduplication by `name` (case-insensitive, trim): first occurrence wins.
- INFO logging for all key actions and failures + dedup summaries.

Author: You :)
"""

import argparse
import datetime as dt
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests
from urllib.parse import urlparse

# ---------- Config & Defaults ----------
DEFAULT_INTEGRATION_ID = "55c176cc-d155-43a2-98ed-aa56873a1ca1"  # placeholder ok
DEFAULT_DATASOURCE_ID = "QUOKKA_CUSTOMER_NAME"

# Asset (repository branch) placeholders
DEFAULT_ASSET_NAME = "com.secure-app:main"
DEFAULT_ASSET_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, DEFAULT_ASSET_NAME))
DEFAULT_BRANCH_NAME = "main"
DEFAULT_REPO_NAME = "myorg/secure-app"
DEFAULT_REPO_URL = "https://github.com/myorg/secure-app"
DEFAULT_VCS = "GitHub"  # Allowed: GitHub, GitLab, AzureDevOps, BitbucketCloud, BitbucketDataCenter (Wiz SAST v2)

# Wiz OAuth & API defaults
DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
DEFAULT_API_URL = "https://api.us18.app.wiz.io/graphql"

# ---------- HARD-CODED POLL CONSTANTS ----------
_POLL_INITIAL_BACKOFF_SEC = 10   # wait once before starting to poll
_POLL_INTERVAL_SEC = 10          # wait between attempts
_POLL_TIMEOUT_SEC = 600          # total time budget (10 minutes)

# ---------- Helpers ----------

def iso_now() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def map_sarif_level_to_wiz_severity(level: Optional[str]) -> str:
    """
    SARIF level -> Wiz severity
    SARIF 'level' typically: "none" | "note" | "warning" | "error".
    Wiz SAST v2 allowed severities: "None", "Low", "Medium", "High", "Critical".
    """
    lvl = (level or "").lower()
    if   lvl == "error":   return "High"
    elif lvl == "warning": return "Medium"
    elif lvl == "note":    return "Low"
    elif lvl == "none":    return "None"
    # default if unspecified
    return "Medium"

def normalize_cwe_tags(tags: List[str]) -> List[str]:
    """
    Extract CWE identifiers from SARIF tags like ["CWE-79", "security"] → ["CWE-79"]
    """
    cwes = []
    for t in tags or []:
        t = str(t).strip()
        if t.upper().startswith("CWE-"):
            parts = t.split("-", 1)
            if len(parts) == 2 and parts[1].isdigit():
                cwes.append(f"CWE-{int(parts[1])}")
    return sorted(set(cwes))

def repo_info_from_vcp(vcp: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Extract repository URL, branch and revision from SARIF run.versionControlProvenance[*].
    Returns (repo_url, branch, revision)
    """
    repo_url = vcp.get("repositoryUri") or ""
    branch = vcp.get("branch") or DEFAULT_BRANCH_NAME
    revision = vcp.get("revisionId") or ""
    return repo_url, branch, revision

def guess_vcs_from_repo_url(repo_url: str) -> str:
    host = urlparse(repo_url).hostname or ""
    host_l = host.lower()
    if "github" in host_l:
        return "GitHub"
    if "gitlab" in host_l:
        return "GitLab"
    if "dev.azure.com" in host_l or "visualstudio.com" in host_l:
        return "AzureDevOps"
    if "bitbucket.org" in host_l:
        return "BitbucketCloud"
    # Heuristic for data center/self-hosted Bitbucket:
    if "bitbucket" in host_l:
        return "BitbucketDataCenter"
    return DEFAULT_VCS

def repo_name_from_url(repo_url: str) -> str:
    """
    Convert https://github.com/org/repo(.git)? → org/repo
    """
    p = urlparse(repo_url)
    path = (p.path or "").strip("/")
    if not path:
        return DEFAULT_REPO_NAME
    # remove trailing ".git"
    if path.endswith(".git"):
        path = path[:-4]
    return path

def build_commit_url(repo_url: str, commit_hash: str, vcs: str) -> Optional[str]:
    if not repo_url or not commit_hash:
        return None
    try:
        if vcs == "GitHub":
            return repo_url.rstrip("/") + "/commit/" + commit_hash
        if vcs == "GitLab":
            return repo_url.rstrip("/") + "/-/commit/" + commit_hash
        if vcs == "AzureDevOps":
            # Azure DevOps URLs vary; leaving placeholder
            return None
        if vcs in ["BitbucketCloud", "BitbucketDataCenter"]:
            return repo_url.rstrip("/") + "/commits/" + commit_hash
    except Exception:
        pass
    return None

def deterministic_finding_id(rule_id: str, file_path: str, start_line: Optional[int]) -> str:
    """
    Stable ID so Wiz can track lifecycle (prefer stable IDs over random UUIDs).
    Format: <rule_id>#<sha1(file_path:start_line)>
    """
    basis = f"{rule_id}::{file_path}::{start_line or 0}"
    digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:20]
    return f"{rule_id}##{digest}"

# ---------- Dedup by 'name' (first occurrence wins) ----------

def _name_key(name: Optional[str]) -> str:
    """
    Case-insensitive, trimmed key for deduplication by name.
    """
    return (name or "").strip().lower()

def deduplicate_findings_by_name_asset_level(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Dedup within a single asset (first occurrence wins).
    Returns a new list with duplicates removed.
    Logs each drop at INFO.
    """
    seen = set()
    unique = []
    for f in findings:
        key = _name_key(f.get("name"))
        if key in seen:
            logging.info("Dedup(name, asset): dropping duplicate name=%s", f.get("name"))
            continue
        seen.add(key)
        unique.append(f)
    return unique

def deduplicate_findings_by_name_globally(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dedup across the entire payload (all assets, all data sources).
    First occurrence wins; subsequent duplicates are dropped.
    Logs each drop and a summary.
    """
    seen = set()
    total_before = 0
    total_after = 0
    dropped = 0

    for ds in payload.get("dataSources", []) or []:
        for asset in ds.get("assets", []) or []:
            original = asset.get("sastFindings", []) or []
            total_before += len(original)
            unique = []
            local_dropped = 0
            for f in original:
                key = _name_key(f.get("name"))
                if key in seen:
                    logging.info("Dedup(name, global): dropping duplicate name=%s", f.get("name"))
                    dropped += 1
                    local_dropped += 1
                    continue
                seen.add(key)
                unique.append(f)
            asset["sastFindings"] = unique
            total_after += len(unique)
            if local_dropped:
                logging.info(
                    "Asset dedup summary: before=%d after=%d dropped=%d",
                    len(original), len(unique), local_dropped
                )

    logging.info(
        "Global dedup summary: total_before=%d total_after=%d total_dropped=%d",
        total_before, total_after, dropped
    )
    return payload

# ---------- SARIF → Wiz SAST v2 conversion ----------

def sarif_to_wiz_sast(
    sarif: Dict[str, Any],
    integration_id: str,
    data_source_id: str,
    fallback_repo_url: str,
    fallback_branch: str,
    fallback_vcs: str
) -> Dict[str, Any]:
    """
    Build SAST v2 JSON (Wiz ingestion model)
    """
    assets: List[Dict[str, Any]] = []
    analysis_date = iso_now()

    runs = sarif.get("runs", []) or []
    for run in runs:
        tool = (run.get("tool") or {}).get("driver") or {}
        rules_by_id = {}
        for r in tool.get("rules", []) or []:
            rid = r.get("id")
            if rid:
                rules_by_id[rid] = r

        # Prefer first versionControlProvenance entry
        vcp_list = run.get("versionControlProvenance") or []
        repo_url, branch, revision = (fallback_repo_url, fallback_branch, "")
        if vcp_list:
            repo_url, branch, revision = repo_info_from_vcp(vcp_list[0])

        vcs = guess_vcs_from_repo_url(repo_url) if repo_url else fallback_vcs
        repo_name = repo_name_from_url(repo_url) if repo_url else DEFAULT_REPO_NAME

        # Build findings (raw)
        raw_findings: List[Dict[str, Any]] = []
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id") or "RULE"
            rule = rules_by_id.get(rule_id, {})
            message = (res.get("message") or {}).get("text") or ""

            # First location only (can be extended)
            loc = (res.get("locations") or [{}])[0] or {}
            phys = (loc.get("physicalLocation") or {})
            artifact = (phys.get("artifactLocation") or {})
            file_uri = artifact.get("uri") or artifact.get("uriBaseId") or ""
            region = (phys.get("region") or {})
            start_line = region.get("startLine")
            end_line = region.get("endLine") or start_line
            start_col = region.get("startColumn")
            end_col = region.get("endColumn")

            severity = map_sarif_level_to_wiz_severity(res.get("level"))
            name = (rule.get("shortDescription") or {}).get("text") \
                   or (rule.get("fullDescription") or {}).get("text") \
                   or rule_id

            # Weaknesses (CWE) from rule.properties.tags or result.properties.tags
            #tags = []
            weaknesses = ""
            remediation = ""
            props = rule.get("properties") or {}
            if "cwe" in props:
                weaknesses = normalize_cwe_tags(props["cwe"])
            if "remediation" in props:
                remediation = props["remediation"]
            
           

            # Stable finding ID (Wiz SAST v2 requires id)
            fid = deterministic_finding_id(rule_id, file_uri, start_line)

            finding: Dict[str, Any] = {
                "id": fid,
                "name": name,
                "severity": severity,
                "filePath": file_uri or "App-level Finding",
            }
            if message:
                finding["description"] = message
            if start_line:
                finding["startLine"] = int(start_line)
            if end_line:
                finding["endLine"] = int(end_line)
            if start_col:
                finding["startColumn"] = int(start_col)
            if end_col:
                finding["endColumn"] = int(end_col)
            if weaknesses:
                finding["weaknesses"] = weaknesses
            if remediation:
                finding["remediation"] = remediation
            if revision:
                finding["commitHash"] = revision
                cu = build_commit_url(repo_url, revision, vcs)
                if cu:
                    finding["commitURL"] = cu
            

            raw_findings.append(finding)

        # Dedup (asset-level, first occurrence wins)
        before = len(raw_findings)
        deduped = deduplicate_findings_by_name_asset_level(raw_findings)
        after = len(deduped)
        if before != after:
            logging.info("Asset-level name dedup: before=%d after=%d dropped=%d", before, after, before - after)


        # Build asset
        if len( deduped ) > 0:
            asset: Dict[str, Any] = {
                "analysisDate": analysis_date,
                "details": {
                    "repositoryBranch": {
                        "assetId": DEFAULT_ASSET_ID,
                        "assetName": DEFAULT_ASSET_NAME,
                        "branchName": branch or DEFAULT_BRANCH_NAME,
                        "repository": {
                            "name": repo_name or DEFAULT_REPO_NAME,
                            "url": repo_url or fallback_repo_url or DEFAULT_REPO_URL,
                        },
                        "vcs": vcs or DEFAULT_VCS,
                    }
                },
                "sastFindings": deduped or [
                    # Minimal example finding if SARIF had none (keeps flow testable)
                    {
                        "id": f"PLACEHOLDER##{uuid.uuid4().hex[:12]}",
                        "name": "Placeholder Finding",
                        "severity": "Low",
                        "filePath": "path/to/file.py",
                        "description": "Test placeholder finding",
                        "startLine": 1,
                        "endLine": 1,
                        "weaknesses": ["CWE-89"],
                    }
                ],
            }
            assets.append(asset)

    payload: Dict[str, Any] = {
        "integrationId": integration_id,
        "dataSources": [{
            "id": data_source_id,
            "analysisDate": analysis_date,
            "assets": assets
        }]
    }
    return payload

# ---------- Wiz API calls ----------

def get_wiz_token(auth_url: str, client_id: str, client_secret: str) -> str:
    """
    Client Credentials grant to Wiz auth:
    POST {auth_url}
    Content-Type: application/x-www-form-urlencoded
    body: grant_type=client_credentials&audience=wiz-api&client_id=...&client_secret=...
    """
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials",
        "audience": "wiz-api",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    resp = requests.post(auth_url, headers=headers, data=data, timeout=30)
    if resp.status_code != 200:
        # Try to surface useful error details from JSON if present
        try:
            err = resp.json()
        except Exception:
            err = {"raw": resp.text}
        raise RuntimeError(f"Auth failed: HTTP {resp.status_code} - {err}")
    tok = resp.json().get("access_token")
    if not tok:
        raise RuntimeError(f"Auth succeeded but no access_token: {resp.text}")
    return tok

REQUEST_UPLOAD_QUERY = """
query RequestSecurityScanUpload($filename: String!) {
  requestSecurityScanUpload(filename: $filename) {
    upload { id url systemActivityId }
  }
}
"""

SYSTEM_ACTIVITY_QUERY = """
query SystemActivity($id: ID!) {
  systemActivity(id: $id) {
    id
    status
    statusInfo
    result {
      ... on SystemActivityEnrichmentIntegrationResult {
        dataSources { incoming handled }
        findings { incoming handled }
      }
    }
    context {
      ... on SystemActivityEnrichmentIntegrationContext {
        fileUploadId
      }
    }
  }
}
"""

def gql(api_url: str, token: str, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = {"query": query, "variables": variables}
    resp = requests.post(api_url, headers=headers, json=body, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"GraphQL failed: HTTP {resp.status_code} - {resp.text}")
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL errors: {data['errors']}")
    return data.get("data") or {}

def request_upload_slot(api_url: str, token: str, filename: str) -> Tuple[str, str, str]:
    data = gql(api_url, token, REQUEST_UPLOAD_QUERY, {"filename": filename})
    upload = ((data or {}).get("requestSecurityScanUpload") or {}).get("upload") or {}
    upload_id = upload.get("id")
    url = upload.get("url")
    system_activity_id = upload.get("systemActivityId")
    if not (upload_id and url and system_activity_id):
        raise RuntimeError(f"Invalid upload response: {data}")
    return upload_id, url, system_activity_id

def upload_to_presigned_s3(url: str, content_bytes: bytes) -> None:
    headers = {"Content-Type": "application/json"}
    resp = requests.put(url, headers=headers, data=content_bytes, timeout=120)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"S3 upload failed: HTTP {resp.status_code} - {resp.text}")

def poll_system_activity(api_url: str, token: str, system_activity_id: str) -> Dict[str, Any]:
    """
    Poll SystemActivity until a terminal status or timeout.
    Logs at INFO level every time an attempt fails (NOT_FOUND, errors, exceptions),
    and on each status transition that we observe.
    """
    deadline = time.time() + _POLL_TIMEOUT_SEC
    attempt = 0

    # Initial backoff to allow SystemActivity to become queryable
    logging.info("Polling SystemActivity %s will start after %ss backoff...",
                 system_activity_id, _POLL_INITIAL_BACKOFF_SEC)
    time.sleep(_POLL_INITIAL_BACKOFF_SEC)

    last_status = None
    last_snapshot: Dict[str, Any] = {}

    while time.time() < deadline:
        attempt += 1
        try:
            data = gql(api_url, token, SYSTEM_ACTIVITY_QUERY, {"id": system_activity_id})
        except Exception as e:
            logging.info(
                "Poll attempt %d for SystemActivity %s: GraphQL call failed (%s). "
                "Retrying in %ss...",
                attempt, system_activity_id, e, _POLL_INTERVAL_SEC
            )
            time.sleep(_POLL_INTERVAL_SEC)
            continue

        sa = data.get("systemActivity") or {}
        if not sa:
            logging.info(
                "Poll attempt %d for SystemActivity %s: empty response payload. Retrying in %ss...",
                attempt, system_activity_id, _POLL_INTERVAL_SEC
            )
            time.sleep(_POLL_INTERVAL_SEC)
            continue

        status = (sa.get("status") or "").upper()
        if status and status != last_status:
            logging.info("SystemActivity %s status changed: %s", system_activity_id, status)
            last_status = status

        # If we have ingestion counters, log them occasionally for visibility
        result = sa.get("result") or {}
        ds_stats = (result.get("dataSources") or {})
        f_stats = (result.get("findings") or {})
        if ds_stats or f_stats:
            logging.info(
                "SystemActivity %s stats: dataSources(incoming=%s, handled=%s) "
                "findings(incoming=%s, handled=%s)",
                system_activity_id,
                ds_stats.get("incoming"), ds_stats.get("handled"),
                f_stats.get("incoming"), f_stats.get("handled"),
            )

        # Terminal statuses
        if status in {"SUCCEEDED", "FAILED", "SKIPPED", "COMPLETED", "DONE"}:
            return sa

        last_snapshot = sa
        time.sleep(_POLL_INTERVAL_SEC)

    # Timed out
    logging.info(
        "Polling for SystemActivity %s timed out after %ss. Returning last snapshot.",
        system_activity_id, _POLL_TIMEOUT_SEC
    )
    return last_snapshot

# ---------- CLI ----------

def main():
    parser = argparse.ArgumentParser(description="Convert SARIF to Wiz SAST v2 and upload via Enrichment API.")
    parser.add_argument("--sarif", required=False, help="Path to SARIF file from Quokka (not required when --poll-only is used)")
    parser.add_argument("--quokka-api", required=True, help="Quokka API key")
    parser.add_argument("--client-id", required=True, help="Wiz Client ID")
    parser.add_argument("--client-secret", required=True, help="Wiz Client Secret")
    parser.add_argument("--api-url", default=DEFAULT_API_URL, help="Wiz GraphQL endpoint (e.g., https://api.us18.app.wiz.io/graphql)")
    parser.add_argument("--auth-url", default=DEFAULT_AUTH_URL, help="Wiz Auth URL (e.g., https://auth.app.wiz.io/oauth/token)")
    parser.add_argument("--integration-id", default=DEFAULT_INTEGRATION_ID, help="Wiz integrationId (placeholder ok)")
    parser.add_argument("--data-source-id", default=DEFAULT_DATASOURCE_ID, help="Stable ID for this SAST data source")
    parser.add_argument("--fallback-repo-url", default=DEFAULT_REPO_URL, help="Repository URL placeholder if SARIF lacks VCS info")
    parser.add_argument("--fallback-branch", default=DEFAULT_BRANCH_NAME, help="Branch placeholder if SARIF lacks VCS info")
    parser.add_argument("--fallback-vcs", default=DEFAULT_VCS, help="VCS placeholder if SARIF lacks VCS info")
    parser.add_argument("--out-json", default="wiz_sast_payload.json", help="Write transformed JSON here before upload")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--poll-only", action="store_true",
                        help="Poll SystemActivity by ID only (skips upload & SARIF conversion).")
    parser.add_argument("--convert_only", action="store_true", help="Create SARIF conversion file only (skips upload).")
    parser.add_argument("--system-activity-id",
                        help="SystemActivity ID to poll when using --poll-only.")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(levelname)s: %(message)s")

    # ---- Poll-only fast path (no SARIF needed) ----
    if args.poll_only:
        if not args.system_activity_id:
            raise SystemExit("--poll-only requires --system-activity-id")

        logging.info("Entering poll-only mode. SystemActivity ID: %s", args.system_activity_id)

        # Auth first (token lifetime is typically 24h)
        token = get_wiz_token(args.auth_url, args.client_id, args.client_secret)
        logging.info("Obtained Wiz token for poll-only mode.")

        sa = poll_system_activity(args.api_url, token, args.system_activity_id)
        status = (sa.get("status") or "UNKNOWN")
        logging.info("Poll-only final status for %s: %s", args.system_activity_id, status)
        print(json.dumps(sa, indent=2))
        return
    # ---- end poll-only ----

    # From here on we are in the regular upload flow, so SARIF is required.
    if not args.sarif:
        raise SystemExit("--sarif is required unless --poll-only is used")

    # 1) Load SARIF
    with open(args.sarif, "r", encoding="utf-8") as f:
        sarif = json.load(f)

    # 2) Convert to Wiz SAST v2 JSON (with placeholders for user-defined bits)
    payload = sarif_to_wiz_sast(
        sarif=sarif,
        integration_id=args.integration_id,
        data_source_id=args.data_source_id,
        fallback_repo_url=args.fallback_repo_url,
        fallback_branch=args.fallback_branch,
        fallback_vcs=args.fallback_vcs,
    )

    # >>> NEW: Global dedup across entire payload (one entry per NAME; first wins)
    payload = deduplicate_findings_by_name_globally(payload)

    # Save locally for observability
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    logging.info("Wrote payload: %s", args.out_json)

    # 3) Auth
    if not args.convert_only:
        token = get_wiz_token(args.auth_url, args.client_id, args.client_secret)
        logging.info("Obtained Wiz token.")

        # 4) Request upload slot
        filename = os.path.basename(args.out_json)
        upload_id, presigned_url, system_activity_id = request_upload_slot(args.api_url, token, filename)
        logging.info("Upload slot: id=%s systemActivityId=%s", upload_id, system_activity_id)

        # 5) Upload to presigned S3
        with open(args.out_json, "rb") as f:
            content = f.read()
        upload_to_presigned_s3(presigned_url, content)
        logging.info("Uploaded file to presigned S3 URL.")

        # 6) Poll for ingestion status
        sa = poll_system_activity(args.api_url, token, system_activity_id)
        status = sa.get("status")
        logging.info("Final SystemActivity status: %s", status)
        print(json.dumps(sa, indent=2))


if __name__ == "__main__":
    main()
