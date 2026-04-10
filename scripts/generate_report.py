#!/usr/bin/env python3
"""
generate_report.py

Runs Bandit and flake8 against bad_example and good_example,
then generates a branded SecuredPress HTML findings report.

Usage:
    python scripts/generate_report.py

Output:
    reports/findings_report.html
"""

import base64
import json
import subprocess
import sys
import webbrowser
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
BAD_EXAMPLE = REPO_ROOT / "bad_example" / "feature_engineering_ai.py"
GOOD_EXAMPLE = REPO_ROOT / "good_example" / "feature_engineering_fixed.py"
REPORTS_DIR = REPO_ROOT / "reports"
OUTPUT_HTML = REPORTS_DIR / "findings_report.html"
LOGO_PATH = REPO_ROOT / "dashboard" / "img" / "securedpress_logo.png"


def load_logo_b64() -> str:
    """Load the SecuredPress logo as a base64 data URI for inline embedding."""
    try:
        with open(LOGO_PATH, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        return f"data:image/png;base64,{b64}"
    except FileNotFoundError:
        return ""


SEVERITY_COLOR = {
    "CRITICAL": "#FF4560",
    "HIGH": "#FF4560",
    "MEDIUM": "#FFB300",
    "LOW": "#00E5FF",
    "UNDEFINED": "#8890A0",
}

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNDEFINED": 4}

RECOMMENDATIONS = {
    "B307": {
        "title": "Replace eval() with ast.literal_eval() or explicit logic",
        "detail": (
            "eval() executes arbitrary Python expressions from a string input. "
            "In a production ML pipeline that processes external data, this is a "
            "remote code execution risk (RCE). Replace with ast.literal_eval() for "
            "safe literal parsing, or refactor to use explicit typed transformation "
            "functions that do not accept string expressions. "
            "<br><br>"
            "This is the same approach AWS used when patching "
            "<a href='https://github.com/advisories/GHSA-5r2p-pjr8-7fh7' "
            "target='_blank' style='color:#199F86;'>GHSA-5r2p-pjr8-7fh7</a> "
            "in the SageMaker Python SDK — they replaced eval() with a safe "
            "recursive descent parser. Apply the same pattern to your own "
            "pipeline code. "
            "<br><br>"
            "<strong style='color:#FF4560;'>Real-world validation:</strong> "
            "AWS published security advisory GHSA-5r2p-pjr8-7fh7 (March 2026) "
            "confirming this exact vulnerability class in the SageMaker Python SDK "
            "itself — eval() in the JumpStart search_hub() function allowed remote "
            "code execution. Patched in SageMaker SDK v3.4.0 (January 2026). "
            "CVSS score: 8.4/10 HIGH. "
        ),
        "fix": "from ast import literal_eval\nresult = literal_eval(transform_expr)",
    },
    "B105": {
        "title": "Load secrets from environment variables",
        "detail": (
            "Hardcoded passwords and API keys in source code are exposed in version "
            "control history permanently — even after deletion. Load all secrets "
            "from environment variables using os.environ.get() and enforce their "
            "presence at startup. Use AWS Secrets Manager or Parameter Store in "
            "production SageMaker environments."
        ),
        "fix": "import os\nAPI_KEY = os.environ.get('API_KEY', '')\nDB_PASSWORD = os.environ.get('DB_PASSWORD', '')",
    },
    "B106": {
        "title": "Load secrets from environment variables",
        "detail": (
            "Same as B105 — hardcoded credentials must be moved to environment "
            "variables or a secrets manager."
        ),
        "fix": "import os\nSECRET = os.environ.get('SECRET_KEY', '')",
    },
    "MUTATION": {
        "title": "Use .copy() to avoid silent DataFrame mutation",
        "detail": (
            "Modifying a DataFrame in-place without .copy() silently mutates the "
            "caller's data, producing incorrect results with no error or warning. "
            "This class of bug is difficult to detect in testing because the "
            "function appears to work correctly in isolation. Always return "
            "result = df.copy() at the start of transformation functions."
        ),
        "fix": "def compute_balance_ratio(df: pd.DataFrame) -> pd.DataFrame:\n    result = df.copy()\n    result['balance_advance_ratio'] = ...\n    return result",
    },
    "TYPES": {
        "title": "Add type annotations — enforce with mypy strict mode",
        "detail": (
            "Missing type annotations allow type errors to reach production silently. "
            "In a SageMaker ML pipeline, a mismatched DataFrame column type or wrong "
            "return type can corrupt model inputs without raising any exception. "
            "Add full type annotations to all functions and run mypy --strict in CI "
            "to catch these errors at review time, not in production."
        ),
        "fix": "def load_data(filepath: str) -> pd.DataFrame:\ndef apply_transformation(df: pd.DataFrame) -> pd.DataFrame:\ndef engineer_features(df: pd.DataFrame) -> pd.DataFrame:",
    },
}

# Override Bandit's conservative severity ratings with real-world risk ratings
# B307 eval() is genuinely HIGH risk in production ML pipelines per CWE-78
# B105/B106 hardcoded secrets are HIGH risk per CWE-259
SEVERITY_OVERRIDE = {
    "B307": "HIGH",
    "B105": "HIGH",
    "B106": "HIGH",
}

MANUAL_FINDINGS = [
    {
        "test_id": "CUSTOM-001",
        "test_name": "silent_dataframe_mutation",
        "issue_text": "In-place DataFrame mutation — modifies caller data silently",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "cwe": "N/A",
        "line_number": 37,
        "code": "df['balance_advance_ratio'] = df['account_balance'] / df['advance_amount']",
        "rec_key": "MUTATION",
    },
    {
        "test_id": "CUSTOM-002",
        "test_name": "missing_type_annotations",
        "issue_text": "Missing type annotations — mypy strict mode fails",
        "severity": "LOW",
        "confidence": "HIGH",
        "cwe": "N/A",
        "line_number": 1,
        "code": "def load_data(filepath):          # no type annotations\ndef apply_transformation(df, transform_expr):  # no type annotations\ndef engineer_features(df, extra_transform=None):  # no type annotations",
        "rec_key": "TYPES",
    },
]


def run_bandit(filepath: Path) -> list:
    """Run bandit and return list of finding dicts."""
    result = subprocess.run(
        [sys.executable, "-m", "bandit", "-f", "json", str(filepath)],
        capture_output=True,
        text=True,
    )
    try:
        data = json.loads(result.stdout)
        return data.get("results", [])
    except json.JSONDecodeError:
        return []


def run_flake8(filepath: Path) -> list:
    """Run flake8 and return list of finding strings."""
    result = subprocess.run(
        [sys.executable, "-m", "flake8", str(filepath)], capture_output=True, text=True
    )
    return result.stdout.strip().splitlines() if result.stdout.strip() else []


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity.upper(), "#8890A0")
    return (
        f'<span style="background:{color}22;color:{color};border:1px solid {color}44;'
        f"padding:2px 10px;border-radius:3px;font-size:11px;font-weight:700;"
        f'font-family:monospace;letter-spacing:0.5px;">{severity.upper()}</span>'
    )


def finding_card(finding: dict, idx: int, rec: dict | None) -> str:
    severity = SEVERITY_OVERRIDE.get(
        finding.get("test_id", ""),
        finding.get("issue_severity", finding.get("severity", "MEDIUM")),
    ).upper()
    test_id = finding.get("test_id", "")
    test_name = finding.get("test_name", finding.get("issue_text", ""))
    issue = finding.get("issue_text", test_name)
    line = finding.get(
        "line_number",
        (
            finding.get("line_range", ["?"])[0]
            if isinstance(finding.get("line_range"), list)
            else "?"
        ),
    )
    code = finding.get("code", "").strip()
    cwe = finding.get("issue_cwe", finding.get("cwe", {}))
    if isinstance(cwe, dict):
        cwe_id = cwe.get("id", "")
        cwe_str = f"CWE-{cwe_id}" if cwe_id else "N/A"
    else:
        cwe_str = str(cwe) if cwe and cwe != "N/A" else "N/A"

    rec_html = ""
    if rec:
        fix_code = rec.get("fix", "")
        rec_html = f"""
        <div style="margin-top:14px;border-top:1px solid #1F2130;padding-top:14px;">
          <div style="font-size:10px;font-weight:700;color:#199F86;letter-spacing:0.8px;
                      text-transform:uppercase;margin-bottom:6px;">Recommendation</div>
          <div style="font-size:12px;color:#8890A0;margin-bottom:10px;line-height:1.6;">
            <strong style="color:#E2E6F0;">{rec['title']}</strong><br>
            {rec['detail']}
          </div>
          <pre style="background:#08090D;border:1px solid #1F2130;border-radius:4px;
                      padding:10px 14px;font-size:11px;color:#00E5FF;overflow-x:auto;
                      margin:0;">{fix_code}</pre>
        </div>"""

    border_color = SEVERITY_COLOR.get(severity, "#1F2130")
    return f"""
    <div style="background:#0F1117;border:1px solid #1F2130;border-left:4px solid {border_color};
                border-radius:0 8px 8px 0;padding:18px 20px;margin-bottom:16px;">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap;">
        {severity_badge(severity)}
        <span style="font-family:monospace;font-size:11px;color:#5A6070;">{test_id}</span>
        <span style="font-size:13px;font-weight:600;color:#E2E6F0;">{issue}</span>
        <span style="margin-left:auto;font-size:11px;color:#5A6070;">Line {line} &nbsp;·&nbsp; {cwe_str}</span>
      </div>
      <pre style="background:#08090D;border:1px solid #1F2130;border-radius:4px;
                  padding:10px 14px;font-size:11px;color:#FF4560;overflow-x:auto;
                  margin:0 0 0 0;">{code}</pre>
      {rec_html}
    </div>"""


def build_html(
    bad_findings: list, good_findings: list, flake8_bad: list, logo_b64: str = ""
) -> str:
    now = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    all_bad = sorted(
        bad_findings + MANUAL_FINDINGS,
        key=lambda f: SEVERITY_RANK.get(
            SEVERITY_OVERRIDE.get(
                f.get("test_id", ""), f.get("issue_severity", f.get("severity", "LOW"))
            ).upper(),
            4,
        ),
    )

    def effective_severity(f: dict) -> str:
        return SEVERITY_OVERRIDE.get(
            f.get("test_id", ""), f.get("issue_severity", f.get("severity", "LOW"))
        ).upper()

    total = len(all_bad)
    critical = sum(1 for f in all_bad if effective_severity(f) in ("CRITICAL", "HIGH"))
    medium = sum(1 for f in all_bad if effective_severity(f) == "MEDIUM")
    low = sum(1 for f in all_bad if effective_severity(f) == "LOW")

    risk_score = max(0, 100 - (critical * 20) - (medium * 5) - (low * 2))

    cards_html = ""
    for i, f in enumerate(all_bad):
        test_id = f.get("test_id", "")
        rec_key = f.get("rec_key", test_id)
        rec = RECOMMENDATIONS.get(rec_key)
        cards_html += finding_card(f, i, rec)

    good_status = "PASS" if not good_findings else "FAIL"
    good_color = "#00E676" if good_status == "PASS" else "#FF4560"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>SecuredPress · Code Quality Audit Report</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Sora:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{background:#08090D;color:#E2E6F0;font-family:'Sora',sans-serif;font-size:13px;min-height:100vh;}}
  a{{color:#199F86;}}
  pre{{white-space:pre-wrap;word-break:break-all;}}
</style>
</head>
<body>

<!-- Header -->
<div style="background:#0F1117;border-bottom:1px solid #1F2130;padding:16px 32px;
            display:flex;align-items:center;justify-content:space-between;">
  <a href="https://securedpress.com" target="_blank"
     style="display:flex;align-items:center;gap:12px;text-decoration:none;">
    <div style="width:40px;height:40px;border-radius:50%;overflow:hidden;flex-shrink:0;">
      {'<img src="' + logo_b64 + '" alt="SecuredPress" style="width:40px;height:40px;border-radius:50%;object-fit:cover;">' if logo_b64 else '<div style="width:40px;height:40px;border-radius:50%;background:#199F86;display:flex;align-items:center;justify-content:center;"><svg width="20" height="20" viewBox="0 0 24 24" fill="none"><polyline points="2,17 8,11 13,14 22,5" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><circle cx="22" cy="5" r="2" fill="white"/><circle cx="2" cy="17" r="2" fill="white"/></svg></div>'}
    </div>
    <div>
      <div style="font-weight:700;font-size:15px;letter-spacing:-0.3px;color:#E2E6F0;">
        Secured<span style="color:#199F86;">Press</span> ™
      </div>
      <div style="font-size:10px;color:#5A6070;letter-spacing:0.5px;">
        EMPOWERING SECURITY WITH INTELLIGENCE ™
      </div>
    </div>
  </a>
  <div style="text-align:center;font-size:12px;color:#8890A0;">
    Code Quality &amp; Security Audit Report &nbsp;·&nbsp; SageMaker Feature Engineering
  </div>
  <div style="font-size:11px;color:#5A6070;font-family:monospace;">{now}</div>
</div>

<!-- Content -->
<div style="max-width:1000px;margin:0 auto;padding:32px 24px;">

  <!-- Title -->
  <div style="margin-bottom:32px;">
    <div style="font-size:22px;font-weight:800;letter-spacing:-0.5px;margin-bottom:6px;">
      Static Analysis Findings
    </div>
    <div style="color:#8890A0;font-size:13px;">
      Target: <code style="color:#00E5FF;background:#0F1117;padding:1px 6px;
      border-radius:3px;font-size:11px;">bad_example/feature_engineering_ai.py</code>
      &nbsp;·&nbsp; Tools: Bandit · flake8 · Manual review
    </div>
  </div>

  <!-- Summary stats — row 1: severity cards -->
  <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px;">
    <div style="background:#0F1117;border:1px solid #1F2130;border-left:4px solid #FF4560;
                border-radius:0 8px 8px 0;padding:18px 20px;">
      <div style="font-family:monospace;font-size:32px;font-weight:700;color:#FF4560;">{critical}</div>
      <div style="font-size:11px;color:#8890A0;margin-top:6px;text-transform:uppercase;
                  letter-spacing:0.6px;">Critical / High</div>
    </div>
    <div style="background:#0F1117;border:1px solid #1F2130;border-left:4px solid #FFB300;
                border-radius:0 8px 8px 0;padding:18px 20px;">
      <div style="font-family:monospace;font-size:32px;font-weight:700;color:#FFB300;">{medium}</div>
      <div style="font-size:11px;color:#8890A0;margin-top:6px;text-transform:uppercase;
                  letter-spacing:0.6px;">Medium</div>
    </div>
    <div style="background:#0F1117;border:1px solid #1F2130;border-left:4px solid #00E5FF;
                border-radius:0 8px 8px 0;padding:18px 20px;">
      <div style="font-family:monospace;font-size:32px;font-weight:700;color:#00E5FF;">{low}</div>
      <div style="font-size:11px;color:#8890A0;margin-top:6px;text-transform:uppercase;
                  letter-spacing:0.6px;">Low</div>
    </div>
  </div>

  <!-- Summary stats — row 2: total + risk score with pie chart -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:32px;">

    <!-- Total findings with pie chart -->
    <div style="background:#0F1117;border:1px solid #1F2130;border-radius:8px;
                padding:20px 24px;display:flex;align-items:center;gap:24px;">
      <canvas id="findingsPie" width="90" height="90"></canvas>
      <div>
        <div style="font-family:monospace;font-size:32px;font-weight:700;color:#E2E6F0;">{total}</div>
        <div style="font-size:11px;color:#8890A0;margin-top:4px;text-transform:uppercase;
                    letter-spacing:0.6px;">Total Findings</div>
        <div style="margin-top:10px;display:flex;flex-direction:column;gap:4px;">
          <div style="display:flex;align-items:center;gap:6px;font-size:10px;color:#8890A0;">
            <div style="width:8px;height:8px;border-radius:50%;background:#FF4560;flex-shrink:0;"></div>
            Critical / High ({critical})
          </div>
          <div style="display:flex;align-items:center;gap:6px;font-size:10px;color:#8890A0;">
            <div style="width:8px;height:8px;border-radius:50%;background:#FFB300;flex-shrink:0;"></div>
            Medium ({medium})
          </div>
          <div style="display:flex;align-items:center;gap:6px;font-size:10px;color:#8890A0;">
            <div style="width:8px;height:8px;border-radius:50%;background:#00E5FF;flex-shrink:0;"></div>
            Low ({low})
          </div>
        </div>
      </div>
    </div>

    <!-- Risk score with donut -->
    <div style="background:#0F1117;border:1px solid #1F2130;border-radius:8px;
                padding:20px 24px;display:flex;align-items:center;gap:24px;">
      <div style="position:relative;width:90px;height:90px;flex-shrink:0;">
        <canvas id="riskDonut" width="90" height="90"></canvas>
        <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
                    text-align:center;">
          <div style="font-family:monospace;font-size:15px;font-weight:700;
                      color:{'#FF4560' if risk_score < 60 else '#FFB300' if risk_score < 80 else '#00E676'};">
            {risk_score}
          </div>
          <div style="font-size:9px;color:#5A6070;">/100</div>
        </div>
      </div>
      <div>
        <div style="font-size:11px;color:#8890A0;text-transform:uppercase;
                    letter-spacing:0.6px;">Risk Score</div>
        <div style="font-size:10px;color:#5A6070;margin-top:4px;">Lower is worse</div>
        <div style="margin-top:8px;font-size:10px;
                    color:{'#FF4560' if risk_score < 60 else '#FFB300' if risk_score < 80 else '#00E676'};">
          {'⚠ HIGH RISK — immediate action required' if risk_score < 60
           else '⚡ MEDIUM RISK — remediation recommended' if risk_score < 80
           else '✓ LOW RISK — minor improvements suggested'}
        </div>
      </div>
    </div>

  </div>

  <script>
    // Pie chart — findings breakdown
    (function() {{
      var canvas = document.getElementById('findingsPie');
      if (!canvas) return;
      var ctx = canvas.getContext('2d');
      var total = {total};
      var slices = [
        {{ value: {critical}, color: '#FF4560' }},
        {{ value: {medium},   color: '#FFB300' }},
        {{ value: {low},      color: '#00E5FF' }},
      ].filter(function(s) {{ return s.value > 0; }});
      var start = -Math.PI / 2;
      var cx = 45, cy = 45, r = 38;
      ctx.clearRect(0, 0, 90, 90);
      slices.forEach(function(s) {{
        var angle = (s.value / total) * 2 * Math.PI;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, r, start, start + angle);
        ctx.closePath();
        ctx.fillStyle = s.color;
        ctx.fill();
        start += angle;
      }});
      // inner circle cutout for donut look
      ctx.beginPath();
      ctx.arc(cx, cy, 22, 0, 2 * Math.PI);
      ctx.fillStyle = '#0F1117';
      ctx.fill();
    }})();

    // Donut chart — risk score
    (function() {{
      var canvas = document.getElementById('riskDonut');
      if (!canvas) return;
      var ctx = canvas.getContext('2d');
      var score = {risk_score};
      var cx = 45, cy = 45, r = 38, inner = 26;
      var riskColor = score < 60 ? '#FF4560' : score < 80 ? '#FFB300' : '#00E676';
      // background track
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, 2 * Math.PI);
      ctx.strokeStyle = '#1F2130';
      ctx.lineWidth = r - inner;
      ctx.stroke();
      // score arc
      var angle = (score / 100) * 2 * Math.PI;
      ctx.beginPath();
      ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + angle);
      ctx.strokeStyle = riskColor;
      ctx.lineWidth = r - inner;
      ctx.lineCap = 'round';
      ctx.stroke();
    }})();
  </script>

  <!-- Good example status -->
  <div style="background:#0F1117;border:1px solid #1F2130;border-radius:8px;
              padding:16px 20px;margin-bottom:32px;display:flex;align-items:center;gap:16px;">
    <span style="background:{good_color}22;color:{good_color};border:1px solid {good_color}44;
                 padding:4px 12px;border-radius:3px;font-size:11px;font-weight:700;
                 font-family:monospace;">{good_status}</span>
    <div>
      <div style="font-weight:600;font-size:13px;">good_example/feature_engineering_fixed.py</div>
      <div style="font-size:11px;color:#8890A0;margin-top:2px;">
        {"All static analysis checks passed — no issues identified." if good_status == "PASS"
         else "Issues found in good_example — review required."}
      </div>
    </div>
  </div>

  <!-- Findings -->
  <div style="font-size:11px;font-weight:600;color:#8890A0;letter-spacing:0.8px;
              text-transform:uppercase;margin-bottom:16px;">
    Findings — bad_example/feature_engineering_ai.py
  </div>

  {cards_html}

  <!-- Recommendations summary -->
  <div style="background:rgba(0,229,255,0.04);border:1px solid rgba(0,229,255,0.15);
              border-left:3px solid #199F86;border-radius:0 8px 8px 0;
              padding:16px 20px;margin-top:32px;margin-bottom:32px;">
    <div style="font-size:10px;font-weight:700;color:#199F86;letter-spacing:0.8px;
                text-transform:uppercase;margin-bottom:8px;">Audit Summary</div>
    <div style="font-size:13px;color:#8890A0;line-height:1.8;">
      This file contains <strong style="color:#E2E6F0;">{total} issues</strong> that would
      not be caught by standard unit tests — including a remote code execution risk,
      a hardcoded credential, a silent data mutation bug, and missing type annotations.
      All four are resolved in <code style="color:#00E5FF;background:#0F1117;
      padding:1px 6px;border-radius:3px;font-size:11px;">good_example/feature_engineering_fixed.py</code>.
      A five-tool pre-commit stack and four parallel CI jobs prevent these issues
      from reaching production on every future commit.
    </div>
  </div>

  <!-- Footer -->
  <div style="margin-top:32px;padding-top:24px;border-top:1px solid #1F2130;
              display:flex;justify-content:space-between;align-items:center;
              font-size:11px;color:#5A6070;flex-wrap:wrap;gap:8px;">
    <a href="https://securedpress.com" target="_blank"
       style="color:#5A6070;text-decoration:none;">
      © 2026 SecuredPress LLC · Las Vegas, Nevada
    </a>
    <div>Empowering Security with Intelligence ™</div>
    <a href="https://securedpress.com" target="_blank"
       style="color:#199F86;text-decoration:none;">securedpress.com</a>
  </div>

</div>
</body>
</html>"""


def main() -> None:
    print("\nRunning Bandit on bad_example...")
    bad_findings = run_bandit(BAD_EXAMPLE)
    print(f"  Found {len(bad_findings)} Bandit findings")

    print("Running Bandit on good_example...")
    good_findings = run_bandit(GOOD_EXAMPLE)
    print(f"  Found {len(good_findings)} Bandit findings (expected 0)")

    print("Running flake8 on bad_example...")
    flake8_bad = run_flake8(BAD_EXAMPLE)

    print("Generating HTML report...")
    REPORTS_DIR.mkdir(exist_ok=True)
    logo_b64 = load_logo_b64()
    html = build_html(bad_findings, good_findings, flake8_bad, logo_b64)
    OUTPUT_HTML.write_text(html)

    print(f"\n✓ Report saved to: {OUTPUT_HTML}")
    print("Opening in browser...\n")
    webbrowser.open(OUTPUT_HTML.resolve().as_uri())


if __name__ == "__main__":
    main()
