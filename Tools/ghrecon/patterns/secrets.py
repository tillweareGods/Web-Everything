"""
patterns/secrets.py — Compiled regex patterns for secret detection
All patterns tested against real-world leaks and CVE disclosures.
"""
from __future__ import annotations
import re

ENTROPY_THRESHOLDS = {
    "hex":    3.5,
    "base64": 4.5,
    "alnum":  3.8,
}
MIN_SECRET_LENGTH = 20
MAX_SECRET_LENGTH = 512

# Note: Q = [\x27\x22] = single or double quote character class
_Q  = r'[\x27\x22]'      # matches ' or "
_NQ = r'[^\x27\x22]'     # matches anything except ' or "

RAW_PATTERNS = [
    # ── Cloud: AWS ──────────────────────────────────────────────────────────
    ("AWS Access Key ID",       "CRITICAL",
     r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|ASCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ("AWS ARN",                 "MEDIUM",
     r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[^\s\"']+"),
    # ── Cloud: GCP ──────────────────────────────────────────────────────────
    ("GCP Service Account Key", "CRITICAL",
     r'"type":\s*"service_account"'),
    ("GCP API Key",             "HIGH",
     r"AIza[0-9A-Za-z\-_]{35}"),
    # ── Cloud: Azure ────────────────────────────────────────────────────────
    ("Azure Storage Key",       "CRITICAL",
     r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{88}"),
    ("Azure Connection String", "HIGH",
     r"(?i)endpoint=sb://[a-zA-Z0-9\-\.]+\.servicebus\.windows\.net/"),
    # ── GitHub Tokens ────────────────────────────────────────────────────────
    ("GitHub PAT (fine-grained)", "CRITICAL",
     r"ghp_[a-zA-Z0-9]{36}"),
    ("GitHub OAuth Token",      "CRITICAL",
     r"gho_[a-zA-Z0-9]{36}"),
    ("GitHub App Token",        "CRITICAL",
     r"(ghu_|ghs_)[a-zA-Z0-9]{36}"),
    ("GitHub Refresh Token",    "CRITICAL",
     r"ghr_[a-zA-Z0-9]{76}"),
    # ── Slack ────────────────────────────────────────────────────────────────
    ("Slack Bot Token",         "HIGH",
     r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}"),
    ("Slack User Token",        "HIGH",
     r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{12}-[0-9a-f]{32}"),
    ("Slack Webhook URL",       "HIGH",
     r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    # ── Stripe ──────────────────────────────────────────────────────────────
    ("Stripe Secret Key",       "CRITICAL",
     r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Restricted Key",   "HIGH",
     r"rk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable Key",  "LOW",
     r"pk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Test Key",         "LOW",
     r"(sk|pk|rk)_test_[0-9a-zA-Z]{24,}"),
    # ── Messaging ───────────────────────────────────────────────────────────
    ("Twilio Account SID",      "HIGH",
     r"AC[a-z0-9]{32}"),
    ("SendGrid API Key",        "HIGH",
     r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"),
    ("Mailgun API Key",         "HIGH",
     r"key-[0-9a-zA-Z]{32}"),
    ("Mailchimp API Key",       "HIGH",
     r"[0-9a-f]{32}-us[0-9]{1,2}"),
    # ── AI / LLM ────────────────────────────────────────────────────────────
    ("OpenAI API Key",          "HIGH",
     r"sk-[a-zA-Z0-9]{48}"),
    ("Anthropic API Key",       "HIGH",
     r"sk-ant-[a-zA-Z0-9\-_]{95,}"),
    ("HuggingFace Token",       "HIGH",
     r"hf_[a-zA-Z0-9]{37,}"),
    # ── Private Keys ────────────────────────────────────────────────────────
    ("RSA/EC Private Key",      "CRITICAL",
     r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY( BLOCK)?-----"),
    ("PGP Private Key",         "CRITICAL",
     r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    # ── Database URIs ────────────────────────────────────────────────────────
    ("MongoDB URI",             "CRITICAL",
     r"mongodb(\+srv)?://[^:@\s]+:[^@\s]+@[^\s\"']+"),
    ("PostgreSQL DSN",          "CRITICAL",
     r"postgres(ql)?://[^:@\s]+:[^@\s]+@[^\s\"']+"),
    ("MySQL DSN",               "CRITICAL",
     r"mysql://[^:@\s]+:[^@\s]+@[^\s\"']+"),
    ("Redis URI with password", "HIGH",
     r"redis://:[^@\s]+@[^\s\"']+"),
    # ── JWT ─────────────────────────────────────────────────────────────────
    ("JSON Web Token",          "MEDIUM",
     r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
    # ── Bearer header ────────────────────────────────────────────────────────
    ("Bearer Token in header",  "HIGH",
     r"(?i)Authorization:\s*Bearer\s+([a-zA-Z0-9\-_\.]+)"),
    # ── Cloud metadata ───────────────────────────────────────────────────────
    ("AWS Metadata URL",        "MEDIUM",
     r"169\.254\.169\.254"),
    # ── Sensitive file contents ──────────────────────────────────────────────
    ("NPM auth token",          "HIGH",
     r"(?i)//registry\.npmjs\.org/:_authToken\s*=\s*[a-zA-Z0-9\-_\.]{20,}"),
    ("PyPI token",              "HIGH",
     r"pypi-[A-Za-z0-9\-_]{20,}"),
    ("Vault token",             "CRITICAL",
     r"s\.[a-zA-Z0-9]{24}"),
    # ── Webhooks ────────────────────────────────────────────────────────────
    ("Discord Webhook",         "HIGH",
     r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"),
    ("Telegram Bot Token",      "HIGH",
     r"[0-9]{8,10}:[a-zA-Z0-9_\-]{35}"),
]

# Build and compile patterns (also includes quote-containing patterns added at runtime)
def _p(name, severity, pattern):
    return {"name": name, "severity": severity, "regex": re.compile(pattern, re.MULTILINE)}

COMPILED_PATTERNS = []
for name, severity, pattern in RAW_PATTERNS:
    try:
        COMPILED_PATTERNS.append({"name": name, "severity": severity,
                                   "regex": re.compile(pattern, re.MULTILINE)})
    except re.error:
        pass

# Add quote-containing patterns using string formatting to avoid Python parser issues
_QUOTE_PATTERNS = [
    ("AWS Secret Access Key",   "CRITICAL",
     r"(?i)aws.{0,20}secret.{0,20}" + _Q + r"[0-9a-zA-Z/+]{40}" + _Q),
    ("GCP OAuth Client Secret", "HIGH",
     r"(?i)client.secret.{0,10}" + _Q + r"[A-Za-z0-9\-_]{24,}" + _Q),
    ("Azure Client Secret",     "CRITICAL",
     r"(?i)(azure|az).{0,20}(client.?secret|password).{0,10}" + _Q + r"[a-zA-Z0-9~_\-\.]{34,}" + _Q),
    ("GitHub Classic PAT",      "HIGH",
     r"(?i)(github|gh).{0,20}token.{0,10}" + _Q + r"[0-9a-f]{40}" + _Q),
    ("Heroku API Key",          "HIGH",
     r"(?i)heroku.{0,20}" + _Q + r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" + _Q),
    ("Generic API Key",         "MEDIUM",
     r"(?i)(api[_-]?key|api[_-]?secret|app[_-]?secret|secret[_-]?key)\s*[=:]\s*" + _Q + r"([a-zA-Z0-9\-_\.]{20,80})" + _Q),
    ("Generic Password",        "MEDIUM",
     r"(?i)(password|passwd|pwd)\s*[=:]\s*" + _Q + _NQ + r"{8,80}" + _Q),
    ("Generic Token",           "MEDIUM",
     r"(?i)(token|auth[_-]?token|access[_-]?token)\s*[=:]\s*" + _Q + r"([a-zA-Z0-9\-_\.]{20,80})" + _Q),
    ("SSH Passphrase",          "HIGH",
     r"(?i)passphrase\s*[=:]\s*" + _Q + _NQ + r"{6,}" + _Q),
    ("SMTP credentials",        "HIGH",
     r"(?i)(smtp|email).{0,20}(password|pass|pwd).{0,10}" + _Q + _NQ + r"{6,}" + _Q),
    ("Atlassian API Token",     "HIGH",
     r"(?i)atlassian.{0,20}" + _Q + r"[a-zA-Z0-9]{24}" + _Q),
]

for name, severity, pattern in _QUOTE_PATTERNS:
    try:
        COMPILED_PATTERNS.append({"name": name, "severity": severity,
                                   "regex": re.compile(pattern, re.MULTILINE)})
    except re.error:
        pass

# High-value files
HIGH_VALUE_FILES = {
    ".env", ".env.local", ".env.prod", ".env.production", ".env.staging",
    ".npmrc", ".pypirc", ".netrc", ".htpasswd", ".htaccess",
    "config.json", "config.yaml", "config.yml", "settings.py",
    "secrets.yaml", "secrets.yml", "secrets.json",
    "credentials", "credentials.json", "credentials.yaml",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "terraform.tfvars",
    "docker-compose.yml", "docker-compose.yaml",
    "Dockerfile",
}

BOOST_KEYWORDS = [
    "secret", "private", "credential", "password", "passwd", "token",
    "api_key", "apikey", "access_key", "auth", "prod", "production", "live",
]

PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)(your[_-]?api[_-]?key|example|placeholder|changeme|replace[_-]?me|"
    r"<[^>]+>|\$\{[^}]+\}|xxx+|your[_-]?secret|insert[_-]?here|todo|"
    r"test[_-]?key|dummy|fake|sample|aaaa+|bbbb+|1234+|0000+)"
)

BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
