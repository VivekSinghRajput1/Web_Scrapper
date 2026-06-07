import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import socket
import re
import json
from datetime import datetime

#configuration

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/137.0 Safari/537.36"
    )
}

TIMEOUT = 15


#URL validation

def validate_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and parsed.netloc


# DNS resolution

def resolve_domain(domain):
    try:
        return socket.gethostbyname_ex(domain)[2]
    except Exception:
        return []


# anti bot detection

def detect_protection(text):
    indicators = [
        "just a moment",
        "cloudflare",
        "checking your browser",
        "attention required",
        "access denied",
        "captcha"
    ]

    text = text.lower()

    return any(i in text for i in indicators)


# IOC extraction

def extract_iocs(text):

    cves = sorted(set(
        re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    ))

    ips = sorted(set(
        re.findall(
            r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)"
            r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b",
            text
        )
    ))

    domains = sorted(set(
        re.findall(
            r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            text
        )
    ))

    emails = sorted(set(
        re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            text
        )
    ))

    return {
        "cves": cves,
        "ips": ips,
        "domains": domains,
        "emails": emails
    }


# for Security headers

def get_security_headers(headers):

    wanted = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    result = {}

    for h in wanted:
        result[h] = headers.get(h)

    return result


# For externam resources

def extract_external_resources(soup, base_domain):

    scripts = set()
    links = set()

    for script in soup.find_all("script", src=True):

        src = script["src"]

        if src.startswith("//"):
            src = "https:" + src

        parsed = urlparse(src)

        if parsed.netloc and base_domain not in parsed.netloc:
            scripts.add(src)

    for a in soup.find_all("a", href=True):

        href = a["href"]

        if href.startswith("//"):
            href = "https:" + href

        parsed = urlparse(href)

        if parsed.netloc and base_domain not in parsed.netloc:
            links.add(href)

    return sorted(scripts), sorted(links)


# main analysis

def analyze_url(url):

    report = {
        "timestamp": str(datetime.utcnow())
    }

    try:

        response = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True
        )

        soup = BeautifulSoup(response.text, "html.parser")

        title = (
            soup.title.get_text(strip=True)
            if soup.title else "No Title"
        )

        text = soup.get_text(" ", strip=True)

        parsed = urlparse(response.url)
        hostname = parsed.hostname

        resolved_ips = resolve_domain(hostname)

        iocs = extract_iocs(text)

        external_scripts, external_links = (
            extract_external_resources(
                soup,
                hostname
            )
        )

        redirects = []

        for r in response.history:
            redirects.append({
                "status": r.status_code,
                "url": r.url
            })

        report.update({

            "target_url": url,

            "final_url": response.url,

            "status_code": response.status_code,

            "title": title,

            "hostname": hostname,

            "resolved_ips": resolved_ips,

            "anti_bot_detected":
                detect_protection(text),

            "server_header":
                response.headers.get("Server"),

            "security_headers":
                get_security_headers(response.headers),

            "redirect_chain":
                redirects,

            "external_scripts":
                external_scripts,

            "external_links":
                external_links,

            "ioc_summary":
                iocs
        })

        return report

    except Exception as e:

        return {
            "error": str(e)
        }


# for saving report

def save_report(report):

    with open(
        "threat_intel_report.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            indent=4
        )


# Main

if __name__ == "__main__":

    url = input("Please, Enter URL: ").strip()

    if not validate_url(url):
        print("Invalid URL")
        exit()

    report = analyze_url(url)

    print(json.dumps(report, indent=4))

    save_report(report)

    print("\nReport saved to threat_intel_report.json")