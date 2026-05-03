# =============================================================================
# ms_update_scanner.py
#
# Purpose:
#   Scans multiple Microsoft-related RSS feeds and community blogs on a weekly
#   schedule, filters articles by topic categories relevant to a Windows-heavy
#   IT environment, and emails a categorized summary to the configured address.
#
# Designed to run as a PythonAnywhere scheduled task (weekly, Monday).
#
# Dependencies:
#   pip install feedparser
#
# Setup:
#   1. Set SENDER_EMAIL and RECEIVER_EMAIL below.
#   2. Set SENDER_PASSWORD to a Gmail App Password (NOT your account password).
#      Generate one at: myaccount.google.com -> Security -> App Passwords
#   3. Upload to PythonAnywhere and create a weekly Scheduled Task pointing here.
# =============================================================================

import feedparser        # Parses RSS/Atom XML feeds into Python objects
import smtplib           # Handles SMTP connection for sending email
import ssl               # Provides TLS/SSL context for secure email delivery
from email.message import EmailMessage  # Constructs well-formed email messages
from datetime import datetime           # Used to timestamp the email subject/body

# Credentials live in config.py, which is excluded from version control via
# .gitignore. On PythonAnywhere, create config.py manually in the same folder.
from config import SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD, RECEIVER_EMAIL


# =============================================================================
# CONFIGURATION — Edit these values before deploying
# =============================================================================

# --- RSS Feed Sources ---
# Each entry is a human-readable label mapped to a feed URL.
# feedparser handles RSS 2.0, Atom, and most XML feed variants.
#
# Feed notes:
#   - MSRC (Microsoft Security Response Center): official CVE/patch announcements
#   - M365 Roadmap: upcoming feature changes and rollouts for Microsoft 365
#   - Windows IT Pro Blog: operational guidance, policy changes, and update behavior
#   - M365 Tech Community: broader Microsoft 365 product announcements
#   - AskWoody: Susan Bradley's site — focuses specifically on update problems,
#               regressions, and "should I install this yet?" analysis
#   - Chris Titus Tech: Windows/Linux sysadmin blog covering real-world impact
#                       of OS changes, driver issues, and tooling
FEEDS = {
    "Security Patches (MSRC)":  "https://api.msrc.microsoft.com/update-guide/rss",
    "M365 Roadmap":              "https://www.microsoft.com/releasecommunications/api/v2/m365/rss",
    "Windows IT Pro Blog":       "https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=Windows-ITPro-blog",
    "M365 Tech Community Blog":  "https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=microsoft_365blog",
    "AskWoody (Update Issues)":  "https://www.askwoody.com/feed/",
    "Chris Titus Tech":          "https://christitus.com/index.xml",
}

# --- Filter Categories ---
# Articles are matched against these keyword lists.
# Matching is case-insensitive and checks both the article title and summary.
# An article can appear under multiple categories if it matches more than one.
# To add a new category, add a new key with a list of keyword strings.
CATEGORIES = {

    # Catches updates that may break older 32-bit software running under WOW64
    # (the Windows-on-Windows 64-bit compatibility layer).
    "32-Bit / Legacy App Impact": [
        "32-bit", "32bit", "x86 application", "WOW64", "legacy application",
        "legacy app", "32-bit support", "32-bit compatibility",
    ],

    # Specifically targets Microsoft Access — avoids false positives from the
    # generic word "access" appearing in unrelated security articles.
    # "access 20" catches versioned names like "Access 2016", "Access 2019", etc.
    "MS Access": [
        "microsoft access", "ms access", "access database", "access runtime",
        "accdb", ".accdb", "access 20",
    ],

    # Targets Windows print subsystem changes that could affect Okidata or Epson
    # printers. Intentionally excludes the bare word "printer" to reduce noise
    # from unrelated hardware articles.
    "Printer Impact (Okidata / Epson)": [
        "okidata", "oki data", "epson", "print driver", "print spooler",
        "spoolsv", "printer driver", "windows printing",
    ],

    # Covers email infrastructure security — important for monitoring changes to
    # Exchange Online, Outlook behavior, and authentication standards (SPF/DKIM/DMARC)
    # that could affect mail delivery or flag outbound messages as spam.
    "Email Security": [
        "exchange", "outlook", "smtp", "email security", "spf", "dkim",
        "dmarc", "phishing", "spoofing", "anti-spam", "antispam",
        "mail flow", "transport rule", "email authentication",
    ],

    # Monitors SMB protocol changes, share authentication shifts, and anything
    # that could break mapped drives or UNC path access after a Windows update.
    "Network Shares / SMB": [
        "smb", "network share", "file share", "cifs", "mapped drive",
        "network drive", "unc path", "net use", "server message block",
        "lanman", "smb signing", "smb encryption",
    ],

    # Catches forward-looking warnings: features being retired, behaviors changing,
    # known regressions introduced by updates, and anything requiring a workaround.
    # This category is feed-agnostic — it applies across all sources above.
    "Deprecations / EOL / Breaking Changes": [
        "deprecated", "deprecation", "end of life", "end-of-life", "eol",
        "end of support", "no longer supported", "retiring", "retirement",
        "removed in", "breaking change", "behavior change", "will no longer",
        "discontinue", "discontinued", "known issue", "regression",
        "breaks", "broken by", "workaround required",
    ],
}

# --- Email Settings ---
# Credentials are imported from config.py (see top of file).
# SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD, RECEIVER_EMAIL


# =============================================================================
# FUNCTIONS
# =============================================================================

def fetch_and_categorize(feed_url, source_name):
    """
    Fetches one RSS feed and scans every article against all CATEGORIES.

    Returns a dict shaped like {category_name: [formatted_article_strings]}.
    If the feed fails to load or returns no entries, returns an empty dict so
    the rest of the script continues unaffected.
    """
    print(f"  Fetching: {source_name}")
    try:
        feed = feedparser.parse(feed_url)

        # feed.bozo is True when feedparser encountered malformed XML.
        # We only treat it as a hard failure when there are also no entries —
        # some feeds are technically malformed but still yield usable content.
        if feed.bozo and not feed.entries:
            print(f"    WARNING: Could not parse feed — {feed.bozo_exception}")
            return {}

    except Exception as e:
        print(f"    ERROR fetching {source_name}: {e}")
        return {}

    # Pre-build the results dict with an empty list for every category
    results = {cat: [] for cat in CATEGORIES}

    for entry in feed.entries:
        title   = entry.get("title", "")
        summary = entry.get("summary", "")
        link    = entry.get("link", "")

        # Combine title + summary into one lowercase string for a single-pass search
        text = (title + " " + summary).lower()

        # Check every category's keyword list against this article's text
        for category, keywords in CATEGORIES.items():
            if any(kw.lower() in text for kw in keywords):
                # Format the match as a bullet with its link on the next line
                results[category].append(f"  * {title}\n    {link}")

    return results


def merge_results(all_results):
    """
    Combines per-feed category dicts from all feeds into one unified dict.

    Also deduplicates — if the same article appears in two feeds (e.g. a
    Microsoft post that shows up on both the IT Pro Blog and M365 feed),
    it will only appear once per category. dict.fromkeys() preserves order
    while removing duplicates, unlike a set() which would scramble ordering.
    """
    merged = {cat: [] for cat in CATEGORIES}

    for feed_results in all_results:
        for cat, items in feed_results.items():
            merged[cat].extend(items)

    # Remove duplicates while preserving insertion order
    for cat in merged:
        merged[cat] = list(dict.fromkeys(merged[cat]))

    return merged


def build_email_body(merged):
    """
    Builds the plain-text email body from the merged category results.

    Sections are printed in CATEGORIES dict order. Each section shows either
    its matched articles or a "no matches" placeholder so the reader can
    confirm the category was checked even when nothing was found.

    Returns:
        body_text (str): The full email body as a single string.
        any_hits  (bool): True if at least one category had a match — used
                          by the caller to decide whether to send the email.
    """
    today = datetime.now().strftime("%Y-%m-%d")

    # Start with a header line and divider
    lines = [f"Microsoft Update Summary — {today}", "=" * 50, ""]

    any_hits = False

    for category, items in merged.items():
        lines.append(f"[ {category.upper()} ]")

        if items:
            any_hits = True
            lines.extend(items)   # Each item is already a formatted multi-line string
        else:
            lines.append("  No matching updates this week.")

        lines.append("")  # Blank line between sections

    return "\n".join(lines), any_hits


def send_summary(body_text):
    """
    Sends the compiled summary email via Gmail using SSL on port 465.

    Uses EmailMessage (stdlib) rather than MIMEText to avoid header injection
    risks. The SSL context uses system-default CA certificates to verify the
    Gmail server certificate — no cert verification is skipped.
    """
    msg = EmailMessage()
    msg.set_content(body_text)
    msg["Subject"] = f"Microsoft Update Summary — {datetime.now().strftime('%Y-%m-%d')}"
    msg["From"]    = SENDER_EMAIL
    msg["To"]      = RECEIVER_EMAIL

    # ssl.create_default_context() verifies the server certificate against
    # the OS trust store — safer than ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # with check_hostname/verify disabled.
    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)

    print("Email sent successfully.")


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    print("Scanning Microsoft update feeds...\n")

    all_results = []

    # Iterate over every configured feed, collect categorized matches
    for source_name, feed_url in FEEDS.items():
        result = fetch_and_categorize(feed_url, source_name)
        # Only append if the feed returned something (empty dict = failed feed)
        if result:
            all_results.append(result)

    # Merge all per-feed results into one dict and remove cross-feed duplicates
    merged = merge_results(all_results)

    # Build the email body; any_hits tells us whether anything matched
    body, any_hits = build_email_body(merged)

    if any_hits:
        print("\nSending summary email...")
        send_summary(body)
    else:
        # Nothing matched — no email sent, but script exits cleanly
        print("\nNo updates matched any category this week. Email not sent.")
