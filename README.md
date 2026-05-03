# Update Scanner

A lightweight Python automation tool that monitors Microsoft-related RSS feeds and community blogs, filters articles by topics relevant to a Windows IT environment, and delivers a categorized weekly email digest.

Designed to run as a scheduled task on [PythonAnywhere](https://www.pythonanywhere.com/) with zero infrastructure overhead.

---

## What It Does

Every Monday, the script:

1. Fetches articles from six RSS sources covering security patches, product roadmap changes, IT pro guidance, and community analysis
2. Scans each article's title and summary against keyword lists organized into six topic categories
3. Deduplicates matches across feeds (the same article won't appear twice)
4. Emails a plain-text categorized summary — or stays silent if nothing matched

---

## Monitored Sources

| Source | What It Covers |
|---|---|
| **MSRC (Microsoft Security Response Center)** | Official CVE and patch announcements |
| **M365 Roadmap** | Upcoming feature changes and rollouts |
| **Windows IT Pro Blog** | Operational guidance and update behavior |
| **M365 Tech Community Blog** | Microsoft 365 product announcements |
| **AskWoody** | Update regressions, known issues, patch-readiness analysis |
| **Chris Titus Tech** | Real-world impact of OS changes, driver issues, tooling |

---

## Filter Categories

Articles are matched against these categories. An article can appear under more than one.

| Category | What Triggers It |
|---|---|
| **32-Bit / Legacy App Impact** | WOW64 changes, x86 compatibility, legacy application support |
| **MS Access** | Microsoft Access runtime, .accdb format, version-specific mentions |
| **Printer Impact (Okidata / Epson)** | Print spooler changes, driver updates, Windows printing subsystem |
| **Email Security** | Exchange, SMTP behavior, SPF/DKIM/DMARC, mail flow rule changes |
| **Network Shares / SMB** | SMB protocol changes, mapped drives, UNC paths, LanMan auth |
| **Deprecations / EOL / Breaking Changes** | End-of-life notices, behavior changes, regressions, workaround advisories |

---

## Requirements

- Python 3.8+
- [feedparser](https://pypi.org/project/feedparser/) (`pip install feedparser`)
- A Gmail account with a generated **App Password**

All other dependencies (`smtplib`, `ssl`, `email`) are part of the Python standard library.

---

## Setup

### 1. Clone or upload the script

```bash
git clone https://github.com/yourusername/microsoft-update-scanner.git
```

### 2. Install the dependency

```bash
pip install feedparser
```

### 3. Configure your email credentials

Open `ms_update_scanner.py` and edit the configuration block near the top:

```python
SENDER_EMAIL    = "you@gmail.com"
SENDER_PASSWORD = "your-app-password"   # See below
RECEIVER_EMAIL  = "you@gmail.com"
```

### 4. Generate a Gmail App Password

Regular Gmail passwords will not work. You need an App Password:

1. Go to [myaccount.google.com](https://myaccount.google.com)
2. Navigate to **Security** → **2-Step Verification** (must be enabled)
3. Scroll down to **App Passwords**
4. Create a new one named something like `PythonAnywhere Scanner`
5. Copy the 16-character password into `SENDER_PASSWORD` (no spaces)

> **Security note:** Never commit your App Password to a public repository. Consider loading it from an environment variable in production:
> ```python
> import os
> SENDER_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD")
> ```

### 5. Test locally

```bash
python ms_update_scanner.py
```

You should see each feed fetched in the terminal, followed by `Email sent successfully.`

---

## Deploying to PythonAnywhere

PythonAnywhere offers free scheduled task hosting — no server management required.

1. Log in to [pythonanywhere.com](https://www.pythonanywhere.com/)
2. Upload `ms_update_scanner.py` via the **Files** tab
3. Install feedparser in a Bash console: `pip install --user feedparser`
4. Go to the **Tasks** tab → **Scheduled Tasks**
5. Set the command: `python3 /home/yourusername/ms_update_scanner.py`
6. Set the schedule: **Weekly**, Monday, at your preferred time

---

## Customizing

### Add a new keyword to an existing category

Find the relevant category in the `CATEGORIES` dict and append to its list:

```python
"Network Shares / SMB": [
    "smb", "network share", ...
    "kerberos authentication",   # <-- added
],
```

### Add an entirely new category

Add a new key/value pair to `CATEGORIES`:

```python
"Remote Desktop / RDS": [
    "remote desktop", "rdp", "rds", "terminal services",
],
```

### Add a new RSS feed

Add a new entry to the `FEEDS` dict:

```python
"Bleeping Computer Windows": "https://www.bleepingcomputer.com/feed/",
```

---

## Project Structure

```
microsoft-update-scanner/
├── ms_update_scanner.py   # Main script — all logic and configuration
└── README.md
```

---

## License

MIT — free to use, modify, and redistribute.
