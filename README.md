Web Application Vulnerability Scanner
Overview

This project is a Python-based web application vulnerability scanner designed to detect common security issues in web applications, including:

XSS (Cross-Site Scripting)

SQL Injection (SQLi)

Missing CSRF Tokens

It includes a simple Flask web interface for scanning target websites and generating structured reports.

This tool is intended for educational purposes and authorized penetration testing only. Never scan websites without explicit permission.

Features

Crawls and scans a website up to a configurable number of pages (max_pages).

Detects input fields, forms, and URL parameters for vulnerabilities.

Minimal yet effective detection for:

Reflected XSS

Basic SQL Injection

Missing CSRF tokens

Generates JSON reports with vulnerabilities and errors.

Flask web interface for easy scanning and viewing results.

Organized reports/ folder with saved reports per target domain.

Lightweight, beginner-friendly, and easy to extend.

Tech Stack

Python 3.x

Flask (for web interface)

Requests (HTTP requests)

BeautifulSoup / lxml (HTML parsing)

Regex (pattern matching for vulnerability detection)

Installation & Setup

1. Clone or Download

Download the project ZIP and extract it:

cd C:\path\to\minimal-webapp-scanner

2. Create Virtual Environment
   python -m venv venv
   .\venv\Scripts\Activate.ps1 # PowerShell

# For CMD: .\venv\Scripts\activate.bat

3. Install Dependencies
   pip install -r requirements.txt

Running the Project
Option 1: Using Flask Web Interface

Set Flask app:

$env:FLASK_APP = "app.py"

Start the server:

flask run

Open your browser:

http://127.0.0.1:5000

Enter the target URL and click Scan.

View the results on the web page and in the reports/ folder.

Option 2: Command-Line Scan

You can also run the scanner directly from the CLI:

python scanner.py https://example.com

The JSON report will be saved automatically in the reports/ folder.

Scan results include detected vulnerabilities and any request errors.

Folder Structure
minimal-webapp-scanner/
│
├─ app.py # Flask web interface
├─ scanner.py # Core scanning engine
├─ templates/ # HTML templates (index.html, results.html)
├─ reports/ # JSON reports (auto-generated)
├─ requirements.txt # Python dependencies
└─ README.md # This documentation

Advantages

Beginner-friendly: Minimal setup, easy to run and understand.

Lightweight: No heavy frameworks, purely Python-based.

Educational: Shows how web vulnerabilities work and how to detect them.

Flexible: Can be extended for additional checks or automated reporting.

Cross-platform: Runs on Windows, Linux, and macOS with Python.

Good Points / Highlights

Auto-crawling: Finds pages and forms within the same domain.

Payload testing: Tests XSS and SQLi payloads automatically.

CSRF detection: Highlights missing CSRF protections in forms.

Structured reporting: Each report saved per domain for easy tracking.

Safe & minimal: Only uses safe GET/POST requests; designed for learning and practice.

Disclaimer

This project is for educational purposes only. Use it only on websites you own or have permission to test. The author is not responsible for any misuse.
