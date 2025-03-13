import tkinter as tk
from tkinter import messagebox, filedialog, font
import requests
from urllib.parse import urlparse
import tldextract
import re
import datetime
import csv
import whois
from Levenshtein import distance as levenshtein_distance

# Google Safe Browsing API Key (Replace with your key)
API_KEY = "YOUR_API_KEY"
API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Trusted domain list for typo-squatting detection
KNOWN_SITES = ["facebook.com", "paypal.com", "google.com", "amazon.com", "bankofamerica.com"]

# 🛑 Enhanced Phishing Detection Functions
def is_ip_address(domain):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) is not None

def has_suspicious_keywords(url):
    suspicious_keywords = ["login", "secure", "verify", "account", "update", "confirm", "banking", "free", "offer"]
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def has_many_subdomains(domain):
    return len(tldextract.extract(domain).subdomain.split('.')) > 2

def check_url_length(url):
    return len(url) > 75

def check_google_safe_browsing(url):
    try:
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(f"{API_URL}?key={API_KEY}", json=payload, timeout=5)
        data = response.json()
        return "matches" in data
    except Exception as e:
        print(f"Google Safe Browsing API Error: {e}")
        return False  # Assume safe if API check fails

def check_whois_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return True  # Assume risky if no creation date found
        age_days = (datetime.datetime.now() - creation_date).days
        return age_days < 90  # Flags domain younger than 3 months
    except Exception as e:
        print(f"WHOIS Lookup Error: {e}")
        return True  # Assume risky if WHOIS lookup fails

def check_levenshtein_distance(url):
    domain = tldextract.extract(url).registered_domain
    if domain in KNOWN_SITES:
        return False  # Don't flag exact matches

    for known_site in KNOWN_SITES:
        if levenshtein_distance(domain, known_site) == 1:  # Detects 1-character typos
            return True  
    return False  

def contains_hex_encoding(url):
    return re.search(r"%[0-9A-Fa-f]{2}", url) is not None

def has_long_redirect_chain(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        return len(response.history) > 3  # If more than 3 redirects, flag as suspicious
    except requests.exceptions.RequestException:
        return False  # Assume safe if request fails

def contains_unusual_tld(url):
    risky_tlds = [".xyz", ".top", ".info", ".biz", ".club", ".online"]
    domain = tldextract.extract(url).suffix
    return domain in risky_tlds

# 🔍 Enhanced Scanning Functions
def scan_url():
    url = url_entry.get().strip()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL.")
        return

    result = scan_single_url(url)
    display_result(result)
    url_entry.delete(0, tk.END)

def scan_single_url(url):
    parsed_url = urlparse(url)
    domain = tldextract.extract(url).registered_domain

    if not domain:
        return {"url": url, "risk_level": "Invalid URL", "checks": {}}

    checks = {
        "IP Address in URL": is_ip_address(parsed_url.netloc),
        "Suspicious Keywords": has_suspicious_keywords(url),
        "Excessive Subdomains": has_many_subdomains(domain),
        "URL Length": check_url_length(url),
        "Google Safe Browsing": check_google_safe_browsing(url),
        "Newly Registered Domain": check_whois_age(domain),
        "Typo-Squatting Detection": check_levenshtein_distance(url),
        "Hex Encoding in URL": contains_hex_encoding(url),
        "Excessive Redirects": has_long_redirect_chain(url),
        "Unusual TLD Usage": contains_unusual_tld(url)
    }

    flag_count = sum(checks.values())
    risk_level = "No Risk"
    if flag_count == 1:
        risk_level = "Low"
    elif flag_count == 2:
        risk_level = "Medium"
    elif flag_count >= 3:
        risk_level = "High"

    log_result(url, risk_level)
    return {"url": url, "risk_level": risk_level, "checks": checks}

def log_result(url, risk_level):
    with open("phishing_log.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.datetime.now(), url, risk_level])

# 🚨 Display Results
def display_result(result):
    if result['risk_level'] == "Invalid URL":
        messagebox.showerror("Error", "The entered URL is not valid.")
        return

    risk_color = {"High": "red", "Medium": "orange", "Low": "green", "No Risk": "green"}.get(result['risk_level'], "black")
    result_label.config(text=f"Risk Level: {result['risk_level']}", fg=risk_color)

    details_text = "\n".join([f"❌ {check}" if value else f"✅ {check}" for check, value in result['checks'].items()])
    details_label.config(text=details_text, fg="red" if "❌" in details_text else "green")

# 📂 Scan from File
def scan_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")])
    if not file_path:
        return

    with open(file_path, "r") as file:
        results = [scan_single_url(line.strip()) for line in file if line.strip()]

    messagebox.showinfo("File Scan Complete", f"Scanned {len(results)} URLs/IPs from file. Check 'phishing_log.csv' for details.")
    result_label.config(text=f"Total Scanned: {len(results)}")
    details_label.config(text="File scan complete. Results saved to 'phishing_log.csv'.")

# 🎨 GUI Setup
root = tk.Tk()
root.title("Advanced Phishing Link Scanner")
root.geometry("520x650")
root.configure(bg="#f7f9fc")

title_font = font.Font(family="Helvetica", size=18, weight="bold")
label_font = font.Font(family="Helvetica", size=12)
result_font = font.Font(family="Helvetica", size=14, weight="bold")

title_label = tk.Label(root, text="Advanced Phishing Link Scanner", font=title_font, bg="#4A90E2", fg="white", pady=10)
title_label.pack(fill=tk.X)

input_frame = tk.Frame(root, bg="#f7f9fc")
input_frame.pack(pady=10)
tk.Label(input_frame, text="Enter URL:", font=label_font, bg="#f7f9fc").pack(side=tk.LEFT, padx=5)
url_entry = tk.Entry(input_frame, width=40, font=label_font)
url_entry.pack(side=tk.LEFT, padx=5)

button_frame = tk.Frame(root, bg="#f7f9fc")
button_frame.pack(pady=10)
tk.Button(button_frame, text="Scan URL", command=scan_url, font=label_font, bg="#007BFF", fg="white", width=15).grid(row=0, column=0, padx=5, pady=5)
tk.Button(button_frame, text="Scan from File", command=scan_file, font=label_font, bg="#28A745", fg="white", width=15).grid(row=0, column=1, padx=5, pady=5)

result_label = tk.Label(root, text="Risk Level: N/A", font=result_font, bg="white")
result_label.pack(pady=10)
details_label = tk.Label(root, text="", font=label_font, justify="left", bg="white")
details_label.pack(pady=10)

root.mainloop()
