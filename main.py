import re
import json
import csv
from bs4 import BeautifulSoup

# File paths
log_file_path = "access_log.txt"
threat_file_path = "threat_feed.html"
url_status_report_path = "url_status_report.txt"
malware_candidates_path = "malware_candidates.csv"
alert_json_path = "alert.json"
summary_report_path = "summary_report.json"


# Load and parse access log
with open(log_file_path, 'r') as file:
    log_data = file.readlines()

# Extract URLs and status codes using Regex
url_status_pattern = r'"[A-Z]+ (http[^\s]+) HTTP/[0-9.]+" (\d{3})'
url_status = [(match.group(1), int(match.group(2))) for line in log_data 
              if (match := re.search(url_status_pattern, line))]

# Count 404 URLs
url_404_counts = {}
for url, status in url_status:
    if status == 404:
        url_404_counts[url] = url_404_counts.get(url, 0) + 1

# Write URL and status to file
with open(url_status_report_path, 'w') as file:
    for url, status in url_status:
        file.write(f"{url} {status}\n")

# Write 404 URL counts to CSV
with open(malware_candidates_path, 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["URL", "Number of 404s"])
    for url, count in url_404_counts.items():
        writer.writerow([url, count])

# Load and parse threat feed HTML
with open(threat_file_path, 'r') as file:
    soup = BeautifulSoup(file, 'html.parser')

# Extract blacklisted domains
blacklisted_domains = {li.text.strip() for li in soup.find_all('li')}

# Check matches with blacklisted domains
blacklisted_matches = {}
for url, status in url_status:
    for domain in blacklisted_domains:
        if domain in url:
            if url not in blacklisted_matches:
                blacklisted_matches[url] = {"status": status, "count": 0}
            blacklisted_matches[url]["count"] += 1

# Create alert.json
with open(alert_json_path, 'w') as file:
    json.dump(blacklisted_matches, file, indent=4)

# Create summary_report.json
summary_report = {
    "total_urls_analyzed": len(url_status),
    "unique_urls": len(set(url for url, _ in url_status)),
    "total_404_urls": len(url_404_counts),
    "blacklisted_matches": len(blacklisted_matches)
}

with open(summary_report_path, 'w') as file:
    json.dump(summary_report, file, indent=4)

# Outputs
url_status_report_path, malware_candidates_path, alert_json_path, summary_report_path
