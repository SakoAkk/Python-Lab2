import re
import csv
import json
from bs4 import BeautifulSoup

def extract_log_entries(log_file):
    """
    Extract URLs and status codes from log file using regex
    """
    url_pattern = re.compile(r'"(GET|POST) (http[s]?://[^\s]+) HTTP/\d\.\d" (\d{3})')
    entries = []
    
    with open(log_file, 'r') as f:
        for line in f:
            match = url_pattern.search(line)
            if match:
                method, url, status = match.groups()
                entries.append({
                    'method': method,
                    'url': url,
                    'status': status
                })
    
    return entries

def get_blacklisted_domains(threat_feed_file):
    """
    Extract blacklisted domains from HTML threat feed
    """
    with open(threat_feed_file, 'r') as f:
        soup = BeautifulSoup(f, 'html.parser')
        return [li.text.strip() for li in soup.find_all('li')]

def analyze_log_entries(entries):
    """
    Analyze log entries and categorize them
    """
    url_status_counts = {}
    error_404_urls = {}
    
    for entry in entries:
        # Count URLs and their status codes
        url_status_key = f"{entry['url']} ({entry['status']})"
        url_status_counts[url_status_key] = url_status_counts.get(url_status_key, 0) + 1
        
        # Track 404 errors
        
        if entry['status'] == '404':
            error_404_urls[entry['url']] = error_404_urls.get(entry['url'], 0) + 1
    
    return url_status_counts, error_404_urls

def main():
    # Extract log entries
    log_entries = extract_log_entries('access_log.txt')
    
    # Get blacklisted domains
    blacklisted_domains = get_blacklisted_domains('threat_feed.html')
    
    # Analyze log entries
    url_status_counts, error_404_urls = analyze_log_entries(log_entries)
    
    # Identify matching blacklisted URLs
    matching_urls = []
    for entry in log_entries:
        for domain in blacklisted_domains:
            if domain in entry['url']:
                matching_urls.append({
                    'url': entry['url'],
                    'status': entry['status'],
                    'blacklisted_domain': domain
                })
    
    # 1. Create URL Status Report
    with open('url_status_report.txt', 'w') as f:
        for url, count in url_status_counts.items():
            f.write(f"{url}: {count} times\n")
    
    # 2. Create Malware Candidates CSV
    with open('malware_candidates.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['URL', 'Number of 404s'])
        for url, count in error_404_urls.items():
            writer.writerow([url, count])
    
    # 3. Create Alert JSON
    with open('alert.json', 'w') as f:
        json.dump(matching_urls, f, indent=2)
    
    # 4. Create Summary Report JSON
    summary = {
        'total_entries': len(log_entries),
        'unique_urls': len(set(entry['url'] for entry in log_entries)),
        'blacklisted_matches': len(matching_urls),
        '404_errors': sum(error_404_urls.values()),
        'unique_404_urls': len(error_404_urls)
    }
    
    with open('summary_report.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print("Analysis complete. Check the output files.")

if __name__ == '__main__':
    main()