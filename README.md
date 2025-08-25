VirusTotal CSV URL Checker

This Python script processes a CSV file containing URLs and checks each URL against VirusTotal for malicious detections. It flags any URLs that have been marked as malicious by VirusTotal's scanning engines.

Features

Reads URLs from a CSV file (supports multiple URLs per row)

Cleans URLs (removes http:// and https://) for compatibility with VirusTotal API

Queries VirusTotal API for each URL's scan results

Displays the number of malicious flags detected

Lists all URLs flagged as malicious



Requirements

Python 3.7+



Libraries: requests, certifi, argparse, urllib3



Install dependencies via:

pip install requests certifi

Usage

Get your VirusTotal API key from https://www.virustotal.com
 and paste it into the script (API_KEY = "YOUR_API_KEY").

Prepare a CSV file containing URLs (one or multiple per row).

Run the script:

python vt_csv_checker.py -f your_file.csv




The script will output the status of each URL and a final list of URLs flagged as malicious.

Example Output
Checking URL: example.com
Flags Detected: 2/94

Checking URL: safewebsite.org
Flags Detected: 0/94

URLs flagged with any detections:
example.com



Notes & Limitations

Rate Limiting: VirusTotal free tier allows 4 requests per minute, the script uses a 15-second delay between requests to comply.

API Key Required: Script will not work without a valid API key.

CSV Format: Each cell in a CSV row can contain a URL. Script deduplicates URLs automatically.

HTTPS Warning: The script disables SSL warnings (verify=False) for convenience but may be less secure.



Improvements

Cleans URLs before querying

Deduplicates URLs before sending requests

Gracefully handles missing files or API errors



License

Open-source; feel free to modify and use.
