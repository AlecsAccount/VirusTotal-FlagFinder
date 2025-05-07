import csv
import requests
import certifi
import time
import re
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

 
# Your VirusTotal API Key
API_KEY = "" #Put your lovely API key in there
 

# Function to clean up URLs (remove HTTPS:// and HTTP:// because the script doesnt like it)
def clean_url(url):
    return re.sub(r'https?://([^/]+).*$', r'\1', url)


# Function to query a URL on VirusTotal
def check_url_virustotal(url):
    headers = {"x-apikey": API_KEY}
    if "/" in url: 
        url = clean_url(url)
    print("Verify this URL is without HTTP(s) ", url)
    try:
        # Query the URL report using its ID
        report_url = f"https://www.virustotal.com/api/v3/domains/{url}"
        report_response = requests.get(report_url, headers=headers, verify=False)
        if report_response.status_code == 200:
            # Extract the results
            analysis_results = report_response.json()
            total_engines = analysis_results["data"]["attributes"]["last_analysis_stats"]
            return total_engines["malicious"]  # Count of malicious engines
        elif report_response.status_code == 404:
            print(f"URL not in VT yet {url}: {report_response.status_code}")
        else:
            print(f"Error querying report for URL {url}: {report_response.status_code}")
    except Exception as e:
        print(f"Exception occurred while processing {url}: {e}")
    return 0  # Default to 0 flags if error occurs
 
# Function to process URLs from a CSV file
def process_csv(file_name):
    urls = []
    try:
        with open(file_name, 'r', encoding='utf-8-sig') as csv_file:
            csv_reader = csv.reader(csv_file)
            for row in csv_reader:
                for line in row:  # Assuming URLs are in each cell of the row
                    url = clean_url(line)
                    if url not in urls:
                        urls.append(url)
    except FileNotFoundError:
        print(f"Error: File {file_name} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return urls


# Main script execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a CSV file containing URLs and check for malicious flags on VirusTotal")
    parser.add_argument("-f", "--file",type=str, required=True, help="Path to the CSV file containing URLs")
    args = parser.parse_args()

    flagged_urls = [] 

    csv_urls = process_csv(args.file)

    for url in csv_urls: 
        print(f"Checking URL: {url}")
        flag_count = check_url_virustotal(url)
        print(f"Flags Detected: {flag_count}/94")
        if flag_count > 0:  # Threshold for flagged URLs
            flagged_urls.append(url)
        time.sleep(15)  # Rate limit (VirusTotal free tier has a 4 requests/min cap )

    print("\nURLs flagged with any detections:")
    for flagged_url in flagged_urls:
        print(flagged_url)
 



 
