import csv
import requests
import certifi
import time



# Your VirusTotal API Key
API_KEY = "" #Put your lovely API key in there

# Function to query a URL on VirusTotal
def check_url_virustotal(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": API_KEY}
    try:
        # Query the URL report using its ID
        report_url = f"https://www.virustotal.com/api/v3/domains/{url}"
        report_response = requests.get(report_url, headers=headers, verify=False) # verify=certifi.where()
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
    flagged_urls = []
    try:
        with open(file_name, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            for row in csv_reader:
                for url in row:  # Assuming URLs are in each cell of the row
                    print(f"Checking URL: {url}")
                    flag_count = check_url_virustotal(url)
                    print(f"Flags Detected: {flag_count}/94")
                    if flag_count > 1:  # Threshold for flagged URLs
                        flagged_urls.append(url)
                    time.sleep(15)  # Rate limit (VirusTotal free tier has a 4 requests/min cap )
    except FileNotFoundError:
        print(f"Error: File {file_name} not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return flagged_urls

# Main script execution
if __name__ == "__main__":
    file_name = input("Enter the path to the CSV file containing URLs: ")
    urls_with_flags = process_csv(file_name)
    
    print("\nURLs flagged with more than 1 detection:")
    for flagged_url in urls_with_flags:
        print(flagged_url)