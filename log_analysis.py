import re
import pandas as pd
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parse the log file and extract relevant details."""
    ip_requests = defaultdict(int)
    endpoint_access = defaultdict(int)
    failed_logins = defaultdict(int)

    log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"(?P<method>GET|POST) (?P<endpoint>/\S*) HTTP.*" (?P<status>\d{3})')
    failed_login_message = "Invalid credentials"

    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = log_pattern.search(line)
                if match:
                    ip = match.group("ip")
                    endpoint = match.group("endpoint")
                    status = match.group("status")

                    ip_requests[ip] += 1
                    endpoint_access[endpoint] += 1

                    if status == "401" or failed_login_message in line:
                        failed_logins[ip] += 1
    except FileNotFoundError:
        logging.error(f"The file {file_path} was not found.")
        exit(1)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        exit(1)

    return ip_requests, endpoint_access, failed_logins

def save_to_csv(ip_requests, endpoint_access, failed_logins, output_file):
    """Save the analysis results to a CSV file."""
    try:
        ip_df = pd.DataFrame(list(ip_requests.items()), columns=["IP Address", "Request Count"]).sort_values(by="Request Count", ascending=False)
        endpoint_df = pd.DataFrame(list(endpoint_access.items()), columns=["Endpoint", "Access Count"]).sort_values(by="Access Count", ascending=False)
        failed_logins_df = pd.DataFrame(list(failed_logins.items()), columns=["IP Address", "Failed Login Count"]).sort_values(by="Failed Login Count", ascending=False)

        # Save each DataFrame to a separate CSV file
        ip_df.to_csv("requests_per_ip.csv", index=False)
        endpoint_df.to_csv("most_accessed_endpoint.csv", index=False)
        failed_logins_df.to_csv("suspicious_activity.csv", index=False)

        logging.info(f"Results successfully saved as separate CSV files.")
    except Exception as e:
        logging.error(f"Failed to save results to CSV: {e}")
        exit(1)


def display_results(ip_requests, endpoint_access, failed_logins):
    """Display the analysis results in the terminal."""
    print("\nRequests per IP Address:")
    print("{:<20} {:<15}".format("IP Address", "Request Count"))
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    most_accessed = max(endpoint_access.items(), key=lambda x: x[1])
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("{:<20} {:<20}".format("IP Address", "Failed Login Attempts"))
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20} {count:<20}")

def main():
    """Main function to execute the log analysis."""
    logging.info("Parsing log file...")
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)

    logging.info("Saving results to CSV...")
    save_to_csv(ip_requests, endpoint_access, failed_logins, OUTPUT_FILE)

    logging.info("Displaying results:")
    display_results(ip_requests, endpoint_access, failed_logins)

if __name__ == "__main__":
    main()
