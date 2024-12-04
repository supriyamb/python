Log Analysis Script
Overview
This project implements a Python script to analyze server log files. The script extracts key insights, such as:

Number of requests made by each IP address.
The most frequently accessed endpoint.
Suspicious activity, such as potential brute-force login attempts.
The results are displayed in the terminal and saved to CSV files for further analysis.

Features
Requests Per IP Address:

Counts the number of requests made by each IP.
Displays the IPs sorted by request count in descending order.
Most Frequently Accessed Endpoint:

Identifies the endpoint (e.g., URL or resource path) with the highest access count.
Suspicious Activity Detection:

Flags IPs with failed login attempts exceeding a threshold (default: 10).
CSV Output:

Results are saved into separate CSV files:
requests_per_ip.csv
most_accessed_endpoint.csv
suspicious_activity.csv
Requirements
Python 3.12 or later
Required Python libraries:
pandas

Setup Instructions
1. Clone the Repository (if applicable):
bash
Copy code
git clone <repository-url>
cd log_analysis_project
2. Install Python and Dependencies:
Ensure Python 3.12 or later is installed. Install required dependencies using:
pip install -r requirements.txt
3. Prepare the Log File:
Save the raw log data in a file named access.log.
Place this file in the same directory as the script (log_analysis.py).
4. Run the Script:
Execute the script in the terminal:
python log_analysis.py
Output
The script outputs the following information in the terminal:

Requests per IP address.
Most frequently accessed endpoint.
Suspicious activity detected.
Requests per IP Address:
IP Address           Request Count
203.0.113.5          8
198.51.100.23        8
192.168.1.1          7

Most Frequently Accessed Endpoint:
/login (Accessed 13 times)

Suspicious Activity Detected:
IP Address           Failed Login Attempts

CSV Files: The results are saved into these CSV files:

requests_per_ip.csv: Contains IP addresses and request counts.
most_accessed_endpoint.csv: Contains endpoints and access counts.
suspicious_activity.csv: Contains IPs with failed login attempts.
