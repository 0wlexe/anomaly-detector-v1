# Anomaly Detector

'Anomaly Detector' is a Python-based tool designed to analyze network traffic and sign-in log files to detect suspicious patterns and potential security anomalies. 
It provides formatted console reports summarizing findings.

## Table of Contents

1.  [Project Overview](#Anomaly-Detector)
2.  [Project Structure](#Project-Structure)
3.  [Technologies Used](#Technologies-Used)
4.  [Usage](#Usage)
6.  [Anomaly Detection Rules](#Anomaly-Detection-Rules)
7.  [Report Output](#Report-output)
10. [License](#License)
11. [Reference](#Reference)
   

## Project Structure

```
Anomaly Detector
├── logs/  
│   ├── traffic-requests.csv     # Sample of traffic request logs  
├── config.py                    # Configuration settings (file paths, anomaly rules)  
├── report_format.py             # Defines report structure and formatting  
├── login_analysis.py            # Handles analysis of sign-in related logs
├── login_report.py              # Generates login-related reports  
├── main.py                      # Main script - Run this file
├── traffic_analysis.py          # Handles traffic patterns and anomalies   
├── traffic_report.py            # Generates web traffic-related reports  
```

## Technologies Used

*   **Python 3.13.2**
*   **Standard Libraries:** `csv`, `re`, `logging`, `os`, `sys`, `json`, `collections`
*   **External Libraries:**
    *   `rich`: For console formatting.

## Usage

1.  Navigate to the project directory in your terminal.
2.  Ensure your log files (`.csv` format) are accessible.
3.  Run the main script:
    ```bash
    python main.py
    ```
4.  **Follow the prompts:**
    *   Select the analysis type (1 for Traffic, 2 for Sign-In).
    *   Enter the name or full path to the relevant log file (`.csv`).
    *   If you selected Sign-In analysis, you **must** enter the specific `transaction_user_id` you want to analyze.
5.  The analysis results will be printed to the console using formatted tables and panels.

## Anomaly Detection Rules
Anomaly detection is performed by matching regular expressions defined in the `ANOMALY_RULES` list in `config.py`. These rules can be customized to detect specific patterns in log data that are not usual for users. 

For this project, common web attack types should be filtered such as:
- Brute Force
- SQL_Injection
- XSS
- Command_Injection
- Privilege_Escalation

Sign-in module also counts with the following detections for anomalous behavior:
- Unknown (For generic traffic actions)
- Multiple Failed Login attempts
- Logins by untrusted device
- Risky reauthentication
- Suspicious Fields (For unusual patterns)

 Review `Anomaly_detector/config.py` for examples.
 
## Report Output

The script generates a report in accordance to the selected prompt.

```
--- ANOMALY DETECTOR ---

What type of log would you like to analyze?
  1. Web traffic logs
  2. Sign-In Logs
```

### For Web Traffic Logs

*   **Log Overview**: Provides a summary of the log data, including the total number of requests, failed requests, and successful requests.
*   **Anomaly Report**: Lists any anomalies detected in the log data, including their type, severity, and associated details.

```
Selected: Traffic Analysis.
Enter path to the traffic log file (e.g., traffic_logs.csv):

Selected: Traffic Analysis.
Enter path to the traffic log file (e.g., traffic_logs.csv): log_sample.csv
Using log file: log_sample.csv

Starting analysis of 'log_sample.csv'...
2025-03-27 22:53:22,414 - INFO - Traffic analysis complete. Processed 3 requests. Found 2 anomaly events.
Analysis complete. Generating report...
╭────────────────────────────────────── Anomaly Detector Report ─────────────────────────────────────╮
│ Traffic Log Analysis Report (Traffic Analysis)                                                     │
╰────────────────────────────────────────────────────────────────────────────────────────────────────╯

--- Log Overview ---
Total Traffic Events Processed: 17036
HTTP Status >= 400: 493
HTTP Status 200: 15763

Request Method Counts:
  - GET: 10016
  - POST: 5476
  - OPTIONS: 1112
  - PUT: 417
  - DELETE: 15

--- Anomaly Report ---
Found 22 potential anomaly events.

╭───────── Potential Command Injection Attack ──────────╮
│  Time                  2023-11-16 10:00:05            │
│  User ID               user456                        │
│  Method                GET                            │
│  Status                500                            │
│  Request URI           /admin?id=1;DROP TABLE users;  │
│  Http User Agent       Mozilla/5.0                    │
│  Matched Pattern       (;.*)                          │
│  Severity              HIGH                           │
│  Attack Types          COMMAND_INJECTION              │
╰──────────── IP: 192.168.1.2 | Log Row: ~2 ────────────╯

╭────────────────── Bot Activity Detected (UA Based) ───────────────────╮
│  Time                  2023-11-16 10:00:10                            │
│  User ID               bot789                                         │
│  Method                GET                                            │
│  Status                200                                            │
│  Request URI           /products                                      │
│  Http User Agent       Googlebot                                      │
│  Matched Pattern       (?i)(bot|crawler|spider|scan|agent|curl|wget)  │
│  Severity              LOW                                            │
│  Attack Types          UNKNOWN                                        │
╰──────────────────── IP: 192.168.1.3 | Log Row: ~3 ────────────────────╯

Report Generation Complete.

```

### For Sign-in Logs

*   **Log Overview**: Shows the total number of sign-in events processed, reflecting any user ID filtering applied during the analysis.
*   **Anomaly Report**: Groups findings by IP address. For each IP address associated with anomalies, an expandable panel is displayed. Inside the panel, each distinct anomaly pattern detected for that IP is listed sequentially as a formatted text block, showing: Anomaly Type,Attack Types, User ID and detected patterns of anomalous behavior.  

```
Selected: Sign-In Analysis.
Enter path to the signin log file (e.g., signin_logs.csv): login_logs.csv
Using log file: login_logs.csv
Enter the specific 'transaction_user_id' to analyze (Required): 88888
Filtering analysis for user ID: 88888

Starting analysis of 'login_logs.csv'...
Sign-in analysis complete for user ID '88888'.
Processed 89/22819 events from 7 IPs.
Found 57 unique anomaly patterns.

╭────────────────────────────────────── Anomaly Detector Report ────────────────────────────────────╮
│  Sign-In Log Analysis Report for User ID: 88888(Sign-In Analysis)                                 │
╰───────────────────────────────────────────────────────────────────────────────────────────────────╯

--- Log Overview ---
Total Sign-In Events Processed/Analyzed: 89

--- Anomaly Report ---
Found 57 distinct anomaly patterns across 7 unique IPs.
╭───────────────────────────────────── IP Address: 192.168.1.3  ─────────────────────────────────────╮
│   Anomaly Type:       Failed Login                                                                 │
│   Severity:           MEDIUM                                                                       │
│   Attack Types:       FAILED_LOGIN_ATTEMPT                                                         │
│   User ID:            88888                                                                        │
│   First Detected:     2025-02-22T11:38:57.390-04:00                                                │
│   Details:            Fail code: email                                                             │
│ ───────────────────────────────────────────────────────────────────────────────────────────────────│
│   Anomaly Type:       Failed Login                                                                 │
│   Severity:           MEDIUM                                                                       │
│   Attack Types:       FAILED_LOGIN_ATTEMPT                                                         │
│   User ID:            88888                                                                        │
│   First Detected:     2025-02-22T11:38:57.683-04:00                                                │
│   Details:            Fail code: enter_password                                                    │
│ ───────────────────────────────────────────────────────────────────────────────────────────────────│
│   Anomaly Type:       Failed Login                                                                 │
│   Severity:           MEDIUM                                                                       │
│   Attack Types:       FAILED_LOGIN_ATTEMPT                                                         │
│   User ID:            88888                                                                        │
│   First Detected:     2022-02-22T11:41:53.637-04:00                                                │
│   Details:            Fail code: enrollment_flow                                                   │
╰───────────────────────────────────── (3 distinct patterns found) ──────────────────────────────────╯

Report Generation Complete.

```

## License

Anomaly Detector is licensed under the MIT license. See the [LICENSE](https://opensource.org/license/MIT) file for details.


## Reference
This project was inspired by the following guides and open source solutions:
 - [Create a Python SIEM System Using AI and LLMs for Log Analysis and Anomaly Detection](https://www.freecodecamp.org/news/how-to-create-a-python-siem-system-using-ai-and-llms/) by Chaitanya Rahalkar;
 - [STRESSED - A Security Log Analysis System](https://github.com/dottxt-ai/demos/tree/main/logs) by dottxt-ai.
