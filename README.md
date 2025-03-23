# Anomaly Detector

This is a project for a Challenge.
The objective is to create an application that works as a prototype of a Security Information and Event Management (SIEM) to agilize in the analysis of traffic logs, and obtain patterns of anomalous behavior from users. 

## Table of Contents

1.  [Project Overview](#Anomaly-Detector)
2.  [Requirements](#Requirements)
3.  [Usage](#Usage)
4.  [Project Structure](#Project-Structure)
5.  [Anomaly Detection Rules](#Anomaly-Detection-Rules)
7.  [Report Output](#Report-output)
8.  [CSV File Format](#CSV-File-Format)
10. [License](#License)
11. [Reference](#Reference)
   

## Requirements

  - This project was build using Python 3.13.2.
  - Requirements are built-in Python modules (no need to install separately):
```
    os
    sys
    re
    csv
    logging
    collections (Counter)
    enum (Enum)
    typing (List, Dict)
 ```   
- External dependencies that require installation:
 ```  
    rich → For enhanced console output
 ```  

## Usage

1. To execute the Anomaly Detector, open a terminal or command prompt.
2. Navigate to the directory where you saved the Python files.
3. Run the `main.py` script, providing the CSV filename as a command-line argument:

  ```bash
  python main.py your_traffic_logs.csv
  ```
If you encounter issues, ensure the CSV file is in the same directory as main.py, or provide the full path to the file such as `username/directory/your_traffic_logs.csv`.

## Project Structure

```
Anomaly_detector/
├── config.py           # Configuration settings (file paths, anomaly rules)
├── log_analyzer.py     # Log analysis logic
├── report_generator.py # Report generation using rich
└── main.py             # Main script - orchestrates analysis
```

## Anomaly Detection Rules
Anomaly detection is performed by matching regular expressions defined in the `ANOMALY_RULES` list in `config.py`. These rules can be customized to detect specific patterns in log data that are not usual for users. 

For this project, common web attack types should be filtered such as:
- Brute Force
- SQL_Injection
- XSS
- Command_Injection
- Privilege_Escalation
- Unknown (For actions that may not present explicit malicious indicators)

 Review `Anomaly_detector/config.py` for examples.
 
## Report Output

The script generates a report to the console with the following sections:

*   **Log Overview**: Provides a summary of the log data, including the total number of requests, failed requests, and successful requests.
*   **Anomaly Report**: Lists any anomalies detected in the log data, including their type, severity, and associated details.
*   **HTTP Request Summary**: Contains two tables: a "Failed Requests" table containing HTTP requests with an error 500, and a "Successful Requests" table containing entries that got accepted.
Each table shows: Times, User ID, Remote Addr, Request URI, Status User Agent, Request Method

```
╭────────────────────────────────────────────────── Anomaly Detector Report ──────────────────────────────────────────────────╮
│ Traffic Log Analysis Report                                                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

--- Log Overview ---
Total Requests: 3
Failed Requests: 1
Successful Requests: 2

--- Anomaly Report ---
╭──────────────────────────────────────────── Potential Command Injection Attack ─────────────────────────────────────────────╮
│ ┌────────────────┬────────────────────────────────────┐                                                                     │
│ │ Type           │ Potential Command Injection Attack │                                                                     │
│ │ User Id        │ user456                            │                                                                     │
│ │ Request Uri    │ /admin?id=1;DROP TABLE users;      │                                                                     │
│ │ Time           │ 2025-03-22 10:00:10                │                                                                     │
│ │ Remote Addr    │ 0.0.0.0                            │                                                                     │
│ │ Status         │ 500                                │                                                                     │
│ │ Request Method │ GET                                │                                                                     │
│ │ Severity       │ LOW                                │                                                                     │
│ │ Attack Types   │ COMMAND_INJECTION                  │                                                                     │
│ └────────────────┴────────────────────────────────────┘                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────────────────────────────── Bot Activity Detected ───────────────────────────────────────────────────╮
│ ┌─────────────────┬───────────────────────┐                                                                                 │
│ │ Type            │ Bot Activity Detected │                                                                                 │
│ │ User Id         │ bot789                │                                                                                 │
│ │ Http User Agent │ Googlebot             │                                                                                 │
│ │ Time            │ 2025-03-22 10:00:10   │                                                                                 │
│ │ Remote Addr     │ 0.0.0.0               │                                                                                 │
│ │ Status          │ 200                   │                                                                                 │
│ │ Request Method  │ GET                   │                                                                                 │
│ │ Severity        │ LOW                   │                                                                                 │
│ │ Attack Types    │ UNKNOWN               │                                                                                 │
│ └─────────────────┴───────────────────────┘                                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

--- Failed Requests ---
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓        
┃ Time                ┃ User ID ┃ Remote Addr ┃ Request URI                   ┃ Status ┃ User Agent  ┃ Request Method ┃        
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩        
│ 2025-03-22 10:00:10 │ user456 │ 0.0.0.0     │ /admin?id=1;DROP TABLE users; │ 500    │ Mozilla/5.0 │ GET            │        
└─────────────────────┴─────────┴─────────────┴───────────────────────────────┴────────┴─────────────┴────────────────┘        

--- Successful Requests ---
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Time                ┃ User ID ┃ Remote Addr ┃ Request URI ┃ Status ┃ User Agent  ┃ Request Method ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ 2025-03-22 10:00:00 │ user123 │ 0.0.0.0     │ /index.html │ 200    │ Mozilla/5.0 │ GET            │
│ 2025-03-22 10:00:10 │ bot789  │ 0.0.0.0     │ /products   │ 200    │ Googlebot   │ GET            │
└─────────────────────┴─────────┴─────────────┴─────────────┴────────┴─────────────┴────────────────┘
```

## CSV File Format
The CSV file should have a header row with the following column names (case-sensitive):

*   `user_id`
*   `time`
*   `proxy_host`
*   `hostname`
*   `status`
*   `http_host`
*   `request_uri`
*   `server_protocol`
*   `request_method`
*   `request_time`
*   `request_length`
*   `bytes_sent`
*   `http_referer`
*   `http_user_agent`
*   (Other columns are permitted, but these are the ones actively analyzed)


## License

This project is licensed under the [CC0 1.0 Universal](LICENSE.md)
Creative Commons License - see the [LICENSE.md](LICENSE.md) file for
details.

    
## Reference
This project was inspired by the following guides and open source solutions:
 - [Create a Python SIEM System Using AI and LLMs for Log Analysis and Anomaly Detection](https://www.freecodecamp.org/news/how-to-create-a-python-siem-system-using-ai-and-llms/) by Chaitanya Rahalkar;
 - [STRESSED - A Security Log Analysis System](https://github.com/dottxt-ai/demos/tree/main/logs) by dottxt-ai.
