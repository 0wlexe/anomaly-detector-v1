# Automated Report For Log Traffic.md
This section includes an output of the 'Anomaly Detector' tool, for the analysis of web traffic logs. 
The purpose of this tool is to agilize the analysis and detection of anomalous behavior in large files. 

By running the analysis to 'traffic_BeatriZ.csv' it has gathered multiple indicators of potential attacks, 
mostly SQL Injections for that web environment.




```
PS C:...\challenge> python main.py

--- ANOMALY DETECTOR ---

What type of log would you like to analyze?
  1. Web traffic logs
  2. Sign-In Logs

Enter choice (1 or 2): 1

Selected: Traffic Analysis.
Enter path to the traffic log file (e.g., traffic_logs.csv): traffic_BeatriZ.csv
Using log file: traffic_BeatriZ.csv

Starting analysis of 'traffic_BeatriZ.csv'...
2025-03-28 12:13:13,758 - INFO - Traffic analysis complete. Processed 17036 requests. Found 22 anomaly events.
Analysis complete. Generating report...
╭────────────────────────────────────────────────────────── Anomaly Detector Report ──────────────────────────────────────────────────────────╮
│ Traffic Log Analysis Report (Traffic Analysis)                                                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

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
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 23:39:52                                                                                                  │
│  IP Address            10.53.198.109                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.198.109                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰───────────────────────────────────────────────────────────────  Log Row: ~34 ───────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 22:04:06                                                                                                  │
│  IP Address            10.53.194.160                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.194.160                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~560 ───────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 21:00:35                                                                                                  │
│  IP Address            10.53.231.86                                                                                                         │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.231.86                                                                                                         │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~1428 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 21:00:35                                                                                                  │
│  IP Address            10.53.231.126                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.231.126                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~2099 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 20:04:02                                                                                                  │
│  IP Address            10.53.194.160                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/90172d33-cda0-ce24-006c-1044d65f02c6?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=116755071&offset=0&limit  │
│                        =50                                                                                                                  │
│  Ip                    10.53.194.160                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(Infinix%20X6812B%3B%20Android%2011%3B%20Build%2FRP1A.200720.011)                  │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~4086 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 19:33:42                                                                                                  │
│  IP Address            10.53.231.86                                                                                                         │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.231.86                                                                                                         │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~4284 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 19:03:31                                                                                                  │
│  IP Address            10.53.192.81                                                                                                         │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/90172d33-cda0-ce24-006c-1044d65f02c6?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=116755071&offset=0&limit  │
│                        =50                                                                                                                  │
│  Ip                    10.53.192.81                                                                                                         │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(Infinix%20X6812B%3B%20Android%2011%3B%20Build%2FRP1A.200720.011)                  │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~4443 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 17:57:19                                                                                                  │
│  IP Address            10.53.212.223                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.212.223                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~5125 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 18:03:53                                                                                                  │
│  IP Address            10.53.250.197                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/9ea282a8-adee-0db1-745a-32cd735ecd03?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=159450106&offset=0&limit  │
│                        =50                                                                                                                  │
│  Ip                    10.53.250.197                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(LM-X525%3B%20Android%2010%3B%20Build%2FQKQ1.200531.002)                           │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~5163 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 17:19:19                                                                                                  │
│  IP Address            10.53.250.197                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/90172d33-cda0-ce24-006c-1044d65f02c6?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=116755071&offset=0&limit  │
│                        =50                                                                                                                  │
│  Ip                    10.53.250.197                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(Infinix%20X6812B%3B%20Android%2011%3B%20Build%2FRP1A.200720.011)                  │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~5184 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 16:10:10                                                                                                  │
│  IP Address            10.53.212.223                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.212.223                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~5322 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 15:03:28                                                                                                  │
│  IP Address            10.53.194.160                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.194.160                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~5598 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 13:24:53                                                                                                  │
│  IP Address            10.53.240.138                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.240.138                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~5741 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 13:53:04                                                                                                  │
│  IP Address            10.53.250.197                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/9ea282a8-adee-0db1-745a-32cd735ecd03?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=159450106&offset=0&limit  │
│                        =50                                                                                                                  │
│  Ip                    10.53.250.197                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(LM-X525%3B%20Android%2010%3B%20Build%2FQKQ1.200531.002)                           │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~5754 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 12:10:39                                                                                                  │
│  IP Address            10.53.192.81                                                                                                         │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.192.81                                                                                                         │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~5917 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 10:01:37                                                                                                  │
│  IP Address            10.53.235.211                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/9ea282a8-adee-0db1-745a-32cd735ecd03?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=159450106&offset=0&limit  │
│                        =50                                                                                                                  │
│  Ip                    10.53.235.211                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(LM-X525%3B%20Android%2010%3B%20Build%2FQKQ1.200531.002)                           │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~6275 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 09:39:10                                                                                                  │
│  IP Address            10.53.192.81                                                                                                         │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.192.81                                                                                                         │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~6333 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 08:45:08                                                                                                  │
│  IP Address            10.53.215.111                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/9ea282a8-adee-0db1-745a-32cd735ecd03?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=159450106&offset=0&limit  │
│                        =50                                                                                                                  │
│  Ip                    10.53.215.111                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(LM-X525%3B%20Android%2010%3B%20Build%2FQKQ1.200531.002)                           │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~6634 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 08:24:59                                                                                                  │
│  IP Address            10.53.235.211                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.235.211                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~6720 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 06:15:02                                                                                                  │
│  IP Address            10.53.250.197                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/9ea282a8-adee-0db1-745a-32cd735ecd03?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=159450106&offset=0&limit  │
│                        =50                                                                                                                  │
│  Ip                    10.53.250.197                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(LM-X525%3B%20Android%2010%3B%20Build%2FQKQ1.200531.002)                           │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~6915 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2023-02-22 00:18:17                                                                                                  │
│  IP Address            10.53.231.126                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/102eab31-866e-355c-bab3-1204a21a63f4?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.249.0&extended=false&last_updated=2023-02-17T13%3A40%3A59%2B0000&user_id=22172335&offset=0&limit=  │
│                        50                                                                                                                   │
│  Ip                    10.53.231.126                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.249.0%20(2107113SG%3B%20Android%2012%3B%20Build%2FSKQ1.211006.001)                         │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰──────────────────────────────────────────────────────────────  Log Row: ~7185 ──────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────── Potential SQL Injection ──────────────────────────────────────────────────────────╮
│  Time                  2022-02-22 11:01:58                                                                                                  │
│  IP Address            10.53.254.190                                                                                                        │
│  User ID                                                                                                                                    │
│  Method                GET                                                                                                                  │
│  Status                200                                                                                                                  │
│  Request URI           /experiments/assignments/62a9d2f6-f35d-ef7a-2711-5be3a1c56552?platform=%2Fmobile%2Fandroid&site=MLB&business=mercad  │
│                        olibre&version=10.231.1&extended=false&last_updated=2022-10-19T19%3A02%3A23%2B0000&offset=0&limit=50                 │
│  Ip                    10.53.254.190                                                                                                        │
│  Http User Agent       MercadoLibre-Android%2F10.231.1%20(motorola%20one%3B%20Android%2010%3B%20Build%2FQPKS30.54-22-27)                    │
│  Matched Pattern       (.*(?:select|insert|update|delete).*(?:from|into|set|where).*)                                                       │
│  Severity              HIGH                                                                                                                 │
│  Attack Types          SQL_INJECTION                                                                                                        │
╰─────────────────────────────────────────────────────────────  Log Row: ~11835 ──────────────────────────────────────────────────────────────╯

Report Generation Complete.

--- Analysis Finished ---
```
