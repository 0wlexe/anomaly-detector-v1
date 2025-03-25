# Log Analysis Report 
A user has reported unusual behavior coming from their account, according to the user there were transactions they did not recognize. 
The objective of this report is to compile relevant information and identify patterns of behavior that might indicate if the user may have been compromised. 

## Log Overview
  - **Transaction account ID:** `41072246`
  - **Date Range of the logs:** `2022-02-22 04:00 - 2022-02-22 04:00`
  - **Total Log Entries Analyzed:** `89`

## Analysis Methodology

This analysis was conducted using custom scripts and manual review. Logs were parsed and filtered to help in the co-validation of User and entity behavior analytics (UEBA), 
which relates to a set of patterns, anomalies, and potential security threats to user accounts and devices.

## Key Findings

### 1. Anomalous Activity
- No re-authentication anomalies detected.
- Potential Brute-Force Attempts Detected:
```
  - User ID: 41072246.0, IP: 189.201.235.176, Attempts: 20, Reauthentication: False
  - User ID: 41072246.0, IP: 189.201.235.241, Attempts: 19, Reauthentication: True
  - User ID: 41072246.0, IP: 200.159.9.139, Attempts: 18, Reauthentication: False
  - User ID: 41072246.0, IP: 189.201.234.220, Attempts: 14, Reauthentication: False
  - User ID: 41072246.0, IP: 189.201.235.131, Attempts: 6, Reauthentication: True
  - User ID: 41072246.0, IP: 189.96.19.153, Attempts: 6, Reauthentication: True
```

### 2. Detected IP Addresses per login type

 Login Type: default
  
| IP Address 	      | Occurrences 	| First Seen 	          | Last Seen 	          | Client Type   |
|:---------------:	|:-----------:	|:-------------------:	|:-------------------:	|:-----------:	|
| 189.201.235.176 	| 20 	          | 2022-02-22 12:12:54 	| 2022-02-22 12:17:33 	| mobile     	  |
| 200.159.9.139 	  | 18 	          | 2022-02-22 01:55:22 	| 2022-02-22 01:58:15 	| mobile 	      |
| 189.201.234.220 	| 14 	          | 2022-02-22 11:38:57 	| 2022-02-22 11:41:53 	| mobile 	      |
| 189.96.19.153 	  | 6 	          | 2022-02-22 21:48:03 	| 2022-02-22 21:48:41 	| mobile 	      |
| 189.201.235.241 	| 6 	          | 2022-02-22 11:22:35 	| 2022-02-22 11:23:13 	| mobile 	      |
| 189.201.235.131 	| 6 	          | 2022-02-22 17:36:23 	| 2022-02-22 17:36:58 	| mobile 	      |
| 189.201.234.8 	  | 5 	          | 2022-02-22 12:31:26 	| 2022-02-22 12:31:26 	| mobile 	      |

Login Type: explicit

| IP Address 	      | Occurrences 	| First Seen 	          | Last Seen 	          | Client Type   |
|:---------------:	|:-----------:	|:-------------------:	|:-------------------:	|:-----------:	|
| 189.201.235.241 	| 13 	          | 2022-02-22 17:15:28 	| 2022-02-22 17:16:22 	| web     	    |


### 3. User agent Modifications 

| User Agent                                                                                                                               | IP Address      | First Seen | Last Seen |
|------------------------------------------------------------------------------------------------------------------------------------------|-----------------|------------|-----------|
| MercadoPago-iOS%2F2.249...iPhone15%2C2                                                                                                   | 200.159.9.139   | 01:55      | 01:58     |
| MercadoPago-iOS%2F2.252...iPhone15%2C2…                                                                                                  | 189.201.235.241 | 11:22      | 11:23     |
| MercadoPago-iOS%2F2.251...iPhone15%2C2…                                                                                                  | 189.201.234.220 | 11:38      | 11:41     |
| MercadoPago-iOS%2F2.251...iPhone15%2C2…                                                                                                  | 189.201.235.176 | 12:12      | 12:17     |
| MercadoPago-iOS%2F2.251...iPhone15%2C2…                                                                                                  | 189.201.234.8   | 12:31      | 12:31     |
| Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X)  AppleWebKit/605.1.15 (KHTML, likeGecko) Version/16.2 Mobile/15E148 Safari/604.1  | 189.201.235.241 | 17:15      | 17:16     |
| MercadoPago-iOS%2F2.251...iPhone15%2C2…                                                                                                  | 189.201.235.131 | 17:36      | 17:36     |
| MercadoPago-iOS%2F2.251...iPhone15%2C2…                                                                                                  | 189.96.19.153   | 21:48      | 21:48     |

### 4. Error Patterns
| Error Code | Count |
|------------|------|
| 404 | [count] |
| 500 | [count] |

## Log Analysis
From the filtering of the login logs from account `41072246`, it’s possible to filter out the legitimate accesses of the user through behavioral patterns and indicators.

Indicators of legitimate action:
- Consistent IP addresses `200.159.9.139` and `189.96.19.153`.
- User agent `“MercadoPago-iOS%2F2.251.2%20%28iPhone15%2C2%3B%20iOS%2016.2.0%29”`, which indicates the user was performing their accesses through a mobile device, an iPhone 15, at the time of the occurrence.
- Fake Tracking ID was also the same for all the legitimate accesses performed by the user `41072246` while utilizing the cited user agents and IP addresses: `a22bbb1c3008c9d68623319232a8928a3bd29eab19654f7615979efc8876ccaf`

Filtering out the indicators that could be classified as legitimate pattern of behavior for the user account, there’s also multiple indicators of compromise and unauthenticated accesses being performed to the same account. 

From `22/02/2022 - 15:43` to `16:22` the account presented unusual behavior, being accessed from web application by explicit login type. 

Potential indicators of compromise: 
- Multiple reauthentication were performed, resulting in failure (Value False).
- User agents rapidly changed IP address to `189.201.235.241` and user agents to `Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1`, then went back to the user
agents identified previously.
- FTID was also changed to `a070baf4fe520dd9564238513e8edc473dabdd673895c4a1896d57684440af83`.


## Conclusion

This log analysis has provided insights into potential security threats and system performance issues. Addressing the identified concerns will enhance system security and reliability. Further monitoring is recommended to track future trends and anomalies.



