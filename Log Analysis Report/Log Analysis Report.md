# Log Analysis Report 
A user has reported unusual behavior coming from their account, according to the user there were transactions they did not recognize. 
The objective of this report is to compile relevant information and identify patterns of behavior that might indicate if the user may have been compromised. 

## Log Overview
  - **Transaction account ID:** `41072246`
  - **Date Range of the logs:** `2022-12-11 21:55 - 2022-12-27 17:00`
  - **Total Log Entries Analyzed:** `89`

## Analysis Methodology

This analysis was conducted using custom scripts and manual review. Logs were parsed and filtered to help in the co-validation of User and entity behavior analytics (UEBA), 
which relates to a set of patterns, anomalies, and potential security threats to user accounts and devices.

## Log Analysis
Through the analysis of the logs from account `41072246`, it was possible to identify multiple patterns of anomalous behavior, indicating a potential account takeover. 

Multiple failed attempts were identified (challenge_failure) from attempting to login using invalid password, by IP addresses `200.159.9.139`, `189.201.235.241`, `189.201.234.220`.

```![screenshot](imageFolder/screenshot.png)```

Multiple reauthentications were performed, resulting in failure (Value False).


```![screenshot](imageFolder/screenshot.png)```

Multiple anomalies related to the application's service level were identified by the system, as flagged by `app_sl_change_anom` operation. 
This operation indicates an unusual, unexpected, or suspicious change occurred in the security level.

```![screenshot](imageFolder/screenshot.png)```


A security measurement `ato_protection_addition` was implemented into the account after the detected anomalous behavior, to ensure its protection.

```![screenshot](imageFolder/screenshot.png)```

This log indicates that the account was flagged for potential Account Takeover (ATO) risk because it is being accessed exclusively via mobile. 
As a result, additional ATO protection measures were added to the account to mitigate the risk.

Multiple `transaction_score` events were flagged with abuse scoring. This suggests the transaction is being flagged as potentially abusive. 

```![screenshot](imageFolder/screenshot.png)```

Multiple accesses being performed by untrusted devices. 

```![screenshot](imageFolder/screenshot.png)```


### Detected IP Addresses 

Multiple IP addresses were identified accessing the account, making multiple requests per day. 
  
| IP Address 	      | Occurrences 	| First Seen 	          | Last Seen 	          | Client Type   |
|:---------------:	|:-----------:	|:-------------------:	|:-------------------:	|:-----------:	|
| 189.201.235.176 	| 20 	          | 2022-02-22 12:12:54 	| 2022-02-22 12:17:33 	| mobile     	  |
| 200.159.9.139 	  | 18 	          | 2022-02-22 01:55:22 	| 2022-02-22 01:58:15 	| mobile 	      |
| 189.201.234.220 	| 14 	          | 2022-02-22 11:38:57 	| 2022-02-22 11:41:53 	| mobile 	      |
| 189.96.19.153 	  | 6 	          | 2022-02-22 21:48:03 	| 2022-02-22 21:48:41 	| mobile 	      |
| 189.201.235.241 	| 6 	          | 2022-02-22 11:22:35 	| 2022-02-22 11:23:13 	| mobile 	      |
| 189.201.235.131 	| 6 	          | 2022-02-22 17:36:23 	| 2022-02-22 17:36:58 	| mobile 	      |
| 189.201.234.8 	  | 5 	          | 2022-02-22 12:31:26 	| 2022-02-22 12:31:26 	| mobile 	      |

Analysis of Anomalous Behavior and Potential Attack Patterns:

#### IP Address: 200.159.9.139
  -  Exhibited suspicious patterns such as:
     - Face validation requested 4 times.
```![screenshot](imageFolder/screenshot.png)```


     - Access from untrusted device(s) on 13 occurences.
     - Access from new mobile domain detected 18 times.
     - By extracting from the ‘data’ field of the log, multiple completed elements were identified, these are indicators that the actor was successful at authenticating in the account with only password, then authenticating with face validation and password, and finally only authenticating only with face validation.
```![screenshot](imageFolder/screenshot.png)```

     - The requisitions from this IP address are made within seconds from 21:55 to 21:58, which presents automated behavior.
     - From 21:55 to 21:56 - The account was given additional protection to account takeover due to the detected behavior from this IP address, as presented below. 
```![screenshot](imageFolder/screenshot.png)```


  - Potential attack patterns:
    - **Potential Brute-Force/Credential Stuffing Attack:** Multiple failed face validation attempts combined with high-risk operations suggest an attacker trying various credentials.
    - **Anomalous Activity and Compromised Device (Anomalous Behavior):** The 'app_sl_change_anom' event combined with an untrusted device might indicate a compromised device attempting unauthorized actions.
    - **Settings Tampering (Anomalous Behavior):** The `app_sl_change_anom` events was triggered by this IP address, and shows the the settings migh have been tampered.

#### IP Address: 189.201.234.220
  -  Exhibited suspicious patterns such as:
    - Access from untrusted device(s) on 10 occurences.
     Face validation requested 2 times.
  - Access from new mobile domain 14 times.
  - Access from mobile 14 times.
  - Declined elements detected 9 times.

  - Potential attack patterns:
    - Brute Force/Credential Stuffing: High number of untrusted device access attempts combined with declined authentication elements suggests attempts to guess credentials.
    - Anomalous Behavior/Potential Account Takeover: Frequent access from a new mobile domain, coupled with face validation requests, could indicate a potential account takeover attempt.


## Key Findings

### 1. Anomalous Activity
- Potential Brute-Force Attempts Detected:
```
  - User ID: 41072246.0, IP: 189.201.235.176, Attempts: 20, Reauthentication: True
  - User ID: 41072246.0, IP: 189.201.235.241, Attempts: 19, Reauthentication: True
  - User ID: 41072246.0, IP: 200.159.9.139, Attempts: 18, Reauthentication: False
  - User ID: 41072246.0, IP: 189.201.234.220, Attempts: 14, Reauthentication: False
  - User ID: 41072246.0, IP: 189.201.235.131, Attempts: 6, Reauthentication: True
  - User ID: 41072246.0, IP: 189.96.19.153, Attempts: 6, Reauthentication: True
```


## Conclusion
The account presents multiple indicators of risky behavior, as demonstrated through extracted logs, 


