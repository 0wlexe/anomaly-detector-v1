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

### 1. Anomalous Activity
Examination of the logs from account `41072246` confirms multiple patterns of anomalous behavior strongly suggesting a potential account takeover, as supported by the following detections:

Multiple login failures (challenge_failure) due to invalid passwords were observed from various IP addresses:
- `200.159.9.139`, `189.201.235.241`, `189.201.234.220`.

![screenshot](imgs/01_challenge_failure.png)


The system detected multiple anomalies in the application's service level, flagged by the `app_sl_change_anom` operation. This indicates an unusual, unexpected, or 
suspicious change in the service level.

![screenshot](imgs/02_app_sl_change_anom.png)





A security measurement `ato_protection_addition` was implemented into the account after the detected anomalous behavior, to ensure its protection.

```![screenshot](imageFolder/screenshot.png)```

This log indicates that the account was flagged for potential Account Takeover (ATO) risk because multiple suspicious actions are being performed such as: 
the account being accessed exclusively via mobile, second factor authentication configurations being actively changed during a short period of time.

As a result, additional ATO protection measures were added to the account to mitigate the risk. However, as this action was taken after the acess, 
the actor remained accessing the account and performing modifications. 



Multiple `transaction_score` events were flagged with abuse scoring. This suggests the transaction is being flagged as potentially abusive. 

```![screenshot](imageFolder/screenshot.png)```

Multiple accesses being performed by untrusted devices. 

```![screenshot](imageFolder/screenshot.png)```


### 2. IP Activity

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
  -  Exhibited alarming suspicious patterns such as:
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



### 3. Final considerations, and mitigation points. 
Given the potential attack and the way it has escalonated with multiple suspicious IP addresses, it's secure to gather it as evidence that the security controls might not have
been strong enough for that account. Making it necessary to increase authentication requirements if access patterns appear suspicious.

The logs indicate that while the account may have been compromised, the system successfully identified anomalous behavior in real time. This presents an opportunity for the 
organization to enhance its security posture by implementing stricter policies, such as automatically blocking accounts when multiple indicators of fraudulent activity occur 
within a short timeframe. Proactively leveraging these insights can help mitigate future threats and reinforce overall account protection.

