import pandas as pd
import json
import sys

def analyze_logs(csv_file):
    """
    Analyzes logs from a CSV file to identify anomalous behavior and potential attack patterns
    based on IP addresses accessing a specific user account.

    Args:
        csv_file (str): The path to the CSV file containing the logs.
    """

    try:
        df = pd.read_csv(csv_file)
    except FileNotFoundError:
        print(f"Error: File not found: {csv_file}")
        return

    # Filter logs for the specified user ID
    user_logs = df[df['transaction_user_id'] == 41072246].copy()  # Create a copy to avoid SettingWithCopyWarning

    # Function to extract specific data fields from the 'data' column
    def extract_data_fields(data_string):
        try:
            data_json = json.loads(data_string)
            return pd.Series({
                'trusted_device': data_json.get('trusted_device'),
                'code': data_json.get('code'),
                'new_mobile_domain': data_json.get('new_mobile_domain'),
                'client_type': data_json.get('client_type'),
                'declined_elements': data_json.get('declined_elements'),
                'sfa_removal': data_json.get('sfa_removal'),
                'device_id': data_json.get('remote_id', None) # Corrected to remote_id
            })
        except (json.JSONDecodeError, TypeError):
            return pd.Series({
                'trusted_device': None,
                'code': None,
                'new_mobile_domain': None,
                'client_type': None,
                'declined_elements': None,
                'sfa_removal': None,
                'device_id': None
            })

    # Apply the extraction function to the 'data' column
    user_logs[['trusted_device', 'code', 'new_mobile_domain', 'client_type', 'declined_elements', 'sfa_removal', 'device_id']] = user_logs['data'].apply(extract_data_fields)


    # Identify unique IP addresses associated with the user
    unique_ips = user_logs['ip'].unique()

    print("Unique IP Addresses accessing user account 41072246:")
    for ip in unique_ips:
        print(f"- {ip}")

    # Analyze each IP address for anomalies and potential attack patterns
    print("\nAnalysis of Anomalous Behavior and Potential Attack Patterns by IP Address:")
    for ip in unique_ips:
        ip_logs = user_logs[user_logs['ip'] == ip]
        print(f"\n--- IP Address: {ip} ---")

        # Anomaly detection logic (customize as needed)
        anomalies = []

        # Example 1: Check for untrusted devices
        untrusted_devices = ip_logs[ip_logs['trusted_device'] == False]
        untrusted_count = len(untrusted_devices)
        if untrusted_count > 0:
            anomalies.append(f"  - Access from untrusted device(s) on {untrusted_count} occurences.")

        # Example 2: Check for face validation requests
        face_validation_requests = ip_logs[ip_logs['code'] == 'face_validation']
        face_validation_count = len(face_validation_requests)
        if face_validation_count > 0:
            anomalies.append(f"  - Face validation requested {face_validation_count} times.")

        # Example 3: Check for new mobile domain access
        new_mobile_domain_access = ip_logs[ip_logs['new_mobile_domain'] == True]
        new_mobile_domain_count = len(new_mobile_domain_access)
        if new_mobile_domain_count > 0:
            anomalies.append(f"  - Access from new mobile domain {new_mobile_domain_count} times.")

        # Example 4: check for client_type=mobile
        mobile_access = ip_logs[ip_logs['client_type'] == 'mobile']
        mobile_count = len(mobile_access)
        if mobile_count > 0:
            anomalies.append(f"  - Access from mobile {mobile_count} times.")

        # Example 5: Check for declined elements (if declined_elements is a list)
        declined_elements_logs = ip_logs[ip_logs['declined_elements'].astype(str) != '[]'] #Handles empty lists or NaNs as strings
        declined_elements_count = len(declined_elements_logs)
        if declined_elements_count > 0:
            anomalies.append(f"  - Declined elements detected {declined_elements_count} times.")

        # Example 6: check for sfa_removal
        sfa_removal_logs = ip_logs[ip_logs['sfa_removal'] == True]
        sfa_removal_count = len(sfa_removal_logs)
        if sfa_removal_count > 0:
            anomalies.append(f"  - sfa_removal detected {sfa_removal_count} times.")



        if anomalies:
            for anomaly in anomalies:
                print(anomaly)

            # Correlate anomalies with potential attack patterns
            attack_patterns = []

            # Brute Force/Credential Stuffing
            if untrusted_count > 5 and declined_elements_count > 3:  # Adjust thresholds as needed
                attack_patterns.append({
                    "attack_type": "Brute Force/Credential Stuffing",
                    "reason": "High number of untrusted device access attempts combined with declined authentication elements suggests attempts to guess credentials."
                })

            # Anomalous Behavior
            if new_mobile_domain_count > 10 and face_validation_count > 1: #Adjust thresholds as needed
                attack_patterns.append({
                    "attack_type": "Anomalous Behavior/Potential Account Takeover",
                    "reason": "Frequent access from a new mobile domain, coupled with face validation requests, could indicate a potential account takeover attempt."
                })

            if attack_patterns:
                print("\n  - Potential attack patterns:")
                for pattern in attack_patterns:
                    print(f"    - {pattern['attack_type']}: {pattern['reason']}")
            else:
                print("  - No specific attack patterns detected based on the defined criteria.")
        else:
            print("  - No anomalies detected for this IP address based on the defined criteria.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <log_file.csv>")
    else:
        log_file = sys.argv[1]
        analyze_logs(log_file)