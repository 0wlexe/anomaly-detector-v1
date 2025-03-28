import re, csv, logging, json
from collections import Counter
from typing import Dict, List, Set, Tuple, Any, Optional
from config import SeverityLevel, AttackType, ANOMALY_RULES

# Format Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

ESSENTIAL_TRAFFIC_FIELDS = {'request_uri', 'http_user_agent', 'status', 'remote_addr'}
TRAFFIC_LOG_FIELDS = [
    'user_id', 'time', 'proxy_host', 'status', 'http_host', 'request_uri', 'server_protocol',
    'request_method', 'request_time', 'http_referer', 'http_user_agent', 'http_x_public', 'http_x_request_id', 'http_connection',
    'http_accept_encoding', 'http_accept', 'http_content_type','remote_addr',
    'sent_http_connection', 'sent_http_location', 'sent_http_content_encoding', 'upstream_status','connection', 'connection_requests', 'source_ip'
]

# Gather anomalies
def analyze_traffic_logs(log_file_path: str, anomaly_rules: List[Dict]) -> Dict[str, Any]:
    data_counters = {
        'status': Counter(), 'request_method': Counter(), 'remote_addr': Counter(),
        'http_user_agent': Counter(), 'server_protocol': Counter(),
    }
    anomalies = []
    total_requests = 0

    try:
        with open(log_file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            if reader.fieldnames is None:
                logging.error(f"Traffic log CSV file empty/no header: {log_file_path}")
                return None

            if not ESSENTIAL_TRAFFIC_FIELDS.issubset(reader.fieldnames):
                 missing = ESSENTIAL_TRAFFIC_FIELDS - set(reader.fieldnames)
                 logging.warning(f"Traffic log missing essential fields for rules: {missing}. Results may be incomplete.")

            for row_num, row in enumerate(reader):
                total_requests += 1
                # Extract only essential fields 
                request_data = {field: row.get(field) for field in ESSENTIAL_TRAFFIC_FIELDS | {'request_method', 'server_protocol', 'time', 'user_id'}}

                # Update Counters 
                status = request_data.get('status'); method = request_data.get('request_method')
                remote_ip = request_data.get('remote_addr'); ua = request_data.get('http_user_agent')
                protocol = request_data.get('server_protocol')
                if status: data_counters['status'][status] += 1
                if method: data_counters['request_method'][method] += 1
                if remote_ip: data_counters['remote_addr'][remote_ip] += 1
                if ua: data_counters['http_user_agent'][ua] += 1 # Can grow large
                if protocol: data_counters['server_protocol'][protocol] += 1

                # Anomaly Detection
                uri = request_data.get('request_uri', '')

                for rule in anomaly_rules:
                    triggered = False
                    # Base details - Start with essential fields for the report
                    anomaly_details = {
                        'ip': remote_ip, 'time': request_data.get('time'),
                        'user_id': request_data.get('user_id'), 'status': status,
                        'request_method': method, 'request_uri': uri,
                        'http_user_agent': ua, 'log_row': row_num + 1,
                        # Add rule info
                        'type': rule['description'], 'severity': rule['severity'],
                        'attack_types': rule['attack_types']
                    }

                    # Pattern-based rules
                    if 'pattern' in rule:
                        field_to_check = None
                        if rule['type'] in ['sql_injection', 'xss_attack', 'file_inclusion', 'command_injection']: field_to_check = uri
                        elif rule['type'] in ['bot_activity', 'brute_force_login_ua']: field_to_check = ua if rule['type'] == 'bot_activity' else (str(ua) + " " + str(uri))

                        if field_to_check and re.search(rule['pattern'], str(field_to_check), re.IGNORECASE):
                             triggered = True
                             match = re.search(rule['pattern'], str(field_to_check), re.IGNORECASE)
                             anomaly_details['matched_pattern'] = rule['pattern']

                    # Threshold-based rules
                    elif rule['type'] == 'high_error_rate' and 'status_code' in rule and 'threshold' in rule:
                        if status == rule['status_code'] and data_counters['status'].get(status, 0) > rule['threshold']:
                              triggered = True
                              anomaly_details['details'] = f"Status {status} count ({data_counters['status'].get(status, 0)}) > threshold ({rule['threshold']})"

                    if triggered:
                        anomalies.append(anomaly_details)

    except FileNotFoundError:
        logging.error(f"Traffic log file not found: {log_file_path}")
        return None
    except Exception as e:
        logging.exception("Error during traffic log analysis:") # Log full traceback
        return None

    logging.info(f"Traffic analysis complete. Processed {total_requests} requests. Found {len(anomalies)} anomaly events.")

    return {
        'data_counters': data_counters,
        'anomalies': anomalies,
        'total_requests': total_requests,
        'analysis_type': 'Traffic Analysis'
    }
