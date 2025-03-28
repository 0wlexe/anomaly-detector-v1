import re, csv, logging, json
from collections import Counter, defaultdict
from typing import Dict, List, Set, Tuple, Any, Optional
from config import SeverityLevel, AttackType

# Format Logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SIGNIN_LOG_FIELDS = {
    'time', 'transaction_user_id', 'site_id', 'login_type', 'client_type', 'transaction_track',
    'code', 'ip', 'operation_id', 'reauthentication', 'tracking_id', 'scoring_type',
    'scoring_result', 'reauth_risk', 'ftid', 'user_agent', 'user_agent_raw', 'user_tags',
    'user_internal_tags', 'data', 'year', 'month', 'day', 'hour'
}

# Fields from 'data' column
DATA_FIELD_KEYS = [
    'trusted_device', 'code', 'new_mobile_domain', 'client_type',
    'declined_elements', 'sfa_removal', 'device_id'
]

def parse_data_field(data_string: str) -> Dict[str, str]:
    parsed_data = {}
    if not data_string or data_string.lower() in ['none', '{}', '""', "null"]: return parsed_data
    try: # JSON attempt
        potential_json = data_string.replace("'", '"').replace('True', 'true').replace('False', 'false').replace('None', 'null')
        if potential_json.startswith('"') and potential_json.endswith('"'): potential_json = potential_json[1:-1]
        if not potential_json.strip().startswith('{'): potential_json = '{' + potential_json + '}'
        data_dict = json.loads(potential_json); #print(f"JSON OK: {data_dict}")
        for key in DATA_FIELD_KEYS:
            if key in data_dict: parsed_data[key] = str(data_dict[key])
        return parsed_data
    except json.JSONDecodeError: pass # Fall through
    except Exception as e: logging.warning(f"JSON parse err: {e}")
    try: # Regex fallback
        pattern = r"['\"]?([\w_]+)['\"]?\s*:\s*(?:['\"]([^'\"]*)['\"]|([^,'\"}\s]+))"
        matches = re.findall(pattern, data_string); #print(f"Regex found: {matches}")
        for key, quoted_value, unquoted_value in matches:
            if key in DATA_FIELD_KEYS:
                value = quoted_value if quoted_value else unquoted_value
                parsed_data[key] = value.strip()
    except Exception as e: logging.warning(f"Regex parse err: {e}")
    return parsed_data

# Filter User ID and correlated anomalies
def analyze_login_logs(log_file_path: str, target_user_id: Optional[str] = None) -> Dict[str, Any]:

    anomalies_by_ip: Dict[str, List[Dict]] = defaultdict(list)
    detected_patterns_per_ip: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)
    data_counters = {'login_type': Counter(), 'client_type': Counter(), 'scoring_result': Counter(), 'reauth_risk': Counter()}
    total_logins_processed = 0; total_logins_in_file = 0; processed_ips = set()

    # Try filtering file
    try:
        with open(log_file_path, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            if reader.fieldnames is None: return None # Empty file

            if not SIGNIN_LOG_FIELDS.issubset(reader.fieldnames):
                missing = SIGNIN_LOG_FIELDS - set(reader.fieldnames)
                logging.warning(f"Sign-in log missing expected fields: {missing}")

            for row_num, row in enumerate(reader):
                total_logins_in_file += 1
                current_user_id = row.get('transaction_user_id')

                if target_user_id and current_user_id != target_user_id:
                    continue 

                # Skip processed rows without IP
                total_logins_processed += 1 
                ip = row.get('ip')
                if not ip: continue 

                processed_ips.add(ip)
                log_data = {field: row.get(field) for field in SIGNIN_LOG_FIELDS}

                # Update Counters
                lt = log_data.get('login_type'); ct = log_data.get('client_type')
                sc = log_data.get('scoring_result'); rr = log_data.get('reauth_risk')
                if lt: data_counters['login_type'][lt] += 1;
                if ct: data_counters['client_type'][ct] += 1;
                if sc: data_counters['scoring_result'][sc] += 1;
                if rr: data_counters['reauth_risk'][rr] += 1;

                # Anomaly Detection
                time=log_data.get('time','N/A'); user_id=log_data.get('transaction_user_id','N/A');
                code=log_data.get('code','N/A'); reauth=log_data.get('reauthentication','').lower()=='true';
                reauth_risk=log_data.get('reauth_risk'); score=log_data.get('scoring_result');
                data_str=log_data.get('data',''); parsed_data = parse_data_field(data_str);
                base_info = {'ip':ip,'time':time,'user_id':user_id,'log_row':row_num + 1}

                # Rules (Simplified add logic)
                def add_anomaly(pattern_tuple, anomaly_dict):
                    if pattern_tuple not in detected_patterns_per_ip[ip]:
                        anomalies_by_ip[ip].append({**base_info, **anomaly_dict})
                        detected_patterns_per_ip[ip].add(pattern_tuple)

                # R1: Failed Login
                if code and not code.startswith('2') and code != 'N/A': add_anomaly(("Failed", code), {'type':"Failed Login",'login_code':code,'details':f"Fail code: {code}",'severity':SeverityLevel.MEDIUM,'attack_types':[AttackType.FAILED_LOGIN_ATTEMPT]})
                # R2: Untrusted Device
                if parsed_data.get('trusted_device','').lower()=='false': add_anomaly(("Untrusted", ""), {'type':"Untrusted Device",'device_id':parsed_data.get('device_id','N/A'),'details':"Device untrusted",'severity':SeverityLevel.LOW,'attack_types':[AttackType.UNTRUSTED_DEVICE_LOGIN]})
                # R3: Risky Reauth
                if reauth and reauth_risk and reauth_risk not in ['0','low','',None]: add_anomaly(("RiskyReauth", reauth_risk), {'type':"Risky Reauth",'reauth_risk_value':reauth_risk,'scoring_result':score,'details':f"Risk: {reauth_risk}",'severity':SeverityLevel.MEDIUM,'attack_types':[AttackType.RISKY_REAUTHENTICATION]})
                # R4: Suspicious Data
                sus_data = [fld for fld,txt in [('face_validation','face_validation code'),('new_mobile_domain: true','new_mobile_domain: true'),('declined_elements','declined: {v}'), ('sfa_removal','sfa_removal')] if (v:=parsed_data.get(fld.split(':')[0])) is not None and (fld.split(':')[0]==fld or str(v).lower()=='true')]
                if sus_data:
                    details = "; ".join(sus_data); sev = SeverityLevel.INFO; attk = [AttackType.SUSPICIOUS_DATA_FIELD];
                    if "declined" in details or "sfa_removal" in details: sev = SeverityLevel.MEDIUM; attk.append(AttackType.MULTI_FACTOR_ISSUES);
                    add_anomaly(("SusData", details), {'type':"Suspicious Data",'details':details,'parsed_data':{k:parsed_data[k] for k in DATA_FIELD_KEYS if k in parsed_data},'severity':sev,'attack_types':attk})

    except FileNotFoundError: logging.error(f"Sign-in log file not found: {log_file_path}"); return None
    except Exception as e: logging.exception("Error during sign-in log analysis:"); return None

    all_anomalies = sorted([a for lst in anomalies_by_ip.values() for a in lst], key=lambda x: (x.get('ip',''), x.get('time','')))
    filter_msg = f" for user ID '{target_user_id}'" if target_user_id else " (all users)"
    logging.info(f"Sign-in analysis complete{filter_msg}. Processed {total_logins_processed}/{total_logins_in_file} events from {len(processed_ips)} IPs. Found {len(all_anomalies)} unique anomaly patterns.")

    return {'data_counters':data_counters,'anomalies':all_anomalies,'total_requests':total_logins_processed,'analysis_type':'Sign-In Analysis'}