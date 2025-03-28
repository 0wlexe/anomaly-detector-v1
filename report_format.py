# report_format.py

import logging
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from typing import Dict, List, Any
from collections import defaultdict # Needed for grouping
from config import SeverityLevel, AttackType

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_severity_color(severity_enum: SeverityLevel) -> str:
    """Maps SeverityLevel enum to Rich color names."""
    if not isinstance(severity_enum, SeverityLevel): return "white"
    if severity_enum in (SeverityLevel.CRITICAL, SeverityLevel.HIGH): return "red"
    if severity_enum == SeverityLevel.MEDIUM: return "yellow"
    return "green" # LOW and INFO

def format_signin_details(anomaly: Dict[str, Any]) -> str:
    """Creates a concise detail string based on sign-in anomaly type."""
    anomaly_type = anomaly.get('type')
    if anomaly_type == "Failed Login Attempt":
        return f"Code: {anomaly.get('login_code', 'N/A')}"
    elif anomaly_type == "Login from Untrusted Device":
        return f"Device ID: {anomaly.get('device_id', 'N/A')}"
    elif anomaly_type == "Risky Reauthentication":
        return f"Risk: {anomaly.get('reauth_risk_value', 'N/A')}, Score: {anomaly.get('scoring_result', 'N/A')}"
    elif anomaly_type == "Suspicious Data Field Content":
        return anomaly.get('details', 'N/A')
    # Add more specific formatting for other types if needed
    else:
        # Generic fallback if details field exists
        return anomaly.get('details', 'No specific details')


def generate_report(analysis_results: Dict[str, Any], report_title: str = "Log Analysis Report"):
    """Generates a console report from analysis results."""

    if analysis_results is None:
        print("[bold red]Analysis results object is None. Cannot generate report.[/bold red]")
        logging.warning("generate_report called with None results.")
        return

    console = Console()

    # Extract common data
    analysis_type = analysis_results.get('analysis_type', 'Unknown Analysis')
    total_events = analysis_results.get('total_requests', 0)
    anomalies = analysis_results.get('anomalies', [])
    data_counters = analysis_results.get('data_counters', {})

    # --- Report Header ---
    panel_title = f"[bold yellow]{report_title} ({analysis_type})[/bold yellow]"
    console.print(Panel(panel_title, title="Anomaly Detector Report", expand=False))

    # --- Log Overview ---
    console.print("\n--- Log Overview ---")
    console.print(f"Total Events Processed/Analyzed: [bold]{total_events}[/bold]")

    # Display specific counters if available
    # (Keep the counter display logic as it is)
    if 'status' in data_counters and data_counters['status']: # Primarily for Traffic
        failed_count = sum(count for status, count in data_counters['status'].items() if status and status >= '400')
        successful_count = sum(count for status, count in data_counters['status'].items() if status and '200' <= status < '300')
        console.print(f"HTTP Status >= 400: [bold red]{failed_count}[/bold red]")
        console.print(f"HTTP Status 2xx: [bold green]{successful_count}[/bold green]")
    if 'login_type' in data_counters and data_counters['login_type']: # For Sign-In
        console.print("\nLogin Type Counts (Processed Events):")
        for login_t, count in data_counters['login_type'].most_common(5): console.print(f"  - {login_t}: {count}")
        if len(data_counters['login_type']) > 5: console.print("  ...")
    if 'client_type' in data_counters and data_counters['client_type']: # For Sign-In
         console.print("\nClient Type Counts (Processed Events):")
         for client_t, count in data_counters['client_type'].most_common(5): console.print(f"  - {client_t}: {count}")
         if len(data_counters['client_type']) > 5: console.print("  ...")


    # --- Anomaly Report ---
    console.print("\n--- Anomaly Report ---")
    if not anomalies:
        console.print("[green]No specific anomalies or suspicious patterns detected based on current rules.[/green]")
    else:
        # --- OPTIMIZED OUTPUT for SIGN-IN ANALYSIS ---
        if analysis_type == 'Sign-In Analysis':
            # 1. Group anomalies by IP
            anomalies_grouped_by_ip = defaultdict(list)
            for anomaly in anomalies:
                ip = anomaly.get('ip')
                if ip: # Ensure IP exists
                    anomalies_grouped_by_ip[ip].append(anomaly)
                else:
                    # Handle anomalies without an IP if necessary (e.g., group under 'IP_Unknown')
                    anomalies_grouped_by_ip['IP_Unknown'].append(anomaly)

            console.print(f"Found {len(anomalies)} distinct anomaly patterns across {len(anomalies_grouped_by_ip)} unique IPs.")

            # 2. Iterate through each IP and create a table
            for ip, ip_anomalies in anomalies_grouped_by_ip.items():
                # Determine overall max severity for this IP for panel border color
                max_severity = SeverityLevel.INFO # Default
                for anom in ip_anomalies:
                    current_sev = anom.get('severity')
                    if isinstance(current_sev, SeverityLevel) and current_sev.value > max_severity.value: # Compare severity levels
                         max_severity = current_sev # Need custom comparison or numeric mapping if comparing enums directly
                         # Assuming SeverityLevel values are ordered logically or use integer mapping

                panel_border_color = get_severity_color(max_severity)

                # Create table for this IP's anomalies
                ip_table = Table(title=f"Detected Patterns", show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
                ip_table.add_column("Anomaly Type", style="cyan", max_width=30)
                ip_table.add_column("Severity", style="white")
                ip_table.add_column("Details", style="white", overflow="fold", max_width=50)
                ip_table.add_column("First Seen", style="dim", max_width=20) # Time of the first occurrence of this pattern
                ip_table.add_column("Attack Types", style="yellow", overflow="fold", max_width=30)
                # ip_table.add_column("Log Row", style="dim", max_width=8) # Optional

                # Populate the table with anomalies for this IP
                for anomaly in ip_anomalies: # ip_anomalies contains the unique patterns for this IP
                    severity = anomaly.get('severity')
                    severity_str = f"[{get_severity_color(severity)}]{severity.value}[/]" if isinstance(severity, SeverityLevel) else "N/A"

                    details_str = format_signin_details(anomaly) # Use helper function

                    time_str = str(anomaly.get('time', 'N/A'))
                    # log_row_str = str(anomaly.get('log_row', 'N/A')) # Optional

                    attack_types = anomaly.get('attack_types', [])
                    attack_str = ", ".join([at.value if hasattr(at, 'value') else str(at) for at in attack_types])

                    ip_table.add_row(
                        anomaly.get('type', 'Unknown Anomaly'),
                        severity_str,
                        details_str,
                        time_str,
                        attack_str,
                        # log_row_str # Optional
                    )

                # Print the panel containing the table for this IP
                console.print(
                    Panel(
                        ip_table,
                        title=f"[bold blue]IP Address: {ip}[/bold blue]",
                        border_style=panel_border_color,
                        expand=False
                    )
                )

        # --- ORIGINAL OUTPUT for TRAFFIC ANALYSIS (or fallback) ---
        else: # Keep original format for Traffic Analysis or if type unknown
            console.print(f"Found {len(anomalies)} potential anomaly events.")
            for anomaly in anomalies:
                ip = anomaly.get('ip') or anomaly.get('remote_addr', 'N/A') # Get IP based on possible field names
                anomaly_type_desc = anomaly.get('type', 'Anomaly')
                log_row = anomaly.get('log_row', 'N/A')

                anomaly_table = Table(show_header=False, box=None, padding=(0, 1))
                anomaly_table.add_column("Field", style="dim", width=20)
                anomaly_table.add_column("Value", style="white", overflow="fold")

                # Display key fields first
                if 'time' in anomaly: anomaly_table.add_row("Time", str(anomaly['time']))
                if 'user_id' in anomaly: anomaly_table.add_row("User ID", str(anomaly['user_id']))
                if analysis_type == 'Traffic Analysis': # Show fields relevant to traffic
                     if 'request_method' in anomaly: anomaly_table.add_row("Method", str(anomaly['request_method']))
                     if 'status' in anomaly: anomaly_table.add_row("Status", str(anomaly['status']))
                     if 'request_uri' in anomaly: anomaly_table.add_row("Request URI", str(anomaly['request_uri']))


                # Add remaining rows dynamically
                for key, value in anomaly.items():
                    # Skip already added or less important fields
                    if key in ['ip', 'remote_addr', 'type', 'log_row', 'time', 'user_id', 'severity', 'attack_types',
                               'request_method', 'status', 'request_uri'] or value is None or value == '':
                        continue
                    display_key = key.replace("_", " ").title()
                    if isinstance(value, dict): value_str = ", ".join([f"{k}: {v}" for k, v in value.items()])
                    elif isinstance(value, list): value_str = ", ".join(map(str, value))
                    else: value_str = str(value)
                    anomaly_table.add_row(display_key, value_str)

                # Add Severity and Attack Types at the end
                severity = anomaly.get('severity')
                if isinstance(severity, SeverityLevel):
                    color = get_severity_color(severity)
                    anomaly_table.add_row("Severity", f"[bold {color}]{severity.value}[/]")
                attack_types = anomaly.get('attack_types')
                if isinstance(attack_types, list):
                    attack_str = ", ".join([at.value if hasattr(at, 'value') else str(at) for at in attack_types])
                    anomaly_table.add_row("Attack Types", attack_str)

                panel_title_text = f"[bold red]{anomaly_type_desc}[/bold red]"
                panel_border_color = get_severity_color(severity) if severity else "red"
                console.print(
                    Panel(
                        anomaly_table, title=panel_title_text,
                        subtitle=f"IP: {ip} | Log Row: ~{log_row}",
                        border_style=panel_border_color, expand=False
                    )
                )

    console.print("\n[bold]Report Generation Complete.[/bold]")