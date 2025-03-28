import logging
from rich.panel import Panel
from rich.console import Console
from rich.text import Text 
from rich.rule import Rule 
from rich.console import Group 
from typing import Dict, List, Any
from collections import defaultdict 
from config import SeverityLevel, AttackType

# Format logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Get severities by color type
def get_severity_color(severity_enum: SeverityLevel) -> str:
    if not isinstance(severity_enum, SeverityLevel): return "white"
    if severity_enum in (SeverityLevel.CRITICAL, SeverityLevel.HIGH): return "red"
    if severity_enum == SeverityLevel.MEDIUM: return "yellow"
    return "green" # LOW and INFO

# Generate details for login anomalies
def format_signin_details(anomaly: Dict[str, Any]) -> str:
    primary_detail_parts = []
    anomaly_type = anomaly.get('type')
    if anomaly_type == "Failed Login Attempt":
        primary_detail_parts.append(f"Code: {anomaly.get('login_code', 'N/A')}")
    elif anomaly_type == "Login from Untrusted Device":
        primary_detail_parts.append(f"Device ID: {anomaly.get('device_id', 'N/A')}")
    elif anomaly_type == "Risky Reauthentication":
        primary_detail_parts.append(f"Risk: {anomaly.get('reauth_risk_value', 'N/A')}, Score: {anomaly.get('scoring_result', 'N/A')}")
    elif anomaly_type == "Suspicious Data Field Content":
         primary_detail_parts.append(anomaly.get('details_trigger', 'Indicator in data field'))
    else: primary_detail_parts.append(anomaly.get('details', 'Specifics unavailable'))
    primary_detail_str = ", ".join(filter(None, primary_detail_parts))

    data_context = anomaly.get('data_context')
    context_block_lines = []
    if data_context and isinstance(data_context, dict):
        context_block_lines.append("[dim]Context:[/dim]")
        for key, value in data_context.items():
            display_key = key.replace('_', ' ').title()
            context_block_lines.append(f"  • {display_key}: {value}")

    full_details = [primary_detail_str] + context_block_lines
    return "\n".join(full_details)

def generate_login_report(analysis_results: Dict[str, Any], report_title: str):
    if analysis_results is None:
        print("[bold red]Sign-in analysis results object is None. Cannot generate report.[/bold red]")
        logging.warning("generate_login_report called with None results.")
        return

    console = Console()

    # Extract data
    analysis_type = analysis_results.get('analysis_type', 'Sign-In Analysis')
    total_events = analysis_results.get('total_requests', 0) # Events processed
    anomalies = analysis_results.get('anomalies', []) # Unique patterns found

    # Report Header
    panel_title = f"[bold yellow]{report_title} ({analysis_type})[/bold yellow]"
    console.print(Panel(panel_title, title="Anomaly Detector Report", expand=True))

    # Log Overview
    console.print("\n--- Log Overview ---")
    console.print(f"Total Sign-In Events Processed/Analyzed: [bold]{total_events}[/bold]")

    # Anomaly Report 
    console.print("\n--- Anomaly Report ---")
    if not anomalies:
        console.print("[green]No specific anomalies or suspicious patterns detected.[/green]")
    else:
        # Group anomalies by IP
        anomalies_grouped_by_ip = defaultdict(list)
        for anomaly in anomalies:
            anomalies_grouped_by_ip[anomaly.get('ip', 'IP_Unknown')].append(anomaly)


        console.print(f"Found {len(anomalies)} distinct anomaly patterns across {len(anomalies_grouped_by_ip)} unique IPs.")

        # Iterate IPs
        ip_counter = 0
        for ip, ip_anomalies in anomalies_grouped_by_ip.items():
            if ip_counter > 0:
                console.print() # Add vertical space between IP panels

            panel_renderables = [] 
            first_anomaly_in_panel = True
            for anomaly in ip_anomalies:
                if not first_anomaly_in_panel:
                    # Anomalies separator
                    panel_renderables.append(Rule(style="dim")) # Add Rule object

                else:
                    first_anomaly_in_panel = False

                anomaly_text = Text()

                # Extract data for anomaly pattern
                anomaly_type_desc = anomaly.get('type', 'N/A')
                severity = anomaly.get('severity')
                severity_color = get_severity_color(severity) if isinstance(severity, SeverityLevel) else "white"
                severity_value_str = severity.value if isinstance(severity, SeverityLevel) else "N/A"
                details_str = format_signin_details(anomaly)
                first_detected_time = str(anomaly.get('time', 'N/A'))
                user_id = str(anomaly.get('user_id', 'N/A'))
                attack_types = anomaly.get('attack_types', [])
                attack_str = ", ".join([getattr(at, 'value', str(at)) for at in attack_types])
                log_row = anomaly.get('log_row', 'N/A')

                # Append Anomaly Patterns
                anomaly_text.append(f"  {'Anomaly Type:':<20}", style="dim")
                anomaly_text.append(f"{anomaly_type_desc}\n", style="white")

                anomaly_text.append(f"  {'Severity:':<20}", style="dim")
                anomaly_text.append(Text(f"{severity_value_str}\n", style=severity_color))

                anomaly_text.append(f"  {'Attack Types:':<20}", style="dim")
                anomaly_text.append(f"{attack_str}\n", style="white")

                anomaly_text.append(f"  {'User ID:':<20}", style="dim")
                anomaly_text.append(f"{user_id}\n", style="white")

                anomaly_text.append(f"  {'First Detected:':<20}", style="dim")
                anomaly_text.append(f"{first_detected_time}\n", style="white")

                anomaly_text.append(f"  {'Details:':<20}", style="dim")
                anomaly_text.append(f"{details_str}", style="white")

                # Add the completed Text object for this anomaly to the list
                panel_renderables.append(anomaly_text)

            # Create and print the panel 
            num_patterns = len(ip_anomalies)
            subtitle_text = f"({num_patterns} distinct pattern{'s' if num_patterns > 1 else ''} found)"

            console.print(
                Panel(
                    Group(*panel_renderables), 
                    title=f"[bold red]IP Address: {ip}[/bold red]",
                    subtitle=subtitle_text,
                    border_style="yellow", 
                    expand=True 
                )
            )
            ip_counter += 1

    console.print("\n[bold]Report Generation Complete.[/bold]")


