import logging
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from typing import Dict, List, Any
from config import SeverityLevel, AttackType 

# Format logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_severity_color(severity_enum: SeverityLevel) -> str:
    if not isinstance(severity_enum, SeverityLevel): return "white"
    if severity_enum in (SeverityLevel.CRITICAL, SeverityLevel.HIGH): return "red"
    if severity_enum == SeverityLevel.MEDIUM: return "yellow"
    return "green" # LOW and INFO

def generate_traffic_report(analysis_results: Dict[str, Any], report_title: str):
    if analysis_results is None:
        print("[bold red]Analysis results object is None. Cannot generate report.[/bold red]")
        logging.warning("generate_traffic_report called with None results.")
        return

    console = Console()

    # Extract data
    analysis_type = analysis_results.get('analysis_type', 'Traffic Analysis') 
    total_events = analysis_results.get('total_requests', 0)
    anomalies = analysis_results.get('anomalies', [])
    data_counters = analysis_results.get('data_counters', {})

    # Report Header
    panel_title = f"[bold yellow]{report_title} ({analysis_type})[/bold yellow]"
    console.print(Panel(panel_title, title="Anomaly Detector Report", expand=True))

    # Log Overview 
    console.print("\n--- Log Overview ---")
    console.print(f"Total Traffic Events Processed: [bold]{total_events}[/bold]")

    if 'status' in data_counters and data_counters['status']:
        failed_count = sum(count for status, count in data_counters['status'].items() if status and status >= '400')
        successful_count = sum(count for status, count in data_counters['status'].items() if status and '200' <= status < '300')
        console.print(f"HTTP Status >= 400: [bold red]{failed_count}[/bold red]")
        console.print(f"HTTP Status 200: [bold green]{successful_count}[/bold green]")

    if 'request_method' in data_counters and data_counters['request_method']:
        console.print("\nRequest Method Counts:")
        for method, count in data_counters['request_method'].most_common(5): console.print(f"  - {method}: {count}")
        if len(data_counters['request_method']) > 5: console.print("  ...")

    # Anomaly Report 
    console.print("\n--- Anomaly Report ---")
    if not anomalies:
        console.print("[green]No specific anomalies detected.[/green]")
    else:
        console.print(f"Found {len(anomalies)} potential anomaly events.")
        for anomaly in anomalies:
            ip = anomaly.get('ip') or anomaly.get('remote_addr', 'N/A') 
            anomaly_type_desc = anomaly.get('type', 'Anomaly')
            log_row = anomaly.get('log_row', 'N/A')
            severity = anomaly.get('severity')

            # Generate table
            anomaly_table = Table(show_header=False, box=None, padding=(0, 1))
            anomaly_table.add_column("Field", style="dim", width=20)
            anomaly_table.add_column("Value", style="white", overflow="fold")

            # Display Table Rows
            if 'time' in anomaly: anomaly_table.add_row("Time", str(anomaly['time']))
            if 'ip' in anomaly: anomaly_table.add_row("IP Address", str(anomaly['ip']))
            if 'user_id' in anomaly: anomaly_table.add_row("User ID", str(anomaly['user_id']))


            # Show fields relevant to traffic
            if 'request_method' in anomaly: anomaly_table.add_row("Method", str(anomaly['request_method']))
            if 'status' in anomaly: anomaly_table.add_row("Status", str(anomaly['status']))
            if 'request_uri' in anomaly: anomaly_table.add_row("Request URI", str(anomaly['request_uri']))

            # Exclude keys
            excluded_keys = {'remote_addr', 'type', 'log_row', 'time', 'user_id', 'severity', 'attack_types',
                             'request_method', 'status', 'request_uri'}
            for key, value in anomaly.items():
                if key in excluded_keys or value is None or value == '': continue
                display_key = key.replace("_", " ").title()
                if isinstance(value, dict): value_str = ", ".join([f"{k}: {v}" for k, v in value.items()])
                elif isinstance(value, list): value_str = ", ".join(map(str, value))
                else: value_str = str(value)
                anomaly_table.add_row(display_key, value_str)

            # Add Severity and Attack Types at the end
            if isinstance(severity, SeverityLevel):
                color = get_severity_color(severity)
                anomaly_table.add_row("Severity", f"[bold {color}]{severity.value}[/]")
            attack_types = anomaly.get('attack_types')
            if isinstance(attack_types, list):
                attack_str = ", ".join([getattr(at, 'value', str(at)) for at in attack_types])
                anomaly_table.add_row("Attack Types", attack_str)

            panel_title_text = f"[bold red]{anomaly_type_desc}[/bold red]"
            panel_border_color = get_severity_color(severity) if severity else "red"
            console.print(
                Panel(
                    anomaly_table, title=panel_title_text,
                    subtitle=f" Log Row: ~{log_row}",
                    border_style=panel_border_color, expand=False
                )
            )

    console.print("\n[bold]Report Generation Complete.[/bold]")

