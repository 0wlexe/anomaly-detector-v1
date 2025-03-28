import os, sys, logging
from rich import print
from config import FULL_TRAFFIC_LOG_PATH, FULL_LOGIN_LOG_PATH, ANOMALY_RULES
from traffic_analysis import analyze_traffic_logs  
from login_analysis import analyze_login_logs 
from login_report import generate_login_report
from traffic_report import generate_traffic_report

def main():
    # Logging Format logs
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    print("\n--- ANOMALY DETECTOR ---")

    # Input Analysis Type
    while True:
        print("\nWhat type of log would you like to analyze?")
        print("  1. Web traffic logs")
        print("  2. Sign-In Logs")

        choice = input("\nEnter choice (1 or 2): ").strip()
        if choice == '1': analysis_type = 'traffic'; break
        elif choice == '2': analysis_type = 'signin'; break
        else: print("[red]Invalid choice. Please enter 1 or 2.[/red]")

    # Determine Analysis 
    analysis_func = None; report_func = None;
    report_title = "Log Analysis Report"; args = []; sugg_fname = ""
    # Gather data from Traffic Analysis and generate a report
    if analysis_type == 'traffic':
        analysis_func = analyze_traffic_logs
        report_func = generate_traffic_report 
        report_title = "Traffic Log Analysis Report"
        args = [ANOMALY_RULES]; sugg_fname = os.path.basename(FULL_TRAFFIC_LOG_PATH)
        print(f"\nSelected: Traffic Analysis.")
    else: # Gather data from signin analysis and generate a report
        analysis_func = analyze_login_logs
        report_func = generate_login_report # Use login report func
        report_title = "Sign-In Log Analysis Report"
        args = []; sugg_fname = os.path.basename(FULL_LOGIN_LOG_PATH)
        print(f"\nSelected: Sign-In Analysis.")

    # File path input
    log_file_path = None
    while True:
        prompt = f"Enter path to the {analysis_type} log file (e.g., {sugg_fname}): "
        fpath = input(prompt).strip().strip("'\"")
        if not fpath: print("[yellow]Path cannot be empty.[/yellow]"); continue
        if os.path.exists(fpath):
            if os.path.isfile(fpath): log_file_path = fpath; print(f"Using log file: [cyan]{log_file_path}[/cyan]"); break
            else: print(f"[red]Error: Path exists but is a directory.[/red]")
        else: print(f"[red]Error: File not found at '{fpath}'.[/red]")

    # Require transaction_user_id if signin analysis 
    target_user_id = None
    if analysis_type == 'signin':
        while True:
            target_user_id = input("Enter the specific 'transaction_user_id' to analyze (Required): ").strip()
            if target_user_id: print(f"Filtering analysis for user ID: [yellow]{target_user_id}[/yellow]"); break
            else: print("[yellow]User ID is required for Sign-In analysis.[/yellow]")
        args.append(target_user_id) 

    # Demonstrate the Anomaly detector is analyzing
    print(f"\nStarting analysis of '{os.path.basename(log_file_path)}'...")
    analysis_results = None
    try:
        analysis_results = analysis_func(log_file_path, *args)
    except Exception as e:
        logging.exception("Critical error during analysis:")
        print(f"[bold red]Analysis failed. Check logs. Exiting.[/bold red]")
        return

    # Generate report
    if analysis_results is not None:
        print(f"Analysis complete. Generating report...")
        try:
            final_report_title = report_title
            if analysis_type == 'signin' and target_user_id:
                final_report_title += f" for User ID: {target_user_id}"
            # Call the chosen specific report function
            report_func(analysis_results, report_title=final_report_title)
        except Exception as e:
             logging.exception("Critical error during report generation:")
             print(f"[bold red]Report generation failed. Check logs.[/bold red]")
    else:
        print("[yellow]Analysis returned no results (None). Report cannot be generated.[/yellow]")

    print("\n--- Analysis Finished ---")

if __name__ == "__main__":
    main()
