import gradio as gr
import pandas as pd
import json
import os
import time
from log_generator import LogGenerator
from rag_engine import RAGEngine

# Initialize components
log_gen = LogGenerator()
rag = RAGEngine()

# State variables
logs_history = []
suspicious_history = []
is_running = False
is_analyzing = False
last_analyzed_count = 0

SUSPICIOUS_FILE = "suspicious_events.json"

def save_suspicious_events():
    try:
        with open(SUSPICIOUS_FILE, 'w') as f:
            json.dump(suspicious_history, f, indent=2)
    except Exception as e:
        print(f"Error saving suspicious events: {e}")

def load_suspicious_events():
    global suspicious_history
    if os.path.exists(SUSPICIOUS_FILE):
        try:
            with open(SUSPICIOUS_FILE, 'r') as f:
                suspicious_history = json.load(f)
            print(f"Loaded {len(suspicious_history)} suspicious events.")
        except Exception as e:
            print(f"Error loading suspicious events: {e}")

def initialize_system():
    global logs_history, last_analyzed_count
    
    # Load suspicious history
    load_suspicious_events()
    
    # Check if DB has data
    try:
        count = rag.get_log_count()
    except Exception as e:
        print(f"Error checking log count: {e}")
        count = 0
        
    if count > 0:
        print(f"Found {count} existing logs in DB. Loading them...")
        existing_logs = rag.get_recent_logs(limit=100)
        logs_history.extend(existing_logs)
        # Reverse to keep chronological order in history list (oldest first) for appending new ones
        # But for display we want newest first.
        # logs_history should probably be kept chronological (append new at end).
        # We'll handle display sorting in format_logs_for_display.
        logs_history.sort(key=lambda x: x['LogID'] if isinstance(x['LogID'], int) else 0)
        print(f"Loaded {len(existing_logs)} logs from history.")
    else:
        print("Generating initial historical logs...")
        initial_logs = log_gen.generate_initial_logs(100)
        rag.ingest_logs(initial_logs)
        logs_history.extend(initial_logs)
        print(f"Ingested {len(initial_logs)} logs.")
    
    last_analyzed_count = len(logs_history)
    return format_logs_for_display(logs_history[-20:])

def format_logs_for_display(logs):
    # Convert list of dicts to DataFrame for display
    if not logs:
        return pd.DataFrame()
    
    flattened = []
    for log in logs:
        flat = {
            "LogID": log.get("LogID", "N/A"),
            "Time": log["TimeCreated"],
            "EventID": log["EventID"],
            "Level": log.get("Level", "Information"), # Handle missing level from reconstructed logs
            "User": log["Security"]["UserID"],
            "IP": log["EventData"]["IpAddress"],
            "Action": log["EventData"]["Description"]
        }
        flattened.append(flat)
    
    df = pd.DataFrame(flattened)
    # Sort by LogID descending (newest at top)
    if "LogID" in df.columns:
        df = df.sort_values(by="LogID", ascending=False)
    return df

def generate_logs_step():
    global logs_history
    
    # 1. Generate new logs (simulating 2 seconds worth, maybe 1-2 logs)
    new_logs = []
    # Generate 1-2 logs per step (faster cadence)
    import random
    num_logs = random.randint(1, 2)
    for _ in range(num_logs):
        # 10% chance of abnormal log
        is_abnormal = random.random() < 0.1
        log = log_gen.generate_log(abnormal=is_abnormal)
        new_logs.append(log)
    
    # 2. Ingest
    rag.ingest_logs(new_logs)
    logs_history.extend(new_logs)
    
    # 3. Return updated data
    # Show last 20 logs
    display_df = format_logs_for_display(logs_history[-20:]) 
    
    # Format log JSON for display
    latest_log_json = json.dumps(new_logs, indent=2)
    
    return display_df, latest_log_json

def analyze_logs_step(model_name):
    global logs_history, suspicious_history, is_analyzing, last_analyzed_count
    
    # Prevent overlapping analysis calls
    if is_analyzing:
        return gr.Skip(), gr.Skip()
        
    is_analyzing = True
    try:
        # Analyze all new logs since last analysis
        current_count = len(logs_history)
        if current_count <= last_analyzed_count:
            return "Waiting for new logs...", json.dumps(suspicious_history, indent=2)
            
        recent_logs = logs_history[last_analyzed_count:]
        print(f"Analyzing batch of {len(recent_logs)} logs...")

        # 3. Analyze
        analysis_json_str = rag.analyze_logs(recent_logs, model_name=model_name)
        
        # Mark these logs as analyzed
        last_analyzed_count = current_count
        
        # Clean up the JSON string (strip markdown code blocks)
        analysis_json_str = analysis_json_str.strip()
        if analysis_json_str.startswith("```json"):
            analysis_json_str = analysis_json_str[7:]
        if analysis_json_str.startswith("```"):
            analysis_json_str = analysis_json_str[3:]
        if analysis_json_str.endswith("```"):
            analysis_json_str = analysis_json_str[:-3]
        analysis_json_str = analysis_json_str.strip()

        try:
            analysis_data = json.loads(analysis_json_str)
            suspicious_events = analysis_data.get("suspicious_events", [])
            summary = analysis_data.get("summary", "No summary provided.")
            
            analysis_text = f"**Summary:** {summary}\n\n"
            
            if suspicious_events:
                analysis_text += "**Suspicious Events:**\n"
                for event in suspicious_events:
                    flagged_id = event.get("flagged_event_id")
                    reason = event.get("reason")
                    analysis_text += f"- **ID {flagged_id}:** {reason}\n"
                
                # Append the full analysis JSON to history
                analysis_data["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
                suspicious_history.insert(0, analysis_data)
                save_suspicious_events()
                
            else:
                analysis_text += "System Normal"
                
        except json.JSONDecodeError:
            analysis_text = f"**Raw Analysis:**\n{analysis_json_str}"
            
            # If raw analysis doesn't say "System Normal", treat it as suspicious
            if "System Normal" not in analysis_json_str:
                 suspicious_record = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "raw_output": analysis_json_str
                }
                 suspicious_history.insert(0, suspicious_record)
                 save_suspicious_events()

        # Format suspicious history for display
        suspicious_json = json.dumps(suspicious_history, indent=2)
        
        return analysis_text, suspicious_json
        
    finally:
        is_analyzing = False

with gr.Blocks(title="Zero Trust Event Log Analysis") as demo:
    gr.Markdown("# Real-Time Zero Trust Event Log Analysis")
    gr.Markdown("Simulates Windows Server 2022 Event Logs and analyzes them using RAG + AI.")
    
    with gr.Row():
        model_selector = gr.Dropdown(
            choices=["OpenAI", "Anthropic", "Google", "Ollama"],
            value="OpenAI",
            label="Select AI Model"
        )
        start_btn = gr.Button("Start Simulation", variant="primary")
        stop_btn = gr.Button("Stop Simulation", variant="stop")

    with gr.Row():
        with gr.Column(scale=2):
            gr.Markdown("### Live Event Logs")
            log_table = gr.Dataframe(label="Recent Logs", interactive=False)
            
            with gr.Row():
                with gr.Column():
                    gr.Markdown("### Latest Raw JSON")
                    json_display = gr.Code(language="json", label="Latest Log Entry")
                with gr.Column():
                    gr.Markdown("### Suspicious Events History")
                    suspicious_display = gr.Code(language="json", label="Suspicious Events")
        
        with gr.Column(scale=1):
            gr.Markdown("### AI Security Insights")
            analysis_output = gr.Markdown(label="Analysis")

    # Timers
    log_timer = gr.Timer(2.0) # Fast: 2 seconds
    analysis_timer = gr.Timer(10.0) # Slow: 10 seconds

    # Events
    def start_sim():
        return gr.Timer(active=True), gr.Timer(active=True)

    def stop_sim():
        return gr.Timer(active=False), gr.Timer(active=False)

    start_btn.click(start_sim, outputs=[log_timer, analysis_timer])
    stop_btn.click(stop_sim, outputs=[log_timer, analysis_timer])
    
    log_timer.tick(
        generate_logs_step,
        inputs=None,
        outputs=[log_table, json_display]
    )
    
    analysis_timer.tick(
        analyze_logs_step, 
        inputs=[model_selector], 
        outputs=[analysis_output, suspicious_display]
    )

    # Initialize on load
    demo.load(initialize_system, outputs=[log_table])

if __name__ == "__main__":
    demo.launch()
