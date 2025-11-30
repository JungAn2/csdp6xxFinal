import gradio as gr
import pandas as pd
import json
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

def initialize_system():
    global logs_history
    print("Generating initial historical logs...")
    initial_logs = log_gen.generate_initial_logs(100)
    rag.ingest_logs(initial_logs)
    logs_history.extend(initial_logs)
    print(f"Ingested {len(initial_logs)} logs.")
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
            "Level": log["Level"],
            "User": log["Security"]["UserID"],
            "IP": log["EventData"]["IpAddress"],
            "Action": log["EventData"]["Description"]
        }
        flattened.append(flat)
    return pd.DataFrame(flattened)

def simulation_step(model_name):
    global logs_history, suspicious_history
    
    # 1. Generate new logs (simulating 5 seconds worth, maybe 1-3 logs)
    new_logs = []
    # Generate 1-3 logs per step
    import random
    num_logs = random.randint(1, 3)
    for _ in range(num_logs):
        # 10% chance of abnormal log
        is_abnormal = random.random() < 0.1
        log = log_gen.generate_log(abnormal=is_abnormal)
        new_logs.append(log)
    
    # 2. Ingest
    rag.ingest_logs(new_logs)
    logs_history.extend(new_logs)
    
    # 3. Analyze (only the new batch)
    analysis_json_str = rag.analyze_logs(new_logs, model_name=model_name)
    
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

    # 4. Return updated data
    display_df = format_logs_for_display(logs_history[-20:]) # Show last 20
    
    # Format log JSON for display
    latest_log_json = json.dumps(new_logs, indent=2)
    
    # Format suspicious history for display
    suspicious_json = json.dumps(suspicious_history, indent=2)
    
    return display_df, latest_log_json, analysis_text, suspicious_json

with gr.Blocks(title="Zero Trust Event Log Analysis") as demo:
    gr.Markdown("# Real-Time Zero Trust Event Log Analysis")
    gr.Markdown("Simulates Windows Server 2022 Event Logs and analyzes them using RAG + AI.")
    
    with gr.Row():
        model_selector = gr.Dropdown(
            choices=["OpenAI", "Anthropic", "Google", "Ollama"],
            value="Ollama",
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

    # Timer for the loop
    timer = gr.Timer(10) # 10 seconds

    # Events
    def start_sim():
        return gr.Timer(active=True)

    def stop_sim():
        return gr.Timer(active=False)

    start_btn.click(start_sim, outputs=[timer])
    stop_btn.click(stop_sim, outputs=[timer])
    
    timer.tick(
        simulation_step, 
        inputs=[model_selector], 
        outputs=[log_table, json_display, analysis_output, suspicious_display]
    )

    # Initialize on load
    demo.load(initialize_system, outputs=[log_table])

if __name__ == "__main__":
    demo.launch()
