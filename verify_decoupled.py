import app
import json

def test_decoupled_steps():
    print("Testing generate_logs_step...")
    # Mock log_gen and rag for safety if needed, but integration test is better
    
    # 1. Test Generation
    try:
        display_df, latest_json = app.generate_logs_step()
        print(f"Generated logs. DF shape: {display_df.shape}")
        logs = json.loads(latest_json)
        print(f"Generated {len(logs)} new logs.")
        if len(logs) > 0:
            print("PASS: Log generation working.")
        else:
            print("WARN: No logs generated (random chance?)")
    except Exception as e:
        print(f"FAIL: generate_logs_step failed: {e}")

    print("\nTesting analyze_logs_step...")
    # 2. Test Analysis
    try:
        # Ensure we have logs to analyze
        if not app.logs_history:
            print("Adding dummy log for analysis test...")
            app.generate_logs_step()
            
        analysis_text, suspicious_json = app.analyze_logs_step(model_name="Ollama")
        print(f"Analysis text length: {len(analysis_text)}")
        suspicious = json.loads(suspicious_json)
        print(f"Suspicious history count: {len(suspicious)}")
        
        if "Summary" in analysis_text or "Waiting" in analysis_text:
            print("PASS: Analysis step returned valid output.")
        else:
            print(f"FAIL: Unexpected analysis output: {analysis_text[:50]}...")
            
    except Exception as e:
        print(f"FAIL: analyze_logs_step failed: {e}")

if __name__ == "__main__":
    # Initialize system first to setup RAG
    app.initialize_system()
    test_decoupled_steps()
