import sys
from unittest.mock import MagicMock

# Mock modules that might be missing or heavy
sys.modules["chromadb"] = MagicMock()
sys.modules["langchain_chroma"] = MagicMock()
sys.modules["langchain_openai"] = MagicMock()
sys.modules["langchain_anthropic"] = MagicMock()
sys.modules["langchain_google_genai"] = MagicMock()
sys.modules["langchain_ollama"] = MagicMock()
sys.modules["langchain_core"] = MagicMock()
sys.modules["langchain_core.documents"] = MagicMock()
sys.modules["langchain_core.prompts"] = MagicMock()
sys.modules["gradio"] = MagicMock() # Mock gradio too as it might launch stuff

import app
import json

# Mock the RAG engine to avoid actual LLM calls
app.rag = MagicMock()
app.rag.analyze_logs.return_value = json.dumps({
    "suspicious_events": [],
    "summary": "Mock analysis"
})
app.rag.get_log_count.return_value = 0

# Mock LogGenerator
app.log_gen = MagicMock()
app.log_gen.generate_initial_logs.return_value = [{"LogID": i, "TimeCreated": "now", "EventID": 4624, "Security": {"UserID": "user"}, "EventData": {"IpAddress": "1.1.1.1", "Description": "Login"}} for i in range(10)]
app.log_gen.generate_log.return_value = {"LogID": 100, "TimeCreated": "now", "EventID": 4624, "Security": {"UserID": "user"}, "EventData": {"IpAddress": "1.1.1.1", "Description": "Login"}}

def test_batch_logic():
    print("Initializing system...")
    app.initialize_system()
    print(f"Initial logs: {len(app.logs_history)}")
    print(f"Last analyzed count: {app.last_analyzed_count}")
    
    assert len(app.logs_history) == 10
    assert app.last_analyzed_count == 10
    
    print("\nSimulating log generation (5 steps)...")
    for _ in range(5):
        app.generate_logs_step()
        
    print(f"Logs after generation: {len(app.logs_history)}")
    # generate_logs_step adds 1-2 logs. Let's assume at least 5 added.
    assert len(app.logs_history) >= 15
    assert app.last_analyzed_count == 10
    
    print("\nSimulating analysis step...")
    app.analyze_logs_step("OpenAI")
    
    print(f"Last analyzed count after analysis: {app.last_analyzed_count}")
    assert app.last_analyzed_count == len(app.logs_history)
    
    # Check if rag.analyze_logs was called with the correct batch
    call_args = app.rag.analyze_logs.call_args
    batch_sent = call_args[0][0]
    print(f"Batch size sent to RAG: {len(batch_sent)}")
    assert len(batch_sent) == len(app.logs_history) - 10
    
    print("\nSimulating overlapping request (should skip)...")
    app.is_analyzing = True
    result = app.analyze_logs_step("OpenAI")
    # Gradio Skip is hard to check directly as it's a class, but we can check if it returned something different
    # or just check if rag was NOT called again
    app.rag.analyze_logs.reset_mock()
    app.analyze_logs_step("OpenAI")
    app.rag.analyze_logs.assert_not_called()
    print("Overlapping request skipped correctly.")
    
    print("\nTest Passed!")

if __name__ == "__main__":
    test_batch_logic()
