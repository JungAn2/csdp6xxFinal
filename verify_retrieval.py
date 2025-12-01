import sys
from unittest.mock import MagicMock

# Mock dependencies
sys.modules["chromadb"] = MagicMock()
sys.modules["langchain_chroma"] = MagicMock()
sys.modules["langchain_openai"] = MagicMock()
sys.modules["langchain_anthropic"] = MagicMock()
sys.modules["langchain_google_genai"] = MagicMock()
sys.modules["langchain_ollama"] = MagicMock()
sys.modules["langchain_core"] = MagicMock()
sys.modules["langchain_core.documents"] = MagicMock()
sys.modules["langchain_core.prompts"] = MagicMock()

# Import RAGEngine after mocking
from rag_engine import RAGEngine

def test_retrieval_logic():
    print("Initializing RAGEngine...")
    rag = RAGEngine()
    
    # Mock vector store
    rag.vector_store = MagicMock()
    rag.vector_store.similarity_search.return_value = []
    
    # Mock LLM to avoid instantiation issues if any
    rag.get_llm = MagicMock()
    
    # Create a batch of logs with diverse entities
    logs = [
        {
            "LogID": 1, "TimeCreated": "now", "EventID": 4624, 
            "Security": {"UserID": "Alice"}, 
            "EventData": {"IpAddress": "192.168.1.10", "Description": "Login Success"}
        },
        {
            "LogID": 2, "TimeCreated": "now", "EventID": 4625, 
            "Security": {"UserID": "Bob"}, 
            "EventData": {"IpAddress": "10.0.0.5", "Description": "Login Failed"}
        }
    ]
    
    print("Analyzing logs...")
    # We expect the analyze_logs to call similarity_search with a query containing both Alice and Bob
    try:
        rag.analyze_logs(logs, model_name="OpenAI")
    except Exception as e:
        # It might fail later in the chain execution because we didn't mock everything perfectly,
        # but we only care about the retrieval call which happens first.
        print(f"Caught expected exception during chain execution: {e}")
        pass
        
    # Check the query passed to similarity_search
    call_args = rag.vector_store.similarity_search.call_args
    if not call_args:
        print("FAILURE: similarity_search was not called.")
        return

    query_arg = call_args[0][0]
    print(f"Captured Query: {query_arg}")
    
    # Verify contents
    assert "Alice" in query_arg, "Query missing Alice"
    assert "Bob" in query_arg, "Query missing Bob"
    assert "192.168.1.10" in query_arg, "Query missing IP 1"
    assert "10.0.0.5" in query_arg, "Query missing IP 2"
    
    print("SUCCESS: Query contains all unique entities from the batch.")

if __name__ == "__main__":
    test_retrieval_logic()
