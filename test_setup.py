try:
    import gradio
    import langchain
    import chromadb
    from log_generator import LogGenerator
    from rag_engine import RAGEngine
    print("Imports successful.")
    
    lg = LogGenerator()
    logs = lg.generate_initial_logs(5)
    print(f"Generated {len(logs)} logs.")
    
    # Mocking RAGEngine init to avoid API key issues during test if possible, 
    # but RAGEngine handles missing keys gracefully by printing a warning.
    rag = RAGEngine()
    print("RAGEngine initialized.")
    
except Exception as e:
    print(f"Verification failed: {e}")
