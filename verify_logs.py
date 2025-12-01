import pandas as pd
from rag_engine import RAGEngine
from app import format_logs_for_display

def test_log_retrieval():
    print("Testing log retrieval...")
    rag = RAGEngine()
    
    # Ensure there are logs (might need to run app once if empty, but we can check count)
    count = rag.get_log_count()
    print(f"Log count in DB: {count}")
    
    if count == 0:
        print("No logs in DB to test retrieval. Please run app.py once to generate logs.")
        return

    logs = rag.get_recent_logs(limit=10)
    print(f"Retrieved {len(logs)} logs.")
    
    if not logs:
        print("FAIL: No logs retrieved despite count > 0.")
        return

    first_log = logs[0]
    print(f"Sample log: {first_log}")
    
    # Check fields
    required_fields = ["LogID", "TimeCreated", "EventID", "Security", "EventData"]
    for field in required_fields:
        if field not in first_log:
            print(f"FAIL: Missing field {field} in log.")
            return
            
    print("PASS: Log structure seems correct.")

    # Test sorting in UI format
    print("\nTesting UI sorting...")
    df = format_logs_for_display(logs)
    
    if df.empty:
        print("FAIL: DataFrame is empty.")
        return
        
    print("DataFrame Head:")
    print(df.head())
    
    # Check if sorted by LogID descending
    ids = df["LogID"].tolist()
    if ids == sorted(ids, reverse=True):
        print("PASS: DataFrame is sorted by LogID descending.")
    else:
        print(f"FAIL: DataFrame is NOT sorted correctly. IDs: {ids}")

if __name__ == "__main__":
    test_log_retrieval()
