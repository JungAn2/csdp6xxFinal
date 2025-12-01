import os
import json
import app
from app import save_suspicious_events, load_suspicious_events, initialize_system

def test_persistence():
    print("Testing persistence...")
    # Mock history
    test_data = [{"id": 1, "reason": "test"}]
    app.suspicious_history = test_data
    
    # Save
    save_suspicious_events()
    
    # Verify file exists
    if not os.path.exists(app.SUSPICIOUS_FILE):
        print("FAIL: suspicious_events.json not created.")
        return
    
    # Clear history
    app.suspicious_history = []
    
    # Load
    load_suspicious_events()
    
    if app.suspicious_history == test_data:
        print("PASS: Persistence working.")
    else:
        print(f"FAIL: Loaded data mismatch. Got {app.suspicious_history}")

    # Clean up
    if os.path.exists(app.SUSPICIOUS_FILE):
        os.remove(app.SUSPICIOUS_FILE)

def test_initialization():
    print("\nTesting initialization...")
    # This should trigger log generation if DB is empty
    try:
        app.initialize_system()
        print("PASS: Initialization successful.")
    except Exception as e:
        print(f"FAIL: Initialization failed: {e}")

if __name__ == "__main__":
    test_persistence()
    test_initialization()
