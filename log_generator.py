import json
import random
import datetime
import uuid

class LogGenerator:
    def __init__(self):
        self.load_data()
        self.log_counter = 0

    def load_data(self):
        with open('data/users.json', 'r') as f:
            self.users = json.load(f)
        with open('data/computers.json', 'r') as f:
            self.computers = json.load(f)
        with open('data/ips.json', 'r') as f:
            self.ips = json.load(f)
        with open('data/event_types.json', 'r') as f:
            self.event_types = json.load(f)

    def generate_log(self, abnormal=False):
        self.log_counter += 1
        now = datetime.datetime.now().isoformat()
        
        if abnormal:
            # Simulate abnormal behavior
            event = random.choice([e for e in self.event_types if e["id"] in [4625, 4740, 4771, 5031]])
            user = random.choice(self.users + ["hacker", "unknown_user"])
            ip = random.choice(["203.0.113.5", "198.51.100.23", "unknown"]) # External IPs
        else:
            event = random.choice(self.event_types)
            user = random.choice(self.users)
            ip = random.choice(self.ips)

        log_entry = {
            "LogID": self.log_counter,
            "EventID": event["id"],
            "TimeCreated": now,
            "Level": event["level"],
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Channel": "Security",
            "Computer": random.choice(self.computers),
            "Security": {
                "UserID": user
            },
            "EventData": {
                "TargetUserName": user,
                "IpAddress": ip,
                "LogonType": random.choice([2, 3, 10]), # Interactive, Network, RDP
                "Description": event["desc"]
            }
        }
        return log_entry

    def generate_initial_logs(self, n=100):
        logs = []
        for _ in range(n):
            # Mix of normal and some abnormal
            is_abnormal = random.random() < 0.1 # 10% abnormal
            logs.append(self.generate_log(abnormal=is_abnormal))
        return logs

if __name__ == "__main__":
    generator = LogGenerator()
    print(json.dumps(generator.generate_initial_logs(5), indent=2))
