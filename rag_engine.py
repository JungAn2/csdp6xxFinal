import os
import chromadb
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate
import json

from dotenv import load_dotenv
load_dotenv()

# ... (imports)

class RAGEngine:
    def __init__(self):
        # Initialize ChromaDB
        self.chroma_client = chromadb.PersistentClient(path="./chroma_db")
        self.collection_name = "event_logs"
        
        # Try OpenAI Embeddings first, fallback to OllamaEmbeddings
        self.embeddings = None
        try:
            if os.getenv("OPENAI_API_KEY"):
                self.embeddings = OpenAIEmbeddings()
            else:
                raise Exception("No OpenAI Key")
        except:
            print("OpenAI API Key not found. Switching to OllamaEmbeddings (nomic-embed-text).")
            try:
                # Assuming 'nomic-embed-text' or similar is pulled. 
                # If not, user might need to pull it: `ollama pull nomic-embed-text`
                # Or use a generic one like 'llama3' if it supports embeddings, but dedicated is better.
                # For safety, let's try a common one or the one user specified for model if applicable.
                # We'll default to 'nomic-embed-text' as it's standard for local RAG, or 'all-minilm'.
                self.embeddings = OllamaEmbeddings(model="nomic-embed-text") 
            except Exception as e:
                print(f"Failed to initialize OllamaEmbeddings: {e}")
                self.embeddings = None

        if self.embeddings is None:
             print("WARNING: No embeddings model available. RAG will fail.")

        self.vector_store = Chroma(
            client=self.chroma_client,
            collection_name=self.collection_name,
            embedding_function=self.embeddings,
        )

    def get_llm(self, model_name):
        if model_name == "OpenAI":
            return ChatOpenAI(model="gpt-4o")
        elif model_name == "Anthropic":
            return ChatAnthropic(model="claude-3-5-sonnet-20240620")
        elif model_name == "Google":
            return ChatGoogleGenerativeAI(model="gemini-1.5-pro")
        elif model_name == "Ollama":
            model = os.getenv("OLLAMA_MODEL")
            if not model:
                model = "llama3" # Default fallback
            return ChatOllama(model=model)
        else:
            raise ValueError(f"Unknown model: {model_name}")

    def ingest_logs(self, logs):
        documents = []
        for log in logs:
            # Convert log to string representation for embedding
            content = f"LogID: {log['LogID']}, Time: {log['TimeCreated']}, EventID: {log['EventID']}, User: {log['Security']['UserID']}, IP: {log['EventData']['IpAddress']}, Action: {log['EventData']['Description']}"
            metadata = {
                "log_id": log['LogID'],
                "user": log['Security']['UserID'],
                "event_id": log['EventID'],
                "ip": log['EventData']['IpAddress']
            }
            documents.append(Document(page_content=content, metadata=metadata))
        
        if documents and self.embeddings:
            self.vector_store.add_documents(documents)

    def analyze_logs(self, recent_logs, model_name="OpenAI"):
        llm = self.get_llm(model_name)
        
        # Retrieve relevant historical context (simple retrieval for now)
        # We query for similar logs to the most recent one
        if not recent_logs:
            return "No logs to analyze."

        # Extract unique entities from the batch to form a comprehensive query
        users = set()
        ips = set()
        descriptions = set()
        
        for log in recent_logs:
            if 'Security' in log and 'UserID' in log['Security']:
                users.add(log['Security']['UserID'])
            if 'EventData' in log:
                if 'IpAddress' in log['EventData']:
                    ips.add(log['EventData']['IpAddress'])
                if 'Description' in log['EventData']:
                    # Take first few words of description to avoid too long query
                    desc = log['EventData']['Description']
                    descriptions.add(desc[:50])

        # Construct a composite query
        query_parts = []
        if users:
            query_parts.append(f"Users: {', '.join(users)}")
        if ips:
            query_parts.append(f"IPs: {', '.join(ips)}")
        if descriptions:
            # Limit descriptions to avoid token overflow
            query_parts.append(f"Activities: {', '.join(list(descriptions)[:3])}")
            
        query = " | ".join(query_parts)
        print(f"RAG Query: {query}")
        
        # Increase k slightly to capture context for multiple entities
        retrieved_docs = self.vector_store.similarity_search(query, k=5)
        context = "\n".join([doc.page_content for doc in retrieved_docs])
        
        recent_logs_str = "\n".join([str(log) for log in recent_logs])

        prompt = ChatPromptTemplate.from_template("""
        You are a Zero Trust Security Analyst. Analyze the following recent Windows Event Logs for anomalies.
        Focus on: Authorization, Authentication, Data, Device, Network, and User behavior.
        
        Historical Context (Similar past events):
        {context}
        
        Recent Logs (Last 5 seconds):
        {recent_logs}
        
        Identify any suspicious activity.
        
        Return your analysis in the following JSON format:
        {{
            "suspicious_events": [
                {{
                    "flagged_event_id": <LogID of the suspicious log entry>,
                    "reason": "Explanation of why it is suspicious"
                }}
            ],
            "summary": "Overall summary of the analysis"
        }}
        If no suspicious activity is found, return an empty list for "suspicious_events".
        """)
        
        chain = prompt | llm
        
        response = chain.invoke({
            "context": context,
            "recent_logs": recent_logs_str
        })
        
        return response.content

    def get_log_count(self):
        return self.vector_store._collection.count()

    def get_recent_logs(self, limit=50):
        # Fetch raw documents from Chroma
        # We use the underlying collection to get the raw data
        # To get the MOST RECENT, we need to use offset, assuming insertion order is preserved.
        count = self.get_log_count()
        offset = max(0, count - limit)
        
        # If we want the last 'limit' items, we start at offset
        results = self.vector_store._collection.get(limit=limit, offset=offset)
        
        logs = []
        import re
        # Regex to parse the content string back into fields
        # Format: LogID: {id}, Time: {time}, EventID: {eid}, User: {user}, IP: {ip}, Action: {action}
        pattern = r"LogID: (?P<LogID>.*?), Time: (?P<Time>.*?), EventID: (?P<EventID>.*?), User: (?P<User>.*?), IP: (?P<IP>.*?), Action: (?P<Action>.*)"
        
        if results and results['documents']:
            for doc_text, metadata in zip(results['documents'], results['metadatas']):
                match = re.search(pattern, doc_text)
                if match:
                    data = match.groupdict()
                    # Reconstruct the log object structure used in app.py
                    log = {
                        "LogID": int(data['LogID']) if data['LogID'].isdigit() else data['LogID'],
                        "TimeCreated": data['Time'],
                        "EventID": int(data['EventID']) if data['EventID'].isdigit() else data['EventID'],
                        "Level": "Information", # Default, as it wasn't stored in text
                        "Security": {
                            "UserID": data['User']
                        },
                        "EventData": {
                            "IpAddress": data['IP'],
                            "Description": data['Action']
                        }
                    }
                    logs.append(log)
        
        # Sort by LogID descending (assuming int IDs)
        logs.sort(key=lambda x: x['LogID'] if isinstance(x['LogID'], int) else 0, reverse=True)
        return logs
