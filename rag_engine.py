import os
import chromadb
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_core.documents import Document
from langchain_core.prompts import ChatPromptTemplate

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

        last_log = recent_logs[-1]
        query = f"User {last_log['Security']['UserID']} {last_log['EventData']['Description']}"
        
        retrieved_docs = self.vector_store.similarity_search(query, k=3)
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
