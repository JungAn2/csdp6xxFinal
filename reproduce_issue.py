import httpx
from typing import List
from langchain_core.embeddings import Embeddings
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class SimpleOllamaEmbeddings(Embeddings):
    def __init__(self, model: str = "nomic-embed-text", base_url: str = "http://127.0.0.1:11434"):
        self.model = model
        self.base_url = base_url

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        embeddings = []
        for text in texts:
            embeddings.append(self.embed_query(text))
        return embeddings

    def embed_query(self, text: str) -> List[float]:
        print(f"Sending request to {self.base_url}/api/embed with model={self.model}")
        response = httpx.post(
            f"{self.base_url}/api/embed",
            json={"model": self.model, "input": text}
        )
        response.raise_for_status()
        return response.json()["embeddings"][0]

try:
    print("Initializing SimpleOllamaEmbeddings...")
    embeddings = SimpleOllamaEmbeddings(model="nomic-embed-text")
    
    print("Embedding a test string...")
    result = embeddings.embed_query("This is a test.")
    print("Embedding successful.")
    print(f"Vector length: {len(result)}")
except Exception as e:
    print(f"Error: {e}")
