# Zero Trust Event Log Analysis with RAG

This project demonstrates a **Zero Trust security monitoring system** that leverages **Retrieval-Augmented Generation (RAG)** to analyze real-time Windows Event Logs. It uses a local Vector Database (ChromaDB) to provide historical context to Large Language Models (LLMs), enabling them to detect subtle anomalies and suspicious behavior patterns.

## Features

- **Real-time Log Simulation**: Generates realistic Windows Server 2022 event logs (Login, File Access, Process Creation, etc.).
- **RAG Architecture**: Uses **ChromaDB** to store and retrieve historical context, allowing the AI to compare current events against past user behavior.
- **Multi-LLM Support**: Compatible with:
  - OpenAI (GPT-4o)
  - Anthropic (Claude 3.5 Sonnet)
  - Google (Gemini 1.5 Pro)
  - Ollama (Local models like Llama 3)
- **Live Dashboard**: Interactive **Gradio** interface with decoupled threads for:
  - High-frequency log generation (~2s interval)
  - Deep AI analysis (~10s interval)
- **Persistence**: 
  - Vector database persists between runs in `./chroma_db`.
  - Suspicious events are logged to `suspicious_events.json`.

## Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com/) (for local embeddings and models)
- API Keys for cloud providers (optional if using local models)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd csdp6xxFinal
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   # Windows
   .\.venv\Scripts\activate
   # Linux/Mac
   source .venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Setup Local Embeddings**
   This project uses `nomic-embed-text` via Ollama for embeddings by default (or OpenAI if configured).
   ```bash
   ollama pull nomic-embed-text
   ```

5. **Configuration**
   Copy `.env.example` to `.env` and configure your keys:
   ```bash
   cp .env.example .env
   ```
   Edit `.env`:
   ```ini
   OPENAI_API_KEY=sk-...
   # ANTHROPIC_API_KEY=...
   # GOOGLE_API_KEY=...
   ```

## Usage

Run the application:
```bash
python app.py
```

Open your browser to the local Gradio URL (usually `http://127.0.0.1:7860`).

### Dashboard Controls
- **Select AI Model**: Choose the backend for analysis.
- **Start Simulation**: Begins generating logs and running analysis.
- **Stop Simulation**: Pauses generation and analysis.

## Project Structure

- `app.py`: Main Gradio application, handles UI and simulation loops.
- `rag_engine.py`: Core logic for ChromaDB interaction, embedding generation, and LLM querying.
- `log_generator.py`: Utility to generate synthetic Windows Event Logs.
- `chroma_db/`: Directory where the vector database is stored.
- `suspicious_events.json`: Persistent record of flagged events.

## Troubleshooting

- **Dimension Mismatch Error**: If you switch embedding models (e.g., from Ollama to OpenAI), you may need to delete the `chroma_db` folder to reset the database, as they use different vector dimensions (768 vs 1536).
