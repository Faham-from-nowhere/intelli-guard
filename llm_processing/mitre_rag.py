# llm_processing/mitre_rag.py

import os
import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer
import sqlite3
import json # <--- ADD THIS IMPORT

# Define paths (consistent with data_processing/vector_db_manager.py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR) # Go up one level from llm_processing (to project root) 
CHROMA_PATH = os.path.join(PROJECT_ROOT, 'data', 'chroma_db')
#print(f"DEBUG (mitre_rag): CHROMA_PATH is set to: {CHROMA_PATH}") # <--- ADD THIS LINE
DB_PATH = os.path.join(PROJECT_ROOT, 'data', 'mitre_attack.db')


_client = chromadb.PersistentClient(path=CHROMA_PATH)
# Use the same embedding model as used for population
_embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2",
    device="cpu" # Use 'cuda' if you have an NVIDIA GPU, otherwise 'cpu'
)

# Get collection objects
_techniques_collection = _client.get_or_create_collection(
    name="mitre_techniques",
    embedding_function=_embedding_function # Ensure embedding function is set for queries
)
_mitigations_collection = _client.get_or_create_collection(
    name="mitre_mitigations",
    embedding_function=_embedding_function # Ensure embedding function is set for queries
)

def get_mitigations_for_technique(technique_id: str) -> list:
    """Retrieves mitigation names and IDs for a given technique from SQLite."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT m.name, m.id
        FROM mitigations AS m
        JOIN technique_mitigation_links AS tml ON m.id = tml.mitigation_id
        WHERE tml.technique_id = ?
    ''', (technique_id,))
    mitigations = cursor.fetchall()
    conn.close()
    return [{"name": name, "id": mid} for name, mid in mitigations]


def retrieve_mitre_context(query: str, n_results: int = 5) -> str:
    """
    Retrieves relevant MITRE ATT&CK techniques and mitigations from ChromaDB
    and formats them as context for the LLM.
    """
    context = []

    # --- DEBUGGING: Check collection count ---
    tech_count = _techniques_collection.count()
    mit_count = _mitigations_collection.count()
    print(f"DEBUG: Techniques collection contains {tech_count} documents.")
    print(f"DEBUG: Mitigations collection contains {mit_count} documents.")
    # --- END DEBUGGING ---

    # 1. Retrieve Techniques
    # The query_texts parameter will be embedded by the collection's embedding_function
    technique_results = _techniques_collection.query(
        query_texts=[query],
        n_results=n_results,
        include=['documents', 'metadatas', 'distances']
    )

    # --- DEBUGGING: Print raw query results ---
    print(f"DEBUG: Raw technique query results for '{query}':")
    # Using json.dumps for pretty printing the dictionary
    print(json.dumps(technique_results, indent=2))
    # --- END DEBUGGING ---

    if technique_results and technique_results['metadatas'] and technique_results['metadatas'][0]:
        context.append("### Relevant MITRE ATT&CK Techniques:\n")
        for i, metadata in enumerate(technique_results['metadatas'][0]):
            tech_id = metadata.get('id')
            tech_name = metadata.get('name')
            tech_tactic = metadata.get('tactic')
            tech_desc = metadata.get('description')
            tech_url = metadata.get('url')
            distance = technique_results['distances'][0][i]

            context.append(f"**Technique ID:** {tech_id}")
            context.append(f"**Name:** {tech_name}")
            context.append(f"**Tactic(s):** {tech_tactic}")
            context.append(f"**Description:** {tech_desc}")
            context.append(f"**URL:** {tech_url}")
            context.append(f"**Similarity Score:** {1 - distance:.2f} (closer to 1 is more similar)") # Convert distance to similarity
            
            # Retrieve associated mitigations from SQLite for this technique
            mitigations = get_mitigations_for_technique(tech_id)
            if mitigations:
                mitigation_strs = [f"{m['name']} (ID: {m['id']})" for m in mitigations]
                context.append(f"**Associated Mitigations:** {'; '.join(mitigation_strs)}")
            else:
                context.append("**Associated Mitigations:** None found in database.")
            context.append("---\n")
    else:
        context.append("No relevant techniques found in the MITRE ATT&CK knowledge base.")

    return "\n".join(context)

if __name__ == "__main__":
    print("Testing MITRE RAG retrieval...")
    
    # Test 1: Broad query
    query1 = "how attackers gain initial access"
    print(f"\n--- Retrieving for '{query1}' ---")
    retrieved_context1 = retrieve_mitre_context(query1, n_results=3)
    print(retrieved_context1)

    # Test 2: Specific technique ID (should find itself if description is in DB)
    query2 = "T1059.001 powershell execution"
    print(f"\n--- Retrieving for '{query2}' ---")
    retrieved_context2 = retrieve_mitre_context(query2, n_results=1)
    print(retrieved_context2)

    # Test 3: Mitigation-focused query
    query3 = "how to prevent code execution"
    print(f"\n--- Retrieving for '{query3}' ---")
    retrieved_context3 = retrieve_mitre_context(query3, n_results=2)
    print(retrieved_context3)