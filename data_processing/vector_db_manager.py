# data_processing/vector_db_manager.py

import os
import sqlite3
import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DB_PATH = os.path.join(PROJECT_ROOT, 'data', 'mitre_attack.db')
CHROMA_PATH = os.path.join(PROJECT_ROOT, 'data', 'chroma_db')

class MITREDbManager:
    """
    Manages interactions with the ChromaDB for MITRE ATT&CK techniques and mitigations.
    """
    def __init__(self):
        print(f"Initializing ChromaDB client at {CHROMA_PATH}...")
        self.client = chromadb.PersistentClient(path=CHROMA_PATH)
        
        # Initialize embedding function once
        print("Loading SentenceTransformer model 'all-MiniLM-L6-v2'...")
        self.embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2",
            device="cpu" # Use 'cuda' if you have an NVIDIA GPU, otherwise 'cpu'
        )
        print("SentenceTransformer model loaded.")

    def get_or_create_collection(self, name: str):
        """
        Gets an existing ChromaDB collection or creates it if it doesn't exist.
        """
        print(f"Getting or creating ChromaDB collection: '{name}'")
        return self.client.get_or_create_collection(
            name=name,
            embedding_function=self.embedding_function
        )

    def _get_data_from_sqlite(self):
        """Retrieves all techniques and mitigations from the SQLite database (internal helper)."""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        techniques = cursor.execute("SELECT id, name, tactic, description, url FROM techniques").fetchall()
        mitigations = cursor.execute("SELECT id, name, description, url FROM mitigations").fetchall()

        conn.close()
        return techniques, mitigations

    def populate_vector_database(self):
        """
        Populates the vector database with techniques and mitigations from SQLite.
        This should typically be run once to set up the database.
        """
        # Ensure collections are clean before populating
        print("Ensuring a clean slate for ChromaDB collections...")
        try:
            self.client.delete_collection(name="techniques") # Use "techniques" matching llm_summarizer
            print("Existing 'techniques' collection deleted.")
        except Exception as e:
            print(f"Could not delete 'techniques' (might not exist yet, or other error): {e}")

        try:
            self.client.delete_collection(name="mitigations") # Use "mitigations" matching llm_summarizer
            print("Existing 'mitigations' collection deleted.")
        except Exception as e:
            print(f"Could not delete 'mitigations' (might not exist yet, or other error): {e}")

        techniques_collection = self.get_or_create_collection(name="techniques")
        mitigations_collection = self.get_or_create_collection(name="mitigations")
        print("ChromaDB collections ready for population.")

        # --- Populate Techniques Collection ---
        techniques_data, mitigations_data = self._get_data_from_sqlite()

        tech_docs = []
        tech_metadatas = []
        tech_ids = []

        print(f"Processing {len(techniques_data)} techniques for embedding...")
        for tech_id, name, tactic, description, url in techniques_data:
            content = f"Technique: {name}. Tactic(s): {tactic}. Description: {description}"
            tech_docs.append(content)
            tech_metadatas.append({
                "id": tech_id,
                "name": name,
                "tactic": tactic,
                "description": description,
                "url": url,
                "type": "technique"
            })
            tech_ids.append(tech_id)

        if tech_docs:
            print(f"Adding {len(tech_docs)} techniques to ChromaDB...")
            techniques_collection.add(
                documents=tech_docs,
                metadatas=tech_metadatas,
                ids=tech_ids
            )
            print(f"Technique embeddings added successfully. Current count: {techniques_collection.count()}")
        else:
            print("No techniques found in SQLite to embed.")

        # --- Populate Mitigations Collection ---
        mit_docs = []
        mit_metadatas = []
        mit_ids = []

        print(f"Processing {len(mitigations_data)} mitigations for embedding...")
        for mit_id, name, description, url in mitigations_data:
            content = f"Mitigation: {name}. Description: {description}"
            mit_docs.append(content)
            mit_metadatas.append({
                "id": mit_id,
                "name": name,
                "description": description,
                "url": url,
                "type": "mitigation"
            })
            mit_ids.append(mit_id)

        if mit_docs:
            print(f"Adding {len(mit_docs)} mitigations to ChromaDB...")
            mitigations_collection.add(
                documents=mit_docs,
                metadatas=mit_metadatas,
                ids=mit_ids
            )
            print(f"Mitigation embeddings added successfully. Current count: {mitigations_collection.count()}")
        else:
            print("No mitigations found in SQLite to embed.")

        print("\nVector database population complete.")

if __name__ == "__main__":
    db_manager = MITREDbManager()
    db_manager.populate_vector_database()