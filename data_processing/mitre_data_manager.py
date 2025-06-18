# data_processing/mitre_data_manager.py

# data_processing/mitre_data_manager.py

import json
import sqlite3
import os

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
MITRE_JSON_PATH = os.path.join(PROJECT_ROOT, 'data', 'enterprise-attack.json')
DB_PATH = os.path.join(PROJECT_ROOT, 'data', 'mitre_attack.db')

def initialize_db():
    db_dir = os.path.dirname(DB_PATH)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create techniques table (if not exists)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS techniques (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            tactic TEXT,
            description TEXT,
            url TEXT
        )
    ''')

    # Create mitigations table (if not exists)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS mitigations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            url TEXT
        )
    ''')

    # Create a linking table for many-to-many relationship (Technique <-> Mitigation)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS technique_mitigation_links (
            technique_id TEXT NOT NULL,
            mitigation_id TEXT NOT NULL,
            PRIMARY KEY (technique_id, mitigation_id),
            FOREIGN KEY (technique_id) REFERENCES techniques (id),
            FOREIGN KEY (mitigation_id) REFERENCES mitigations (id)
        )
    ''')

    conn.commit()
    conn.close()
    print(f"Database initialized at {DB_PATH}")

def populate_db_from_mitre_json():
    """Populates the 'techniques' and 'mitigations' tables from the enterprise-attack.json file."""
    if not os.path.exists(MITRE_JSON_PATH):
        print(f"Error: MITRE ATT&CK JSON file not found at {MITRE_JSON_PATH}")
        print("Please download 'enterprise-attack.json' from https://github.com/mitre/cti and place it in the 'data/' directory.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Clear existing data before repopulating
    cursor.execute("DELETE FROM technique_mitigation_links")
    cursor.execute("DELETE FROM techniques")
    cursor.execute("DELETE FROM mitigations")
    conn.commit()
    print("Cleared existing technique, mitigation, and link data.")

    try:
        with open(MITRE_JSON_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)

        objects = data.get('objects', [])

        # --- Step 1: Build necessary maps ---
        # Map STIX ID to Tactic Name
        stix_id_to_tactic_name = {
            obj['id']: obj['name']
            for obj in objects if obj.get('type') == 'x-mitre-tactic'
        }

        # Map STIX ID to Mitigation (course-of-action) object details
        stix_id_to_mitigation_details = {}
        for obj in objects:
            if obj.get('type') == 'course-of-action':
                mitigation_id = None
                mitigation_url = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack' and ref.get('external_id','').startswith('M'):
                        mitigation_id = ref.get('external_id')
                        mitigation_url = ref.get('url')
                        break
                
                if mitigation_id: # Only store if it has a proper MITRE M-ID
                    stix_id_to_mitigation_details[obj['id']] = {
                        'id': mitigation_id,
                        'name': obj.get('name'),
                        'description': obj.get('description'),
                        'url': mitigation_url
                    }
        
        # Build map of Technique STIX ID to its associated Mitigation STIX IDs via relationships
        # Mitigations link to techniques with relationship_type "mitigates"
        technique_stix_id_to_mitigation_stix_ids = {}
        for obj in objects:
            if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates':
                # Relationship: source_ref (course-of-action) mitigates target_ref (attack-pattern)
                mitigation_stix_id = obj['source_ref']
                technique_stix_id = obj['target_ref']

                if technique_stix_id not in technique_stix_id_to_mitigation_stix_ids:
                    technique_stix_id_to_mitigation_stix_ids[technique_stix_id] = []
                technique_stix_id_to_mitigation_stix_ids[technique_stix_id].append(mitigation_stix_id)


        # --- Step 2: Populate Mitigations Table ---
        mitigations_added = 0
        for stix_id, details in stix_id_to_mitigation_details.items():
            cursor.execute(
                "INSERT OR REPLACE INTO mitigations (id, name, description, url) VALUES (?, ?, ?, ?)",
                (details['id'], details['name'], details['description'], details['url'])
            )
            mitigations_added += 1
        print(f"Populated database with {mitigations_added} mitigations.")


        # --- Step 3: Populate Techniques Table and Link Table ---
        techniques_added = 0
        links_added = 0
        for obj in objects:
            if obj.get('type') == 'attack-pattern':
                if 'revoked_by_ref' in obj or obj.get('x_mitre_deprecated', False):
                    continue

                technique_id = None
                url = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        technique_id = ref.get('external_id')
                        url = ref.get('url')
                        break

                if not technique_id:
                    continue

                name = obj.get('name')
                description = obj.get('description')
                stix_id = obj.get('id') # STIX ID for linking

                # Get associated tactics
                # Extract tactics directly from kill_chain_phases
                associated_tactic_names = []
                for phase in obj.get("kill_chain_phases", []):
                        if phase.get("kill_chain_name") == "mitre-attack":
                           associated_tactic_names.append(phase.get("phase_name"))



                tactic_string = ", ".join(sorted(associated_tactic_names)) if associated_tactic_names else "N/A"

                cursor.execute(
                    "INSERT OR REPLACE INTO techniques (id, name, tactic, description, url) VALUES (?, ?, ?, ?, ?)",
                    (technique_id, name, tactic_string, description, url)
                )
                techniques_added += 1

                # Populate technique_mitigation_links table
                for mitigation_stix_id in technique_stix_id_to_mitigation_stix_ids.get(stix_id, []):
                    mitigation_details = stix_id_to_mitigation_details.get(mitigation_stix_id)
                    if mitigation_details: # Ensure mitigation exists and has a proper M-ID
                        cursor.execute(
                            "INSERT OR IGNORE INTO technique_mitigation_links (technique_id, mitigation_id) VALUES (?, ?)",
                            (technique_id, mitigation_details['id'])
                        )
                        links_added += 1

        conn.commit()
        print(f"Successfully populated database with {techniques_added} techniques and {links_added} links.")

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON file: {e}")
    except sqlite3.Error as e:
        print(f"Database error during population: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        conn.close()

def get_techniques_by_keyword(keyword):
    """
    Searches for techniques by keyword and returns their details,
    including tactics and associated mitigations.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    keyword = f"%{keyword}%"

    cursor.execute('''
        SELECT 
            t.id, 
            t.name, 
            t.tactic, 
            t.description, 
            t.url,
            GROUP_CONCAT(m.name || '::' || m.id) AS mitigations
        FROM techniques AS t
        LEFT JOIN technique_mitigation_links AS tml ON t.id = tml.technique_id
        LEFT JOIN mitigations AS m ON tml.mitigation_id = m.id
        WHERE t.name LIKE ? OR t.description LIKE ?
        GROUP BY t.id
        ORDER BY t.name
        LIMIT 5
    ''', (keyword, keyword))
    results = cursor.fetchall()
    conn.close()

    techniques_info = []
    for row in results:
        mitigation_list = []
        if row[5]: # If there are mitigations
            for mit_str in row[5].split('::'):
                # Assuming '::' is only used as a separator between name and ID
                # and not within the name/id themselves
                parts = mit_str.rsplit('::', 1) # Split from right, max 1 time
                if len(parts) == 2:
                    mitigation_list.append(f"{parts[0]} (ID: {parts[1]})")
                else: # Fallback for malformed or single part (shouldn't happen with || operator)
                    mitigation_list.append(parts[0])
        
        techniques_info.append({
            "ID": row[0],
            "Name": row[1],
            "Tactic": row[2],
            "Description": row[3],
            "URL": row[4],
            "Mitigations": "; ".join(mitigation_list) if mitigation_list else "N/A"
        })
    return techniques_info

if __name__ == "__main__":
    print("Initializing MITRE ATT&CK database...")
    initialize_db()
    print("Populating database (this may take a moment)...")
    populate_db_from_mitre_json()

    print("\n--- Testing keyword search ---")

    test_keywords = ["phishing", "PowerShell", "task", "network", "credential"]
    for kw in test_keywords:
        print(f"\nSearching for '{kw}':")
        results = get_techniques_by_keyword(kw)
        if results:
            for tech in results:
                print(f"  - ID: {tech['ID']}, Name: {tech['Name']}, Tactic: {tech['Tactic']}")
                print(f"    Description: {tech['Description'][:100]}...") # Truncate description
                print(f"    Mitigations: {tech['Mitigations']}")
                print(f"    URL: {tech['URL']}")
        else:
            print(f"  No techniques found for '{kw}'.")