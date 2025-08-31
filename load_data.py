import json
import os
from db import get_db_connection  # Direct import since db.py is in same directory

def load_json_to_mongodb(file_path, collection_name):
    try:
        db = get_db_connection()
        for encoding in ('utf-8-sig', 'utf-8', 'latin1'):
            try:
                with open(file_path, 'r', encoding=encoding) as file:
                    data = json.load(file)
                    collection = db[collection_name]
                    collection.delete_many({})  # Clear existing data (optional)
                    if isinstance(data, list):
                        collection.insert_many(data)
                    else:
                        collection.insert_one(data)
                print(f"Loaded {file_path} into {collection_name} collection with {encoding} encoding")
                break
            except UnicodeDecodeError as ude:
                print(f"Failed to decode {file_path} with {encoding}: {str(ude)}")
                continue
            except json.JSONDecodeError as jde:
                print(f"JSON error in {file_path}: {str(jde)}")
                return
    except Exception as e:
        print(f"Error loading {file_path}: {str(e)}")

if __name__ == "__main__":
    json_files = [
        ("../backend/dataset/verbs.json", "verbs"),
        ("../backend/dataset/nouns.json", "nouns"),
        ("../backend/dataset/conjugations.json", "conjugations"),
        ("../backend/dataset/sentences.json", "sentences"),
        ("../backend/dataset/matching_game.json", "matching_game")
    ]
    for file_path, collection_name in json_files:
        load_json_to_mongodb(file_path, collection_name)