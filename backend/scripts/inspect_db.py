import os
import sys
import json
from pymongo import MongoClient
from dotenv import load_dotenv

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

load_dotenv('backend/.env')
uri = os.getenv('MONGODB_URI') or os.getenv('MONGO_URI')
target_db = os.getenv('DB_NAME', 'threat_intel_db')
target_col = os.getenv('COLLECTION_NAME', 'threat_reports')

def check():
    client = MongoClient(uri)
    dbs = client.list_database_names()
    print("=== ALL DATABASES IN YOUR MONGODB ATLAS CLUSTER ===")
    for d in dbs:
        print(f" - {d}")
    
    for db_name in dbs:
        if db_name in ['admin', 'local', 'config']:
            continue
        db = client[db_name]
        cols = db.list_collection_names()
        print(f"\n=======================================================")
        print(f" DATABASE: {db_name}")
        print(f" Collections Present: {cols}")
        print(f"=======================================================")
        
        for col_name in cols:
            col = db[col_name]
            count = col.count_documents({})
            try:
                stats = db.command('collstats', col_name)
                size_mb = stats.get("size", 0) / (1024 * 1024)
                storage_mb = stats.get("storageSize", 0) / (1024 * 1024)
                avg_bytes = stats.get("avgObjSize", 0)
                n_indexes = stats.get("nindexes", 0)
                total_index_size = stats.get("totalIndexSize", 0) / (1024 * 1024)
            except Exception as e:
                size_mb = storage_mb = avg_bytes = n_indexes = total_index_size = 0

            print(f"\n[+] COLLECTION: '{col_name}'")
            print(f"    * Total Documents (Records): {count:,}")
            print(f"    * Uncompressed Data Size: {size_mb:.2f} MB")
            print(f"    * WiredTiger Compressed Storage: {storage_mb:.2f} MB")
            print(f"    * Average Document BSON Size: {avg_bytes:.2f} Bytes")
            print(f"    * Number of Indexes: {n_indexes}")
            print(f"    * Total Index Size: {total_index_size:.2f} MB")

            # Index details
            indexes = col.index_information()
            print("    * Indexes:")
            for idx_name, idx_info in indexes.items():
                print(f"        - {idx_name}: {idx_info.get('key')}")

            # Threat Type aggregation
            tt_agg = list(col.aggregate([
                {'$group': {'_id': '$threatType', 'count': {'$sum': 1}}},
                {'$sort': {'count': -1}}
            ]))
            if tt_agg and any(t['_id'] is not None for t in tt_agg):
                print("    * Threat Category (threatType) Distribution:")
                for t in tt_agg:
                    print(f"        - {t['_id']}: {t['count']:,} reports")

            # Severity distribution
            sev_agg = list(col.aggregate([
                {'$group': {'_id': '$severity', 'count': {'$sum': 1}}},
                {'$sort': {'count': -1}}
            ]))
            if sev_agg and any(s['_id'] is not None for s in sev_agg):
                print("    * Severity Distribution:")
                for s in sev_agg:
                    print(f"        - {s['_id']}: {s['count']:,} reports")

            # Sample Document
            sample = col.find_one()
            if sample:
                print("\n    * Sample Document Structure & Field Types:")
                for k, v in sample.items():
                    val_preview = str(v)
                    if len(val_preview) > 65:
                        val_preview = val_preview[:62] + "..."
                    print(f"        - '{k}' ({type(v).__name__}): {val_preview}")

if __name__ == "__main__":
    check()
