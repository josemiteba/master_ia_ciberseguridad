#!/usr/bin/env python3
"""
Database Verification Script
Verifies the cybersecurity_dataset.db structure and content
"""

import sqlite3
import os

def verify_database():
    db_file = 'cybersecurity_dataset.db'
    
    if not os.path.exists(db_file):
        print(f"✗ Database file not found: {db_file}")
        return
    
    print(f"✓ Database file found: {db_file}")
    print(f"Size: {os.path.getsize(db_file):,} bytes")
    
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Check table schema
        cursor.execute('SELECT sql FROM sqlite_master WHERE type="table" AND name="network_traffic";')
        schema = cursor.fetchone()
        if schema:
            print("\n✓ Table Schema:")
            print(schema[0])
        else:
            print("✗ Table network_traffic not found")
            return
        
        # Check indexes
        cursor.execute('SELECT name FROM sqlite_master WHERE type="index" AND tbl_name="network_traffic";')
        indexes = cursor.fetchall()
        print(f"\n✓ Indexes ({len(indexes)}):")
        for idx in indexes:
            print(f"  - {idx[0]}")
        
        # Check record count
        cursor.execute('SELECT COUNT(*) FROM network_traffic;')
        count = cursor.fetchone()[0]
        print(f"\n✓ Total Records: {count:,}")
        
        # Sample data
        cursor.execute('SELECT * FROM network_traffic LIMIT 3;')
        sample = cursor.fetchall()
        print(f"\n✓ Sample Data (first 3 records):")
        cursor.execute('PRAGMA table_info(network_traffic);')
        columns = [col[1] for col in cursor.fetchall()]
        print(f"Columns: {', '.join(columns)}")
        
        for i, row in enumerate(sample, 1):
            print(f"Record {i}: {row[:5]}... (truncated)")
        
        conn.close()
        print("\n✓ Database verification completed successfully")
        
    except sqlite3.Error as e:
        print(f"✗ Database error: {e}")

if __name__ == "__main__":
    verify_database()