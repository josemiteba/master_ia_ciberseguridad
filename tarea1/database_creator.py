#!/usr/bin/env python3
"""
Cybersecurity Dataset Database Creator - Phase 4
Creates SQLite database with anonymized network traffic data and executes analytical queries.

Project: Tools4Trading Database Optimization
Database: cybersecurity_dataset.db (SQLite)
Input: datos_anonimizados.csv (6,588 records)

Author: Database Optimization Specialist
Date: 2025-09-13
"""

import sqlite3
import pandas as pd
import os
from datetime import datetime
import sys

class CybersecurityDatabaseCreator:
    def __init__(self, csv_file='datos_anonimizados.csv', db_file='cybersecurity_dataset.db'):
        self.csv_file = csv_file
        self.db_file = db_file
        self.conn = None
        self.results = []
        
    def create_connection(self):
        """Create SQLite database connection"""
        try:
            self.conn = sqlite3.connect(self.db_file)
            print(f"✓ Connected to SQLite database: {self.db_file}")
            return True
        except sqlite3.Error as e:
            print(f"✗ Error connecting to database: {e}")
            return False
    
    def create_table_schema(self):
        """Create network_traffic table with specified schema"""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS network_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip_anon TEXT NOT NULL,
            dst_ip_anon TEXT NOT NULL, 
            protocol TEXT NOT NULL,
            src_port INTEGER,
            dst_port INTEGER,
            length INTEGER NOT NULL,
            dns_query TEXT,
            http_host TEXT,
            http_path TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        try:
            cursor = self.conn.cursor()
            cursor.execute(create_table_sql)
            self.conn.commit()
            print("✓ Created network_traffic table schema")
            return True
        except sqlite3.Error as e:
            print(f"✗ Error creating table: {e}")
            return False
    
    def create_indexes(self):
        """Create performance indexes on key columns"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON network_traffic(timestamp);",
            "CREATE INDEX IF NOT EXISTS idx_src_ip ON network_traffic(src_ip_anon);",
            "CREATE INDEX IF NOT EXISTS idx_dst_ip ON network_traffic(dst_ip_anon);",
            "CREATE INDEX IF NOT EXISTS idx_protocol ON network_traffic(protocol);",
            "CREATE INDEX IF NOT EXISTS idx_dst_port ON network_traffic(dst_port);"
        ]
        
        try:
            cursor = self.conn.cursor()
            for index_sql in indexes:
                cursor.execute(index_sql)
            self.conn.commit()
            print("✓ Created performance indexes")
            return True
        except sqlite3.Error as e:
            print(f"✗ Error creating indexes: {e}")
            return False
    
    def load_data(self):
        """Load CSV data into database using pandas"""
        try:
            # Check if CSV file exists
            if not os.path.exists(self.csv_file):
                print(f"✗ CSV file not found: {self.csv_file}")
                return False
            
            # Read CSV file
            print(f"Reading CSV file: {self.csv_file}")
            df = pd.read_csv(self.csv_file)
            
            # Display data info
            print(f"✓ Loaded {len(df)} records from CSV")
            print(f"Columns: {list(df.columns)}")
            
            # Convert port columns to nullable integers
            df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').astype('Int64')
            df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').astype('Int64')
            df['length'] = pd.to_numeric(df['length'], errors='coerce').fillna(0).astype(int)
            
            # Handle NULL/empty values
            df = df.where(pd.notnull(df), None)
            
            # Load data to SQLite using pandas
            df.to_sql('network_traffic', self.conn, if_exists='replace', index=False)
            
            print(f"✓ Loaded {len(df)} records into network_traffic table")
            return True
            
        except Exception as e:
            print(f"✗ Error loading data: {e}")
            return False
    
    def execute_query(self, query_name, sql_query):
        """Execute a single analytical query and capture results"""
        try:
            cursor = self.conn.cursor()
            start_time = datetime.now()
            
            cursor.execute(sql_query)
            results = cursor.fetchall()
            
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            
            # Get column names
            column_names = [description[0] for description in cursor.description]
            
            result_data = {
                'query_name': query_name,
                'sql': sql_query,
                'results': results,
                'columns': column_names,
                'row_count': len(results),
                'execution_time': execution_time
            }
            
            self.results.append(result_data)
            print(f"✓ Executed {query_name}: {len(results)} rows in {execution_time:.4f}s")
            
            return result_data
            
        except sqlite3.Error as e:
            print(f"✗ Error executing {query_name}: {e}")
            return None
    
    def execute_analytical_queries(self):
        """Execute all 6 required analytical queries"""
        queries = [
            {
                'name': '1. Total Records',
                'sql': 'SELECT COUNT(*) as total_records FROM network_traffic;'
            },
            {
                'name': '2. Top 10 Destination IPs',
                'sql': '''SELECT dst_ip_anon, COUNT(*) as count 
                         FROM network_traffic 
                         GROUP BY dst_ip_anon 
                         ORDER BY count DESC 
                         LIMIT 10;'''
            },
            {
                'name': '3. Most Queried Domains',
                'sql': '''SELECT dns_query, COUNT(*) as count 
                         FROM network_traffic 
                         WHERE dns_query IS NOT NULL AND dns_query != ''
                         GROUP BY dns_query 
                         ORDER BY count DESC 
                         LIMIT 10;'''
            },
            {
                'name': '4. Common Destination Ports',
                'sql': '''SELECT dst_port, COUNT(*) as count,
                                 CASE 
                                   WHEN dst_port = 80 THEN 'HTTP'
                                   WHEN dst_port = 443 THEN 'HTTPS'
                                   WHEN dst_port = 53 THEN 'DNS'
                                   ELSE 'Other'
                                 END as service_type
                         FROM network_traffic 
                         WHERE dst_port IS NOT NULL 
                         GROUP BY dst_port 
                         ORDER BY count DESC 
                         LIMIT 10;'''
            },
            {
                'name': '5. Packet Length Statistics',
                'sql': '''SELECT 
                             AVG(length) as avg_length,
                             MAX(length) as max_length,
                             MIN(length) as min_length,
                             CAST(AVG(length) AS INTEGER) as avg_length_int
                         FROM network_traffic 
                         WHERE length IS NOT NULL;'''
            },
            {
                'name': '6. Protocol Distribution',
                'sql': '''SELECT protocol, 
                                 COUNT(*) as count,
                                 ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM network_traffic), 2) as percentage
                         FROM network_traffic 
                         WHERE protocol IS NOT NULL
                         GROUP BY protocol 
                         ORDER BY count DESC;'''
            }
        ]
        
        print("\n" + "="*60)
        print("EXECUTING ANALYTICAL QUERIES")
        print("="*60)
        
        for query in queries:
            self.execute_query(query['name'], query['sql'])
        
        return len(self.results) == len(queries)
    
    def format_results(self):
        """Format query results for output"""
        output_lines = []
        
        output_lines.append("CYBERSECURITY DATABASE ANALYTICAL RESULTS")
        output_lines.append("=" * 50)
        output_lines.append(f"Database: {self.db_file}")
        output_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        output_lines.append("")
        
        for i, result in enumerate(self.results, 1):
            output_lines.append(f"\n{'-' * 60}")
            output_lines.append(f"QUERY {i}: {result['query_name']}")
            output_lines.append(f"{'-' * 60}")
            output_lines.append(f"SQL: {result['sql']}")
            output_lines.append(f"Execution Time: {result['execution_time']:.4f} seconds")
            output_lines.append(f"Rows Returned: {result['row_count']}")
            output_lines.append("")
            
            # Format results as table
            if result['results']:
                # Column headers
                headers = result['columns']
                output_lines.append(" | ".join(f"{h:>15}" for h in headers))
                output_lines.append("-" * (len(headers) * 18))
                
                # Data rows
                for row in result['results']:
                    formatted_row = []
                    for val in row:
                        if val is None:
                            formatted_row.append("NULL")
                        elif isinstance(val, float):
                            formatted_row.append(f"{val:.2f}")
                        else:
                            formatted_row.append(str(val))
                    output_lines.append(" | ".join(f"{val:>15}" for val in formatted_row))
            else:
                output_lines.append("No results returned")
                
        return "\n".join(output_lines)
    
    def save_results(self, output_file='resultados_consultas.txt'):
        """Save query results to text file"""
        try:
            formatted_output = self.format_results()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(formatted_output)
            
            print(f"✓ Results saved to: {output_file}")
            return True
            
        except Exception as e:
            print(f"✗ Error saving results: {e}")
            return False
    
    def validate_database(self):
        """Validate database integrity and structure"""
        try:
            cursor = self.conn.cursor()
            
            # Check table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='network_traffic';")
            if not cursor.fetchone():
                print("✗ Table network_traffic not found")
                return False
            
            # Check record count
            cursor.execute("SELECT COUNT(*) FROM network_traffic;")
            count = cursor.fetchone()[0]
            
            # Check indexes
            cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='network_traffic';")
            indexes = cursor.fetchall()
            
            print(f"✓ Database validation complete:")
            print(f"  - Records: {count}")
            print(f"  - Indexes: {len(indexes)}")
            
            return True
            
        except sqlite3.Error as e:
            print(f"✗ Database validation error: {e}")
            return False
    
    def close_connection(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("✓ Database connection closed")
    
    def run_complete_process(self):
        """Execute the complete database creation and analysis process"""
        print("CYBERSECURITY DATABASE CREATOR - PHASE 4")
        print("=" * 50)
        
        success = True
        
        # Step 1: Create connection
        if not self.create_connection():
            return False
        
        # Step 2: Create table schema
        if not self.create_table_schema():
            success = False
        
        # Step 3: Load data
        if success and not self.load_data():
            success = False
        
        # Step 4: Create indexes
        if success and not self.create_indexes():
            success = False
        
        # Step 5: Execute analytical queries
        if success and not self.execute_analytical_queries():
            success = False
        
        # Step 6: Save results
        if success and not self.save_results():
            success = False
        
        # Step 7: Validate database
        if success and not self.validate_database():
            success = False
        
        # Step 8: Close connection
        self.close_connection()
        
        if success:
            print("\n" + "="*60)
            print("✓ DATABASE CREATION COMPLETED SUCCESSFULLY")
            print("="*60)
            print(f"Database file: {os.path.abspath(self.db_file)}")
            print(f"Results file: {os.path.abspath('resultados_consultas.txt')}")
            print(f"Script file: {os.path.abspath(__file__)}")
        else:
            print("\n" + "="*60)
            print("✗ DATABASE CREATION FAILED")
            print("="*60)
        
        return success


def main():
    """Main execution function"""
    # Initialize database creator
    db_creator = CybersecurityDatabaseCreator()
    
    # Run complete process
    success = db_creator.run_complete_process()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()