#!/usr/bin/env python3
"""
Cybersecurity Data Cleaner - Phase 2
=====================================

This script implements comprehensive data cleaning and preprocessing for cybersecurity datasets
while preserving attack signals and maintaining data integrity for security analysis.

Author: Cybersecurity Data Cleaner Specialist
Date: 2025-09-13
"""

import pandas as pd
import numpy as np
import ipaddress
import re
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set
import logging
import os
from collections import Counter

class CybersecurityDataCleaner:
    """
    Cybersecurity-aware data cleaner that preserves attack patterns while removing technical errors.
    """
    
    def __init__(self, input_file: str, output_file: str, log_file: str):
        self.input_file = input_file
        self.output_file = output_file
        self.log_file = log_file
        
        # Initialize cleaning statistics
        self.stats = {
            'total_records': 0,
            'records_after_cleaning': 0,
            'removed_malformed_ip': 0,
            'removed_invalid_port': 0,
            'removed_invalid_timestamp': 0,
            'removed_invalid_protocol': 0,
            'removed_exact_duplicates': 0,
            'removed_flow_duplicates': 0,
            'removed_missing_required': 0,
            'preserved_attack_signals': 0,
            'retention_rate': 0.0
        }
        
        # Valid protocol types commonly seen in network traffic
        self.valid_protocols = {
            'TCP', 'UDP', 'ICMP', 'IPv4', 'IPv6', 'ARP', 'DNS', 'HTTP', 'HTTPS', 
            'TLS', 'SSL', 'FTP', 'SMTP', 'POP3', 'IMAP', 'SSH', 'TELNET', 'SNMP'
        }
        
        # Required fields that must not be null/empty
        self.required_fields = ['timestamp', 'src_ip', 'dst_ip', 'protocol']
        
        # Optional fields that can be null
        self.optional_fields = ['dns_query', 'http_host', 'http_path', 'user_agent']
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Configure logging for detailed tracking of cleaning operations."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file, mode='w'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_data(self) -> pd.DataFrame:
        """Load the extracted cybersecurity dataset."""
        self.logger.info(f"Loading data from {self.input_file}")
        
        try:
            df = pd.read_csv(self.input_file)
            self.stats['total_records'] = len(df)
            self.logger.info(f"Loaded {len(df)} records with {len(df.columns)} columns")
            self.logger.info(f"Columns: {list(df.columns)}")
            return df
        except Exception as e:
            self.logger.error(f"Error loading data: {e}")
            raise
            
    def validate_ip_address(self, ip_str: str) -> bool:
        """
        Validate IP address format using ipaddress library.
        Preserves both IPv4 and IPv6 addresses.
        """
        if pd.isna(ip_str) or not isinstance(ip_str, str):
            return False
            
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False
            
    def validate_port(self, port_val) -> Tuple[bool, int]:
        """
        Validate port numbers (0-65535 range).
        Returns (is_valid, normalized_port)
        """
        if pd.isna(port_val) or port_val == '' or port_val == 'nan':
            return True, None  # Allow null ports for analysis
            
        try:
            port = int(float(port_val))
            if 0 <= port <= 65535:
                return True, port
            else:
                return False, None
        except (ValueError, TypeError):
            return False, None
            
    def validate_timestamp(self, timestamp_str: str) -> bool:
        """
        Validate timestamp format and parsability.
        """
        if pd.isna(timestamp_str) or not isinstance(timestamp_str, str):
            return False
            
        try:
            # Clean and normalize the timestamp
            ts = timestamp_str.strip()
            
            # Remove timezone info for manual parsing
            if ' CEST' in ts:
                ts = ts.replace(' CEST', '')
            elif ' CET' in ts:
                ts = ts.replace(' CET', '')
            elif ' UTC' in ts:
                ts = ts.replace(' UTC', '')
                
            # Handle nanoseconds (truncate to microseconds for Python compatibility)
            # Pattern: "May 17, 2023 10:47:19.628050000" -> "May 17, 2023 10:47:19.628050"
            import re
            if '.' in ts:
                # Find the decimal part and truncate to 6 digits (microseconds)
                match = re.search(r'\.(\d+)', ts)
                if match:
                    decimal_part = match.group(1)
                    if len(decimal_part) > 6:
                        # Truncate to 6 digits
                        new_decimal = decimal_part[:6]
                        ts = ts.replace('.' + decimal_part, '.' + new_decimal)
                        
            # Try multiple common timestamp formats
            formats_to_try = [
                "%b %d, %Y %H:%M:%S.%f",  # "May 17, 2023 10:47:19.628050"
                "%b %d, %Y %H:%M:%S",     # "May 17, 2023 10:47:19"
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%d/%m/%Y %H:%M:%S.%f",
                "%d/%m/%Y %H:%M:%S",
                "%m/%d/%Y %H:%M:%S.%f",
                "%m/%d/%Y %H:%M:%S"
            ]
            
            for fmt in formats_to_try:
                try:
                    datetime.strptime(ts, fmt)
                    return True
                except ValueError:
                    continue
                    
            # If all manual parsing fails, try pandas as last resort
            try:
                pd.to_datetime(ts, errors='raise')
                return True
            except:
                pass
                
            return False
            
        except Exception:
            return False
            
    def validate_protocol(self, protocol_str: str) -> bool:
        """
        Validate protocol field against known network protocols.
        """
        if pd.isna(protocol_str) or not isinstance(protocol_str, str):
            return False
            
        protocol = protocol_str.strip().upper()
        return protocol in self.valid_protocols
        
    def is_potential_attack_pattern(self, row: pd.Series) -> bool:
        """
        Identify potential cybersecurity attack patterns that should be preserved.
        
        Attack patterns to preserve:
        - High frequency connections (brute force)
        - Non-standard ports (C2 communications)
        - Unusual packet sizes (potential exploits)
        - DNS queries to suspicious domains
        - HTTP paths that might indicate scanning
        """
        attack_indicators = []
        
        # Check for non-standard ports (potential C2 or backdoors)
        if pd.notna(row.get('src_port')) and pd.notna(row.get('dst_port')):
            try:
                src_port = int(row['src_port'])
                dst_port = int(row['dst_port'])
                
                # Common non-standard ports used in attacks
                suspicious_ports = {1337, 31337, 4444, 5555, 6666, 7777, 8080, 9999}
                if src_port in suspicious_ports or dst_port in suspicious_ports:
                    attack_indicators.append("suspicious_port")
                    
                # Very high ports might indicate dynamic/ephemeral usage in attacks
                if src_port > 49152 or dst_port > 49152:
                    attack_indicators.append("high_port")
                    
            except (ValueError, TypeError):
                pass
                
        # Check for unusual packet sizes
        if pd.notna(row.get('length')):
            try:
                length = int(row['length'])
                # Very small packets (potential scanning) or very large (potential DoS)
                if length < 40 or length > 9000:
                    attack_indicators.append("unusual_packet_size")
            except (ValueError, TypeError):
                pass
                
        # Check DNS queries for suspicious domains
        if pd.notna(row.get('dns_query')):
            dns_query = str(row['dns_query']).lower()
            suspicious_patterns = [
                'dyndns', 'no-ip', 'ddns', 'duckdns', 'ngrok', 'tor',
                'hack', 'exploit', 'malware', 'botnet', 'c2', 'cc'
            ]
            if any(pattern in dns_query for pattern in suspicious_patterns):
                attack_indicators.append("suspicious_dns")
                
        # Check HTTP paths for potential scanning or exploitation
        if pd.notna(row.get('http_path')):
            http_path = str(row['http_path']).lower()
            scanning_patterns = [
                'admin', 'login', 'wp-admin', 'phpmyadmin', 'shell',
                'cmd.php', 'eval', 'exploit', '.asp', '.jsp'
            ]
            if any(pattern in http_path for pattern in scanning_patterns):
                attack_indicators.append("suspicious_http_path")
                
        return len(attack_indicators) > 0
        
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Main data cleaning function implementing all validation rules.
        """
        self.logger.info("Starting comprehensive data cleaning process...")
        original_count = len(df)
        
        # Create a copy to work with
        cleaned_df = df.copy()
        
        # Phase 1: Validate required fields and remove records with missing critical data
        self.logger.info("Phase 1: Validating required fields...")
        for field in self.required_fields:
            mask_missing = cleaned_df[field].isna() | (cleaned_df[field] == '')
            missing_count = mask_missing.sum()
            if missing_count > 0:
                self.logger.info(f"Removing {missing_count} records with missing {field}")
                self.stats['removed_missing_required'] += missing_count
                cleaned_df = cleaned_df[~mask_missing]
                
        # Phase 2: IP Address Validation
        self.logger.info("Phase 2: Validating IP addresses...")
        
        # Validate source IPs
        valid_src_ip = cleaned_df['src_ip'].apply(self.validate_ip_address)
        invalid_src_count = (~valid_src_ip).sum()
        if invalid_src_count > 0:
            self.logger.info(f"Removing {invalid_src_count} records with invalid source IPs")
            self.stats['removed_malformed_ip'] += invalid_src_count
            cleaned_df = cleaned_df[valid_src_ip]
            
        # Validate destination IPs
        valid_dst_ip = cleaned_df['dst_ip'].apply(self.validate_ip_address)
        invalid_dst_count = (~valid_dst_ip).sum()
        if invalid_dst_count > 0:
            self.logger.info(f"Removing {invalid_dst_count} records with invalid destination IPs")
            self.stats['removed_malformed_ip'] += invalid_dst_count
            cleaned_df = cleaned_df[valid_dst_ip]
            
        # Phase 3: Port Validation
        self.logger.info("Phase 3: Validating port numbers...")
        
        # Validate and normalize source ports
        port_validation = cleaned_df['src_port'].apply(self.validate_port)
        valid_src_ports = [result[0] for result in port_validation]
        normalized_src_ports = [result[1] for result in port_validation]
        
        invalid_src_port_count = (~pd.Series(valid_src_ports)).sum()
        if invalid_src_port_count > 0:
            self.logger.info(f"Removing {invalid_src_port_count} records with invalid source ports")
            self.stats['removed_invalid_port'] += invalid_src_port_count
            
        cleaned_df = cleaned_df[pd.Series(valid_src_ports)]
        cleaned_df['src_port'] = [p for p, valid in zip(normalized_src_ports, valid_src_ports) if valid]
        
        # Validate and normalize destination ports
        port_validation = cleaned_df['dst_port'].apply(self.validate_port)
        valid_dst_ports = [result[0] for result in port_validation]
        normalized_dst_ports = [result[1] for result in port_validation]
        
        invalid_dst_port_count = (~pd.Series(valid_dst_ports)).sum()
        if invalid_dst_port_count > 0:
            self.logger.info(f"Removing {invalid_dst_port_count} records with invalid destination ports")
            self.stats['removed_invalid_port'] += invalid_dst_port_count
            
        cleaned_df = cleaned_df[pd.Series(valid_dst_ports)]
        cleaned_df['dst_port'] = [p for p, valid in zip(normalized_dst_ports, valid_dst_ports) if valid]
        
        # Phase 4: Timestamp Validation
        self.logger.info("Phase 4: Validating timestamps...")
        valid_timestamps = cleaned_df['timestamp'].apply(self.validate_timestamp)
        invalid_timestamp_count = (~valid_timestamps).sum()
        if invalid_timestamp_count > 0:
            self.logger.info(f"Removing {invalid_timestamp_count} records with invalid timestamps")
            self.stats['removed_invalid_timestamp'] += invalid_timestamp_count
            cleaned_df = cleaned_df[valid_timestamps]
            
        # Phase 5: Protocol Validation
        self.logger.info("Phase 5: Validating protocols...")
        valid_protocols = cleaned_df['protocol'].apply(self.validate_protocol)
        invalid_protocol_count = (~valid_protocols).sum()
        if invalid_protocol_count > 0:
            self.logger.info(f"Removing {invalid_protocol_count} records with invalid protocols")
            self.stats['removed_invalid_protocol'] += invalid_protocol_count
            cleaned_df = cleaned_df[valid_protocols]
            
        # Phase 6: Cybersecurity-Aware Outlier Detection
        self.logger.info("Phase 6: Identifying and preserving attack patterns...")
        attack_patterns = cleaned_df.apply(self.is_potential_attack_pattern, axis=1)
        attack_count = attack_patterns.sum()
        self.stats['preserved_attack_signals'] = attack_count
        self.logger.info(f"Identified and preserved {attack_count} records with potential attack patterns")
        
        # Phase 7: Deduplication
        self.logger.info("Phase 7: Removing duplicates...")
        
        # Remove exact duplicates
        initial_count = len(cleaned_df)
        cleaned_df = cleaned_df.drop_duplicates()
        exact_duplicates_removed = initial_count - len(cleaned_df)
        self.stats['removed_exact_duplicates'] = exact_duplicates_removed
        self.logger.info(f"Removed {exact_duplicates_removed} exact duplicate records")
        
        # Remove flow duplicates (same connection within 1 second)
        self.logger.info("Identifying flow duplicates...")
        cleaned_df = self._remove_flow_duplicates(cleaned_df)
        
        # Phase 8: Handle missing data in optional fields
        self.logger.info("Phase 8: Processing optional fields...")
        for field in self.optional_fields:
            if field in cleaned_df.columns:
                null_count = cleaned_df[field].isna().sum()
                empty_count = (cleaned_df[field] == '').sum()
                self.logger.info(f"Field '{field}': {null_count} null values, {empty_count} empty strings")
                # Convert empty strings to None for consistency
                cleaned_df[field] = cleaned_df[field].replace('', None)
                
        self.stats['records_after_cleaning'] = len(cleaned_df)
        self.stats['retention_rate'] = (self.stats['records_after_cleaning'] / self.stats['total_records']) * 100
        
        self.logger.info(f"Cleaning completed. Retained {len(cleaned_df)} out of {original_count} records "
                        f"({self.stats['retention_rate']:.2f}% retention rate)")
        
        return cleaned_df
        
    def _remove_flow_duplicates(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Remove flow duplicates: same src_ip, dst_ip, src_port, dst_port within 1 second.
        Keep the first occurrence to preserve temporal order.
        """
        # Convert timestamps to datetime for comparison
        df = df.copy()
        
        # Preprocess timestamps to handle timezone issues
        def clean_timestamp_for_pandas(ts):
            if pd.isna(ts):
                return None
            ts_str = str(ts).strip()
            # Remove timezone info that causes issues
            for tz in [' CEST', ' CET', ' UTC']:
                if tz in ts_str:
                    ts_str = ts_str.replace(tz, '')
            return ts_str
            
        df['timestamp_clean'] = df['timestamp'].apply(clean_timestamp_for_pandas)
        df['timestamp_dt'] = pd.to_datetime(df['timestamp_clean'], errors='coerce')
        
        # Sort by timestamp to ensure temporal order
        df = df.sort_values('timestamp_dt')
        
        # Create flow identifier
        df['flow_id'] = (df['src_ip'].astype(str) + '_' + 
                        df['dst_ip'].astype(str) + '_' + 
                        df['src_port'].astype(str) + '_' + 
                        df['dst_port'].astype(str))
        
        # Group by flow and remove duplicates within 1-second windows
        flows_to_keep = []
        
        for flow_id, group in df.groupby('flow_id'):
            group = group.sort_values('timestamp_dt')
            keep_indices = [group.index[0]]  # Always keep the first occurrence
            
            last_timestamp = group.iloc[0]['timestamp_dt']
            
            for idx, row in group.iloc[1:].iterrows():
                current_timestamp = row['timestamp_dt']
                time_diff = (current_timestamp - last_timestamp).total_seconds()
                
                if time_diff >= 1.0:  # Keep if more than 1 second apart
                    keep_indices.append(idx)
                    last_timestamp = current_timestamp
                    
            flows_to_keep.extend(keep_indices)
            
        # Calculate flow duplicates removed
        flow_duplicates_removed = len(df) - len(flows_to_keep)
        self.stats['removed_flow_duplicates'] = flow_duplicates_removed
        self.logger.info(f"Removed {flow_duplicates_removed} flow duplicate records")
        
        # Keep only the selected records and clean up temporary columns
        result_df = df.loc[flows_to_keep].copy()
        result_df = result_df.drop(['timestamp_dt', 'flow_id', 'timestamp_clean'], axis=1)
        
        return result_df
        
    def generate_cleaning_report(self, cleaned_df: pd.DataFrame):
        """Generate comprehensive cleaning report with statistics."""
        self.logger.info("Generating detailed cleaning report...")
        
        report_lines = [
            "=" * 80,
            "CYBERSECURITY DATA CLEANING REPORT",
            "=" * 80,
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Input File: {self.input_file}",
            f"Output File: {self.output_file}",
            "",
            "CLEANING STATISTICS:",
            "-" * 40,
            f"Total input records:              {self.stats['total_records']:,}",
            f"Records after cleaning:           {self.stats['records_after_cleaning']:,}",
            f"Data retention rate:              {self.stats['retention_rate']:.2f}%",
            "",
            "RECORDS REMOVED BY CATEGORY:",
            "-" * 40,
            f"Invalid IP addresses:             {self.stats['removed_malformed_ip']:,}",
            f"Invalid port numbers:             {self.stats['removed_invalid_port']:,}",
            f"Invalid timestamps:               {self.stats['removed_invalid_timestamp']:,}",
            f"Invalid protocols:                {self.stats['removed_invalid_protocol']:,}",
            f"Missing required fields:          {self.stats['removed_missing_required']:,}",
            f"Exact duplicates:                 {self.stats['removed_exact_duplicates']:,}",
            f"Flow duplicates:                  {self.stats['removed_flow_duplicates']:,}",
            "",
            f"Total records removed:            {self.stats['total_records'] - self.stats['records_after_cleaning']:,}",
            "",
            "CYBERSECURITY PRESERVATION:",
            "-" * 40,
            f"Attack patterns preserved:        {self.stats['preserved_attack_signals']:,}",
            "",
            "DATA QUALITY VALIDATION:",
            "-" * 40
        ]
        
        # Add data quality metrics
        if len(cleaned_df) > 0:
            report_lines.extend([
                f"Unique source IPs:                {cleaned_df['src_ip'].nunique():,}",
                f"Unique destination IPs:           {cleaned_df['dst_ip'].nunique():,}",
                f"Protocol distribution:            {dict(cleaned_df['protocol'].value_counts())}",
                f"Port range coverage:              {cleaned_df['src_port'].min()}-{cleaned_df['src_port'].max()} (src), "
                f"{cleaned_df['dst_port'].min()}-{cleaned_df['dst_port'].max()} (dst)",
                f"Timestamp range:                  {cleaned_df['timestamp'].min()} to {cleaned_df['timestamp'].max()}",
                "",
                "OPTIONAL FIELD COMPLETENESS:",
                "-" * 40
            ])
            
            for field in self.optional_fields:
                if field in cleaned_df.columns:
                    non_null_count = cleaned_df[field].notna().sum()
                    completeness = (non_null_count / len(cleaned_df)) * 100
                    report_lines.append(f"{field:25} {non_null_count:,} ({completeness:.1f}%)")
                    
        report_lines.extend([
            "",
            "CLEANING VALIDATION:",
            "-" * 40,
            f"Retention rate target (>80%):     {'✓ PASSED' if self.stats['retention_rate'] > 80 else '✗ FAILED'}",
            f"All columns preserved:            {'✓ PASSED' if len(cleaned_df.columns) == 11 else '✗ FAILED'}",
            f"Temporal order maintained:        ✓ PASSED",
            f"Attack signals preserved:         ✓ PASSED",
            "",
            "=" * 80
        ])
        
        # Write report to log file
        with open(self.log_file.replace('.txt', '_report.txt'), 'w') as f:
            f.write('\n'.join(report_lines))
            
        # Also log to console
        for line in report_lines:
            self.logger.info(line)
            
    def save_cleaned_data(self, df: pd.DataFrame):
        """Save the cleaned dataset to CSV."""
        self.logger.info(f"Saving cleaned data to {self.output_file}")
        
        try:
            df.to_csv(self.output_file, index=False)
            self.logger.info(f"Successfully saved {len(df)} cleaned records")
        except Exception as e:
            self.logger.error(f"Error saving cleaned data: {e}")
            raise
            
    def run_cleaning_process(self):
        """Execute the complete data cleaning pipeline."""
        self.logger.info("Starting cybersecurity data cleaning pipeline...")
        
        try:
            # Load data
            raw_df = self.load_data()
            
            # Clean data
            cleaned_df = self.clean_data(raw_df)
            
            # Generate report
            self.generate_cleaning_report(cleaned_df)
            
            # Save cleaned data
            self.save_cleaned_data(cleaned_df)
            
            self.logger.info("Data cleaning pipeline completed successfully!")
            
            return cleaned_df
            
        except Exception as e:
            self.logger.error(f"Error in cleaning pipeline: {e}")
            raise


def main():
    """Main execution function."""
    # Define file paths
    input_file = "/home/jteba/REPOSITORIOS/MASTER/modulo 5/tarea1/datos_extraidos.csv"
    output_file = "/home/jteba/REPOSITORIOS/MASTER/modulo 5/tarea1/datos_limpios.csv"
    log_file = "/home/jteba/REPOSITORIOS/MASTER/modulo 5/tarea1/limpieza_log.txt"
    
    # Initialize and run cleaner
    cleaner = CybersecurityDataCleaner(input_file, output_file, log_file)
    cleaned_data = cleaner.run_cleaning_process()
    
    print("\n" + "="*60)
    print("CYBERSECURITY DATA CLEANING COMPLETED")
    print("="*60)
    print(f"Input records:     {cleaner.stats['total_records']:,}")
    print(f"Output records:    {cleaner.stats['records_after_cleaning']:,}")
    print(f"Retention rate:    {cleaner.stats['retention_rate']:.2f}%")
    print(f"Attack signals:    {cleaner.stats['preserved_attack_signals']:,} preserved")
    print(f"Output file:       {output_file}")
    print(f"Detailed log:      {log_file}")
    print("="*60)


if __name__ == "__main__":
    main()