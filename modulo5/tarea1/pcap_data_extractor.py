#!/usr/bin/env python3
"""
PCAP Data Extractor - Phase 1 of Cybersecurity Dataset Creation
==============================================================

Extracts structured cybersecurity-relevant data from PCAP files using tshark.
Focuses on HTTP/HTTPS, DNS, and external IP traffic while filtering network noise.

Author: PCAP Analyst Specialist
Date: 2025-09-13
"""

import os
import subprocess
import csv
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import pandas as pd
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('extraccion_log.txt'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Protocol mapping for ip.proto field
PROTOCOL_MAPPING = {
    '1': 'ICMP',
    '2': 'IGMP', 
    '6': 'TCP',
    '17': 'UDP',
    '41': 'IPv6',
    '47': 'GRE',
    '50': 'ESP',
    '51': 'AH',
    '58': 'ICMPv6',
    '89': 'OSPF',
    '132': 'SCTP'
}

# Ports to filter out (network noise)
NOISE_PORTS = {
    67, 68,      # DHCP
    137, 138,    # NetBIOS
    1900,        # SSDP
    5353,        # mDNS/Bonjour
    5355,        # LLMNR
}

# Important cybersecurity ports to keep
IMPORTANT_PORTS = {
    53,          # DNS
    80, 443,     # HTTP/HTTPS
    8080, 8443,  # Alternative HTTP/HTTPS
    21, 22,      # FTP, SSH
    23, 25,      # Telnet, SMTP
    110, 143,    # POP3, IMAP
    993, 995,    # IMAPS, POP3S
    3389,        # RDP
    5900,        # VNC
    1433, 3306,  # SQL Server, MySQL
    5432,        # PostgreSQL
    6379,        # Redis
    27017,       # MongoDB
}

class PCAPDataExtractor:
    """Main class for extracting cybersecurity data from PCAP files."""
    
    def __init__(self, pcap_dir: str, output_csv: str):
        self.pcap_dir = Path(pcap_dir)
        self.output_csv = output_csv
        self.total_packets = 0
        self.filtered_packets = 0
        self.processed_files = 0
        self.failed_files = 0
        
        # CSV headers exactly as specified
        self.csv_headers = [
            'timestamp', 'src_ip', 'dst_ip', 'protocol', 
            'src_port', 'dst_port', 'length', 'dns_query',
            'http_host', 'http_path', 'user_agent'
        ]
    
    def get_pcap_files(self) -> List[Path]:
        """Get all .pcapng files from the directory."""
        pcap_files = list(self.pcap_dir.glob('*.pcapng'))
        logger.info(f"Found {len(pcap_files)} PCAP files to process")
        return sorted(pcap_files)
    
    def build_tshark_command(self, pcap_file: Path) -> List[str]:
        """Build the tshark command with all required fields."""
        cmd = [
            'tshark', '-r', str(pcap_file),
            '-T', 'fields',
            '-e', 'frame.time',           # timestamp
            '-e', 'ip.src',               # src_ip
            '-e', 'ip.dst',               # dst_ip
            '-e', 'ip.proto',             # protocol (numeric)
            '-e', 'tcp.srcport',          # TCP source port
            '-e', 'tcp.dstport',          # TCP destination port
            '-e', 'udp.srcport',          # UDP source port
            '-e', 'udp.dstport',          # UDP destination port
            '-e', 'frame.len',            # length
            '-e', 'dns.qry.name',         # dns_query
            '-e', 'http.host',            # http_host
            '-e', 'http.request.uri',     # http_path
            '-e', 'http.user_agent',      # user_agent
            '-E', 'header=y',
            '-E', 'separator=,',
            '-E', 'occurrence=f',
            '-E', 'quote=d'               # Quote fields with double quotes
        ]
        return cmd
    
    def is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal/private."""
        if not ip or ip == '':
            return True
        
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return True
                
            first = int(octets[0])
            second = int(octets[1])
            
            # RFC 1918 private addresses
            if first == 10:
                return True
            elif first == 172 and 16 <= second <= 31:
                return True
            elif first == 192 and second == 168:
                return True
            # Loopback
            elif first == 127:
                return True
            # Link-local
            elif first == 169 and second == 254:
                return True
                
        except (ValueError, IndexError):
            return True
            
        return False
    
    def should_filter_packet(self, row: Dict[str, str]) -> bool:
        """Determine if packet should be filtered out based on cybersecurity relevance."""
        protocol = row.get('protocol', '').upper()
        src_ip = row.get('src_ip', '')
        dst_ip = row.get('dst_ip', '')
        src_port = row.get('src_port', '')
        dst_port = row.get('dst_port', '')
        
        # Filter out packets without IP addresses
        if not src_ip or not dst_ip:
            return True
        
        # Convert ports to integers for comparison
        try:
            src_port_int = int(src_port) if src_port else 0
            dst_port_int = int(dst_port) if dst_port else 0
        except ValueError:
            src_port_int = dst_port_int = 0
        
        # Always keep DNS traffic
        if src_port_int == 53 or dst_port_int == 53:
            return False
        
        # Always keep HTTP/HTTPS traffic
        if (src_port_int in {80, 443, 8080, 8443} or 
            dst_port_int in {80, 443, 8080, 8443}):
            return False
        
        # Filter out network noise ports
        if (src_port_int in NOISE_PORTS or dst_port_int in NOISE_PORTS):
            return True
        
        # Keep traffic involving important security ports
        if (src_port_int in IMPORTANT_PORTS or dst_port_int in IMPORTANT_PORTS):
            return False
        
        # Keep external IP traffic (at least one IP should be external)
        if not (self.is_internal_ip(src_ip) and self.is_internal_ip(dst_ip)):
            return False
        
        # Keep packets with HTTP/DNS application data
        if (row.get('http_host') or row.get('http_path') or 
            row.get('user_agent') or row.get('dns_query')):
            return False
        
        # Filter out pure internal traffic with no interesting ports
        if (self.is_internal_ip(src_ip) and self.is_internal_ip(dst_ip) and
            src_port_int not in IMPORTANT_PORTS and dst_port_int not in IMPORTANT_PORTS):
            return True
        
        return False
    
    def process_tshark_row(self, raw_row: str) -> Optional[Dict[str, str]]:
        """Process a single row from tshark output and normalize data."""
        try:
            # Split CSV row accounting for quoted fields
            import csv
            from io import StringIO
            
            csv_reader = csv.reader(StringIO(raw_row))
            fields = next(csv_reader)
            
            if len(fields) < 13:
                return None
            
            # Map raw tshark fields to our structure
            timestamp = fields[0].strip('"') if fields[0] else ''
            src_ip = fields[1].strip('"') if fields[1] else ''
            dst_ip = fields[2].strip('"') if fields[2] else ''
            protocol_num = fields[3].strip('"') if fields[3] else ''
            tcp_src = fields[4].strip('"') if fields[4] else ''
            tcp_dst = fields[5].strip('"') if fields[5] else ''
            udp_src = fields[6].strip('"') if fields[6] else ''
            udp_dst = fields[7].strip('"') if fields[7] else ''
            length = fields[8].strip('"') if fields[8] else '0'
            dns_query = fields[9].strip('"') if fields[9] else ''
            http_host = fields[10].strip('"') if fields[10] else ''
            http_path = fields[11].strip('"') if fields[11] else ''
            user_agent = fields[12].strip('"') if fields[12] else ''
            
            # Map protocol number to name
            protocol = PROTOCOL_MAPPING.get(protocol_num, f'PROTO-{protocol_num}')
            
            # Consolidate ports (TCP takes precedence over UDP)
            src_port = tcp_src if tcp_src else udp_src
            dst_port = tcp_dst if tcp_dst else udp_dst
            
            # Create normalized row
            row = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'length': length,
                'dns_query': dns_query,
                'http_host': http_host,
                'http_path': http_path,
                'user_agent': user_agent
            }
            
            return row
            
        except Exception as e:
            logger.warning(f"Error processing row: {e}")
            return None
    
    def extract_from_pcap(self, pcap_file: Path) -> Tuple[List[Dict[str, str]], int, int]:
        """Extract data from a single PCAP file."""
        logger.info(f"Processing: {pcap_file.name}")
        
        cmd = self.build_tshark_command(pcap_file)
        extracted_data = []
        total_packets = 0
        filtered_packets = 0
        
        try:
            # Run tshark command
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=300,  # 5 minute timeout per file
                check=True
            )
            
            lines = result.stdout.strip().split('\n')
            if not lines or lines == ['']:
                logger.warning(f"No data extracted from {pcap_file.name}")
                return extracted_data, 0, 0
            
            # Skip header line
            data_lines = lines[1:] if lines[0].startswith('frame.time') else lines
            
            for line in data_lines:
                if not line.strip():
                    continue
                    
                total_packets += 1
                row = self.process_tshark_row(line)
                
                if row and not self.should_filter_packet(row):
                    extracted_data.append(row)
                else:
                    filtered_packets += 1
            
            logger.info(f"{pcap_file.name}: {len(extracted_data)} packets kept, "
                       f"{filtered_packets} filtered out of {total_packets} total")
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout processing {pcap_file.name}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Tshark error for {pcap_file.name}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error processing {pcap_file.name}: {e}")
        
        return extracted_data, total_packets, filtered_packets
    
    def process_all_pcaps(self) -> None:
        """Process all PCAP files and create consolidated CSV."""
        pcap_files = self.get_pcap_files()
        
        if not pcap_files:
            logger.error("No PCAP files found!")
            return
        
        all_data = []
        
        logger.info(f"Starting extraction from {len(pcap_files)} PCAP files...")
        
        for pcap_file in pcap_files:
            try:
                data, total, filtered = self.extract_from_pcap(pcap_file)
                all_data.extend(data)
                
                self.total_packets += total
                self.filtered_packets += filtered
                self.processed_files += 1
                
            except Exception as e:
                logger.error(f"Failed to process {pcap_file.name}: {e}")
                self.failed_files += 1
        
        # Write consolidated CSV
        if all_data:
            self.write_csv(all_data)
            logger.info(f"Successfully created {self.output_csv} with {len(all_data)} records")
        else:
            logger.warning("No data extracted from any PCAP files!")
        
        # Log final statistics
        self.log_final_stats()
    
    def write_csv(self, data: List[Dict[str, str]]) -> None:
        """Write extracted data to CSV file."""
        try:
            with open(self.output_csv, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.csv_headers)
                writer.writeheader()
                writer.writerows(data)
        except Exception as e:
            logger.error(f"Error writing CSV file: {e}")
            raise
    
    def log_final_stats(self) -> None:
        """Log final processing statistics."""
        kept_packets = self.total_packets - self.filtered_packets
        filter_rate = (self.filtered_packets / self.total_packets * 100) if self.total_packets > 0 else 0
        
        stats_msg = f"""
=== PCAP EXTRACTION SUMMARY ===
Files processed: {self.processed_files}
Files failed: {self.failed_files}
Total packets analyzed: {self.total_packets:,}
Packets kept: {kept_packets:,}
Packets filtered: {self.filtered_packets:,}
Filter rate: {filter_rate:.1f}%
Output file: {self.output_csv}
================================
        """
        
        logger.info(stats_msg)

def validate_csv_output(csv_file: str) -> bool:
    """Validate the output CSV format and content."""
    try:
        df = pd.read_csv(csv_file)
        
        expected_columns = [
            'timestamp', 'src_ip', 'dst_ip', 'protocol', 
            'src_port', 'dst_port', 'length', 'dns_query',
            'http_host', 'http_path', 'user_agent'
        ]
        
        # Check column count and names
        if len(df.columns) != 11:
            logger.error(f"Expected 11 columns, found {len(df.columns)}")
            return False
        
        if list(df.columns) != expected_columns:
            logger.error(f"Column mismatch. Expected: {expected_columns}, Found: {list(df.columns)}")
            return False
        
        # Check for data
        if len(df) == 0:
            logger.error("CSV file is empty")
            return False
        
        logger.info(f"CSV validation passed: {len(df)} records, 11 columns")
        logger.info(f"Sample protocols found: {df['protocol'].value_counts().head()}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error validating CSV: {e}")
        return False

def main():
    """Main function to execute PCAP data extraction."""
    # Configuration
    pcap_dir = "/home/jteba/REPOSITORIOS/MASTER/modulo 5/tarea1/pcaps/pcaps_eval"
    output_csv = "/home/jteba/REPOSITORIOS/MASTER/modulo 5/tarea1/datos_extraidos.csv"
    
    logger.info("=== PCAP DATA EXTRACTOR - PHASE 1 ===")
    logger.info("Cybersecurity Dataset Creation Project")
    logger.info(f"PCAP directory: {pcap_dir}")
    logger.info(f"Output CSV: {output_csv}")
    
    # Initialize extractor
    extractor = PCAPDataExtractor(pcap_dir, output_csv)
    
    # Process all PCAP files
    extractor.process_all_pcaps()
    
    # Validate output
    if os.path.exists(output_csv):
        is_valid = validate_csv_output(output_csv)
        if is_valid:
            logger.info("Phase 1 extraction completed successfully!")
        else:
            logger.error("Phase 1 extraction completed with validation errors!")
    else:
        logger.error("Phase 1 extraction failed - no output file created!")

if __name__ == "__main__":
    main()