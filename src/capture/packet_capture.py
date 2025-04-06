"""
Network packet capture module using Scapy.
"""

import os
import time
import threading
import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, wrpcap
from scapy.layers.http import HTTP

# Import project modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config import config
from src.utils.helpers import (
    is_private_ip, get_geo_info, get_whois_info, 
    save_dataframe, print_alert
)

class PacketCapture:
    """Capture network packets and extract relevant features."""
    
    def __init__(self, interface=None, capture_filter="", output_dir=None):
        """Initialize packet capture with specified interface and filter."""
        self.interface = interface or config.CAPTURE_INTERFACE
        self.capture_filter = capture_filter or config.CAPTURE_FILTER
        self.output_dir = output_dir or config.DATA_DIR
        
        self.packets = []
        self.packet_count = 0
        self.stop_capture = threading.Event()
        self.capture_thread = None
        
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Load GeoIP database if available
        self.geoip_db = None
        if config.GEOIP_ENABLED:
            # This assumes you have the GeoLite2 database
            # Download from: https://dev.maxmind.com/geoip/geoip2/geolite2/
            self.geoip_db = os.path.join(self.output_dir, 'GeoLite2-City.mmdb')
            if not os.path.exists(self.geoip_db):
                print_alert("GeoIP database not found. Geographic analysis will be limited.", "WARNING")
    
    def start_capture(self, count=None, timeout=None):
        """Start packet capture in a separate thread."""
        count = count or config.PACKET_COUNT
        timeout = timeout or config.CAPTURE_TIMEOUT
        
        self.stop_capture.clear()
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            args=(count, timeout),
            daemon=True
        )
        self.capture_thread.start()
        print_alert(f"Started packet capture on interface {self.interface}", "INFO")
        return self.capture_thread
    
    def stop_capture_process(self):
        """Stop the packet capture thread."""
        if self.capture_thread and self.capture_thread.is_alive():
            self.stop_capture.set()
            self.capture_thread.join(timeout=2.0)
            print_alert("Stopped packet capture", "INFO")
    
    def _capture_packets(self, count, timeout):
        """Capture packets with specified parameters."""
        try:
            self.packets = sniff(
                iface=self.interface,
                filter=self.capture_filter, 
                count=count,
                timeout=timeout,
                store=True,
                stop_filter=lambda _: self.stop_capture.is_set()
            )
            self.packet_count = len(self.packets)
            
            if self.packet_count > 0:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                pcap_file = os.path.join(self.output_dir, f"capture_{timestamp}.pcap")
                wrpcap(pcap_file, self.packets)
                print_alert(f"Captured {self.packet_count} packets, saved to {pcap_file}", "INFO")
                
        except Exception as e:
            print_alert(f"Error during packet capture: {str(e)}", "HIGH")
    
    def extract_features(self):
        """Extract features from captured packets for analysis."""
        if not self.packets:
            print_alert("No packets captured to extract features from", "WARNING")
            return pd.DataFrame()
        
        features = []
        for i, packet in enumerate(self.packets):
            # Basic packet features
            pkt_features = {
                'timestamp': datetime.now().isoformat(),
                'packet_id': i,
                'length': len(packet),
                'protocol': None,
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'tcp_flags': None,
                'udp_length': None,
                'icmp_type': None,
                'dns_query': None,
                'src_country': None,
                'dst_country': None,
                'src_is_private': None,
                'dst_is_private': None
            }
            
            # Extract IP layer information
            if IP in packet:
                pkt_features['src_ip'] = packet[IP].src
                pkt_features['dst_ip'] = packet[IP].dst
                pkt_features['src_is_private'] = is_private_ip(packet[IP].src)
                pkt_features['dst_is_private'] = is_private_ip(packet[IP].dst)
                
                # Get geographic info if enabled
                if config.GEOIP_ENABLED and self.geoip_db:
                    if not pkt_features['src_is_private']:
                        geo_info = get_geo_info(packet[IP].src, self.geoip_db)
                        pkt_features['src_country'] = geo_info['country_code']
                    
                    if not pkt_features['dst_is_private']:
                        geo_info = get_geo_info(packet[IP].dst, self.geoip_db)
                        pkt_features['dst_country'] = geo_info['country_code']
                
                # Extract TCP information
                if TCP in packet:
                    pkt_features['protocol'] = 'TCP'
                    pkt_features['src_port'] = packet[TCP].sport
                    pkt_features['dst_port'] = packet[TCP].dport
                    pkt_features['tcp_flags'] = packet[TCP].flags
                    
                    # Identify common protocols by port
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        pkt_features['protocol'] = 'HTTP'
                    elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        pkt_features['protocol'] = 'HTTPS'
                    elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                        pkt_features['protocol'] = 'SSH'
                
                # Extract UDP information
                elif UDP in packet:
                    pkt_features['protocol'] = 'UDP'
                    pkt_features['src_port'] = packet[UDP].sport
                    pkt_features['dst_port'] = packet[UDP].dport
                    pkt_features['udp_length'] = packet[UDP].len
                    
                    # Identify DNS traffic
                    if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                        pkt_features['protocol'] = 'DNS'
                        if DNS in packet:
                            if packet[DNS].qd:
                                pkt_features['dns_query'] = packet[DNS].qd.qname.decode()
                
                # Extract ICMP information
                elif ICMP in packet:
                    pkt_features['protocol'] = 'ICMP'
                    pkt_features['icmp_type'] = packet[ICMP].type
            
            features.append(pkt_features)
        
        # Convert to DataFrame
        df = pd.DataFrame(features)
        
        # Save features to CSV
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        features_file = os.path.join(self.output_dir, f"features_{timestamp}.csv")
        save_dataframe(df, features_file)
        print_alert(f"Extracted features from {len(features)} packets, saved to {features_file}", "INFO")
        
        return df

    def get_protocol_stats(self, df=None):
        """Get protocol distribution statistics."""
        if df is None:
            if not self.packets:
                return {}
            df = self.extract_features()
        
        # Get protocol distribution
        protocol_counts = df['protocol'].value_counts().to_dict()
        total = len(df)
        
        # Calculate percentages
        protocol_stats = {
            protocol: {
                'count': count,
                'percentage': (count / total) * 100 if total > 0 else 0
            }
            for protocol, count in protocol_counts.items()
        }
        
        return protocol_stats
    
    def get_geo_stats(self, df=None):
        """Get geographic distribution statistics."""
        if df is None:
            if not self.packets:
                return {}
            df = self.extract_features()
        
        geo_stats = {}
        
        # Only proceed if country data is available
        if 'src_country' in df.columns and 'dst_country' in df.columns:
            # Source country distribution
            src_countries = df['src_country'].value_counts().to_dict()
            
            # Destination country distribution
            dst_countries = df['dst_country'].value_counts().to_dict()
            
            # Combine statistics
            geo_stats = {
                'source_countries': src_countries,
                'dest_countries': dst_countries
            }
            
            # Flag suspicious countries
            suspicious_traffic = []
            for country in config.SUSPICIOUS_COUNTRIES:
                src_count = src_countries.get(country, 0)
                dst_count = dst_countries.get(country, 0)
                if src_count > 0 or dst_count > 0:
                    suspicious_traffic.append({
                        'country': country,
                        'src_count': src_count,
                        'dst_count': dst_count
                    })
            
            geo_stats['suspicious_traffic'] = suspicious_traffic
        
        return geo_stats

    def get_connection_stats(self, df=None):
        """Get statistics on network connections."""
        if df is None:
            if not self.packets:
                return {}
            df = self.extract_features()
        
        connection_stats = {}
        
        # Extract source and destination IP addresses
        if 'src_ip' in df.columns and 'dst_ip' in df.columns:
            # Count unique source IPs
            src_ips = df['src_ip'].value_counts().to_dict()
            connection_stats['unique_src_ips'] = len(src_ips)
            
            # Count unique destination IPs
            dst_ips = df['dst_ip'].value_counts().to_dict()
            connection_stats['unique_dst_ips'] = len(dst_ips)
            
            # Identify top talkers (source IPs with most packets)
            connection_stats['top_talkers'] = dict(sorted(
                src_ips.items(), key=lambda x: x[1], reverse=True)[:5])
            
            # Identify top destinations (destination IPs with most packets)
            connection_stats['top_destinations'] = dict(sorted(
                dst_ips.items(), key=lambda x: x[1], reverse=True)[:5])
            
            # Create unique connections (source IP, destination IP pairs)
            df['connection'] = df['src_ip'] + '->' + df['dst_ip']
            connections = df['connection'].value_counts().to_dict()
            connection_stats['unique_connections'] = len(connections)
            
            # Top connections by volume
            connection_stats['top_connections'] = dict(sorted(
                connections.items(), key=lambda x: x[1], reverse=True)[:5])
        
        return connection_stats
