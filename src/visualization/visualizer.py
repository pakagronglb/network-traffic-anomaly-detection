"""
Terminal-based visualization for network traffic anomalies.
"""

import os
import time
import threading
import pandas as pd
import numpy as np
from datetime import datetime
import plotext as plt
from tabulate import tabulate
import json
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Import project modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config import config
from src.utils.helpers import print_alert, print_banner, print_table

class Visualizer:
    """Terminal-based visualization for network traffic data and anomalies."""
    
    def __init__(self, update_interval=None):
        """Initialize the visualizer with update interval."""
        self.update_interval = update_interval or config.PLOT_UPDATE_INTERVAL
        self.stop_visualization = threading.Event()
        self.visualization_thread = None
        self.data_buffer = {
            'timestamps': [],
            'packet_counts': [],
            'protocol_counts': {},
            'anomaly_scores': [],
            'threat_counts': {}
        }
        self.max_buffer_size = 100  # Maximum number of data points to keep
    
    def start_visualization(self, callback=None):
        """Start visualization in a separate thread with optional callback."""
        self.stop_visualization.clear()
        self.visualization_thread = threading.Thread(
            target=self._visualization_loop,
            args=(callback,),
            daemon=True
        )
        self.visualization_thread.start()
        print_alert("Started visualization dashboard", "INFO")
        return self.visualization_thread
    
    def stop_visualization_process(self):
        """Stop the visualization thread."""
        if self.visualization_thread and self.visualization_thread.is_alive():
            self.stop_visualization.set()
            self.visualization_thread.join(timeout=2.0)
            print_alert("Stopped visualization dashboard", "INFO")
    
    def _visualization_loop(self, callback):
        """Main visualization loop."""
        while not self.stop_visualization.is_set():
            try:
                # Call the provided callback to get latest data
                if callback:
                    latest_data = callback()
                    if latest_data:
                        self.update_data(latest_data)
                
                # Display the dashboard
                self.display_dashboard()
                
                # Wait for the next update
                time.sleep(self.update_interval)
                
            except Exception as e:
                print_alert(f"Error in visualization loop: {str(e)}", "WARNING")
                time.sleep(self.update_interval)
    
    def update_data(self, data):
        """Update visualization data buffer with new data."""
        timestamp = datetime.now().isoformat()
        
        # Update timestamps
        self.data_buffer['timestamps'].append(timestamp)
        
        # Update packet counts
        packet_count = data.get('packet_count', 0)
        self.data_buffer['packet_counts'].append(packet_count)
        
        # Update protocol counts
        protocol_counts = data.get('protocol_counts', {})
        for protocol, count in protocol_counts.items():
            if protocol not in self.data_buffer['protocol_counts']:
                self.data_buffer['protocol_counts'][protocol] = []
            self.data_buffer['protocol_counts'][protocol].append(count)
            # Ensure all protocol arrays have the same length
            while len(self.data_buffer['protocol_counts'][protocol]) < len(self.data_buffer['timestamps']):
                self.data_buffer['protocol_counts'][protocol].insert(0, 0)
        
        # Update anomaly scores
        anomaly_score = data.get('anomaly_score', 0)
        self.data_buffer['anomaly_scores'].append(anomaly_score)
        
        # Update threat counts
        threat_counts = data.get('threat_counts', {})
        for threat_type, count in threat_counts.items():
            if threat_type not in self.data_buffer['threat_counts']:
                self.data_buffer['threat_counts'][threat_type] = []
            self.data_buffer['threat_counts'][threat_type].append(count)
            # Ensure all threat arrays have the same length
            while len(self.data_buffer['threat_counts'][threat_type]) < len(self.data_buffer['timestamps']):
                self.data_buffer['threat_counts'][threat_type].insert(0, 0)
        
        # Trim buffers to max size
        if len(self.data_buffer['timestamps']) > self.max_buffer_size:
            self.data_buffer['timestamps'] = self.data_buffer['timestamps'][-self.max_buffer_size:]
            self.data_buffer['packet_counts'] = self.data_buffer['packet_counts'][-self.max_buffer_size:]
            self.data_buffer['anomaly_scores'] = self.data_buffer['anomaly_scores'][-self.max_buffer_size:]
            
            for protocol in self.data_buffer['protocol_counts']:
                self.data_buffer['protocol_counts'][protocol] = self.data_buffer['protocol_counts'][protocol][-self.max_buffer_size:]
            
            for threat_type in self.data_buffer['threat_counts']:
                self.data_buffer['threat_counts'][threat_type] = self.data_buffer['threat_counts'][threat_type][-self.max_buffer_size:]
    
    def display_dashboard(self):
        """Display the visualization dashboard in the terminal."""
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print_banner("Network Traffic Anomaly Detection Dashboard")
        print(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        # Only show visualizations if we have data
        if not self.data_buffer['timestamps']:
            print("Waiting for data...")
            return
        
        # Calculate dashboard layout
        term_width = os.get_terminal_size().columns
        term_height = os.get_terminal_size().lines
        
        # Show packet volume plot if enabled
        if config.DASHBOARD_ITEMS.get('show_packet_volume', True):
            self._plot_packet_volume()
        
        # Show protocol distribution if enabled
        if config.DASHBOARD_ITEMS.get('show_protocol_distribution', True):
            self._plot_protocol_distribution()
        
        # Show anomaly scores if enabled
        if config.DASHBOARD_ITEMS.get('show_anomaly_scores', True):
            self._plot_anomaly_scores()
        
        # Show threats if available
        if config.DASHBOARD_ITEMS.get('show_threat_summary', True) and self.data_buffer['threat_counts']:
            self._display_threat_summary()
    
    def _plot_packet_volume(self):
        """Plot packet volume over time."""
        plt.clf()
        plt.plot(self.data_buffer['packet_counts'])
        plt.title("Packet Volume Over Time")
        plt.xlabel("Time")
        plt.ylabel("Packet Count")
        plt.show()
        print()
    
    def _plot_protocol_distribution(self):
        """Plot protocol distribution over time."""
        # Only plot if we have protocol data
        if not self.data_buffer['protocol_counts']:
            return
        
        plt.clf()
        
        # Get the most common protocols
        all_protocols = list(self.data_buffer['protocol_counts'].keys())
        if len(all_protocols) > 5:
            # If more than 5 protocols, only show the 5 most common
            protocol_sums = {}
            for protocol in all_protocols:
                protocol_sums[protocol] = sum(self.data_buffer['protocol_counts'][protocol])
            
            top_protocols = sorted(protocol_sums.items(), key=lambda x: x[1], reverse=True)[:5]
            protocols_to_plot = [p[0] for p in top_protocols]
        else:
            protocols_to_plot = all_protocols
        
        # Plot each protocol
        for protocol in protocols_to_plot:
            plt.plot(self.data_buffer['protocol_counts'][protocol], label=protocol)
        
        plt.title("Protocol Distribution Over Time")
        plt.xlabel("Time")
        plt.ylabel("Packet Count")
        plt.show()
        print()
        
        # Display current protocol distribution as a table
        current_protocol_counts = {}
        for protocol in self.data_buffer['protocol_counts']:
            if self.data_buffer['protocol_counts'][protocol]:
                current_protocol_counts[protocol] = self.data_buffer['protocol_counts'][protocol][-1]
        
        if current_protocol_counts:
            protocol_table = []
            for protocol, count in sorted(current_protocol_counts.items(), key=lambda x: x[1], reverse=True):
                protocol_table.append([protocol, count])
            
            print("Current Protocol Distribution:")
            print_table(protocol_table, ["Protocol", "Count"])
            print()
    
    def _plot_anomaly_scores(self):
        """Plot anomaly scores over time."""
        if not self.data_buffer['anomaly_scores']:
            return
        
        plt.clf()
        
        # Plot anomaly scores
        plt.plot(self.data_buffer['anomaly_scores'])
        
        # Add threshold line
        threshold = [config.ANOMALY_THRESHOLD] * len(self.data_buffer['timestamps'])
        plt.plot(threshold, label="Threshold", color="red")
        
        plt.title("Anomaly Scores Over Time")
        plt.xlabel("Time")
        plt.ylabel("Anomaly Score")
        plt.ylim(0, 1)
        plt.show()
        print()
        
        # Display current anomaly score
        current_score = self.data_buffer['anomaly_scores'][-1]
        score_color = Fore.GREEN
        if current_score > config.ALERT_LEVELS['CRITICAL']:
            score_color = Fore.RED + Style.BRIGHT
        elif current_score > config.ALERT_LEVELS['HIGH']:
            score_color = Fore.RED
        elif current_score > config.ALERT_LEVELS['MEDIUM']:
            score_color = Fore.YELLOW
        elif current_score > config.ALERT_LEVELS['LOW']:
            score_color = Fore.BLUE
        
        print(f"Current Anomaly Score: {score_color}{current_score:.4f}{Style.RESET_ALL}")
        print()
    
    def _display_threat_summary(self):
        """Display summary of detected threats."""
        # Calculate current threat counts
        current_threats = {}
        for threat_type in self.data_buffer['threat_counts']:
            if self.data_buffer['threat_counts'][threat_type]:
                current_threats[threat_type] = self.data_buffer['threat_counts'][threat_type][-1]
        
        if not current_threats:
            return
        
        print(f"{Fore.YELLOW}Potential Threats Detected:{Style.RESET_ALL}")
        
        # Create table for threats
        threat_table = []
        for threat_type, count in sorted(current_threats.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                threat_color = Fore.YELLOW
                if threat_type == 'PORT_SCAN' or threat_type == 'DATA_EXFILTRATION':
                    threat_color = Fore.RED
                elif threat_type == 'COMMAND_AND_CONTROL':
                    threat_color = Fore.RED + Style.BRIGHT
                
                threat_table.append([f"{threat_color}{threat_type}{Style.RESET_ALL}", count])
        
        if threat_table:
            print_table(threat_table, ["Threat Type", "Count"])
            print()
    
    def visualize_packet_capture(self, packet_df):
        """Visualize packet capture statistics."""
        if packet_df.empty:
            print_alert("No packet data to visualize", "WARNING")
            return
        
        print_banner("Packet Capture Statistics")
        
        # Protocol distribution
        if 'protocol' in packet_df.columns:
            protocol_counts = packet_df['protocol'].value_counts()
            print("Protocol Distribution:")
            for protocol, count in protocol_counts.items():
                percentage = (count / len(packet_df)) * 100
                print(f"  {protocol}: {count} packets ({percentage:.2f}%)")
            print()
        
        # Geographic distribution
        if 'src_country' in packet_df.columns and 'dst_country' in packet_df.columns:
            print("Geographic Distribution:")
            
            # Source countries
            src_countries = packet_df['src_country'].value_counts()
            print("  Source Countries:")
            for country, count in src_countries.items():
                print(f"    {country}: {count} packets")
            
            # Destination countries
            dst_countries = packet_df['dst_country'].value_counts()
            print("  Destination Countries:")
            for country, count in dst_countries.items():
                print(f"    {country}: {count} packets")
            print()
        
        # Connection statistics
        if 'src_ip' in packet_df.columns and 'dst_ip' in packet_df.columns:
            print("Connection Statistics:")
            unique_src = packet_df['src_ip'].nunique()
            unique_dst = packet_df['dst_ip'].nunique()
            print(f"  Unique Source IPs: {unique_src}")
            print(f"  Unique Destination IPs: {unique_dst}")
            
            # Top talkers (source IPs)
            top_sources = packet_df['src_ip'].value_counts().head(5)
            print("  Top Talkers (Source IPs):")
            for ip, count in top_sources.items():
                print(f"    {ip}: {count} packets")
            
            # Top destinations
            top_dests = packet_df['dst_ip'].value_counts().head(5)
            print("  Top Destinations:")
            for ip, count in top_dests.items():
                print(f"    {ip}: {count} packets")
            print()
    
    def visualize_anomalies(self, anomaly_df):
        """Visualize detected anomalies."""
        if anomaly_df is None or 'is_anomaly' not in anomaly_df.columns:
            print_alert("No anomaly data to visualize", "WARNING")
            return
        
        # Filter to anomalous packets
        anomalies = anomaly_df[anomaly_df['is_anomaly'] == True]
        if len(anomalies) == 0:
            print_alert("No anomalies detected in this batch", "INFO")
            return
        
        print_banner("Detected Anomalies")
        print(f"Total anomalies: {len(anomalies)} out of {len(anomaly_df)} packets ({(len(anomalies)/len(anomaly_df))*100:.2f}%)")
        print()
        
        # Display anomaly distribution by protocol
        if 'protocol' in anomalies.columns:
            protocol_counts = anomalies['protocol'].value_counts()
            
            plt.clf()
            plt.bar(list(protocol_counts.keys()), list(protocol_counts.values()))
            plt.title("Anomalies by Protocol")
            plt.xlabel("Protocol")
            plt.ylabel("Count")
            plt.show()
            print()
        
        # Display top anomalous connections
        if 'src_ip' in anomalies.columns and 'dst_ip' in anomalies.columns:
            # Create connection strings
            anomalies['connection'] = anomalies['src_ip'] + ' -> ' + anomalies['dst_ip']
            connection_counts = anomalies['connection'].value_counts().head(10)
            
            print("Top Anomalous Connections:")
            conn_table = []
            for conn, count in connection_counts.items():
                avg_score = anomalies[anomalies['connection'] == conn]['anomaly_score'].mean()
                conn_table.append([conn, count, f"{avg_score:.4f}"])
            
            print_table(conn_table, ["Connection", "Count", "Avg. Anomaly Score"])
            print()
        
        # Display geographic anomalies if available
        if 'src_country' in anomalies.columns and 'dst_country' in anomalies.columns:
            suspicious_countries = config.SUSPICIOUS_COUNTRIES
            suspicious_traffic = anomalies[
                (anomalies['src_country'].isin(suspicious_countries)) | 
                (anomalies['dst_country'].isin(suspicious_countries))
            ]
            
            if len(suspicious_traffic) > 0:
                print(f"{Fore.RED}Suspicious Geographic Traffic:{Style.RESET_ALL}")
                for country in suspicious_countries:
                    src_count = len(anomalies[anomalies['src_country'] == country])
                    dst_count = len(anomalies[anomalies['dst_country'] == country])
                    
                    if src_count > 0 or dst_count > 0:
                        print(f"  {country}: {src_count} outbound, {dst_count} inbound")
                print()
    
    def visualize_threats(self, threats):
        """Visualize identified threats."""
        if not threats:
            return
        
        print_banner("Potential Security Threats")
        
        for threat in threats:
            threat_type = threat.get('type', 'UNKNOWN')
            confidence = threat.get('confidence', 0) * 100
            
            # Set color based on threat type and confidence
            color = Fore.YELLOW
            if confidence > 80:
                color = Fore.RED
            elif confidence > 50:
                color = Fore.YELLOW
            else:
                color = Fore.BLUE
            
            print(f"{color}[{threat_type}] ({confidence:.1f}% confidence){Style.RESET_ALL}")
            
            # Print threat details based on type
            if threat_type == 'PORT_SCAN':
                print(f"  Source IP: {threat.get('source_ip', 'Unknown')}")
                print(f"  Ports scanned: {threat.get('ports_count', 0)}")
            
            elif threat_type == 'DATA_EXFILTRATION':
                print(f"  Destination IP: {threat.get('destination_ip', 'Unknown')}")
                print(f"  Data volume: {threat.get('total_bytes', 0)} bytes")
            
            elif threat_type == 'SUSPICIOUS_COUNTRY':
                print(f"  Country: {threat.get('country', 'Unknown')}")
                print(f"  Packet count: {threat.get('packet_count', 0)}")
            
            elif threat_type == 'COMMAND_AND_CONTROL':
                print(f"  Destination IP: {threat.get('destination_ip', 'Unknown')}")
                print(f"  Protocol: {threat.get('dominant_protocol', 'Unknown')}")
            
            print()
