#!/usr/bin/env python3
"""
Test simulation for Network Traffic Anomaly Detection System.
This creates synthetic network traffic data to test the anomaly detection system.
"""

import os
import sys
import time
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import ipaddress

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import project modules
from config import config
from src.analysis.anomaly_detector import AnomalyDetector
from src.visualization.visualizer import Visualizer
from src.utils.helpers import print_alert, print_banner, save_dataframe

def generate_normal_traffic(num_packets=1000, seed=42):
    """Generate synthetic normal network traffic data."""
    random.seed(seed)
    np.random.seed(seed)
    
    # Define common protocols with their probabilities
    protocols = {
        'TCP': 0.6,  # 60% of traffic
        'UDP': 0.2,  # 20% of traffic
        'HTTPS': 0.15,  # 15% of traffic
        'HTTP': 0.03,  # 3% of traffic
        'DNS': 0.02,  # 2% of traffic
    }
    
    # Generate timestamps
    base_time = datetime.now()
    timestamps = [
        (base_time + timedelta(seconds=i*0.01)).isoformat()
        for i in range(num_packets)
    ]
    
    # Generate source and destination IPs
    # Create a pool of IPs for realistic traffic simulation
    server_ips = [
        str(ipaddress.IPv4Address('192.168.1.1') + i)
        for i in range(5)  # 5 servers
    ]
    
    client_ips = [
        str(ipaddress.IPv4Address('192.168.0.1') + i)
        for i in range(20)  # 20 clients
    ]
    
    external_ips = [
        str(ipaddress.IPv4Address('8.8.8.8') + i)
        for i in range(10)  # 10 external services
    ]
    
    # Generate protocol based on probability distribution
    protocol_choices = np.random.choice(
        list(protocols.keys()),
        size=num_packets,
        p=list(protocols.values())
    )
    
    # Generate packet sizes based on protocol
    def get_packet_size(protocol):
        if protocol == 'TCP':
            return int(np.random.normal(500, 200))  # Mean 500, std 200
        elif protocol == 'UDP':
            return int(np.random.normal(300, 100))  # Mean 300, std 100
        elif protocol == 'HTTP':
            return int(np.random.normal(800, 300))  # Mean 800, std 300
        elif protocol == 'HTTPS':
            return int(np.random.normal(1000, 400))  # Mean 1000, std 400
        elif protocol == 'DNS':
            return int(np.random.normal(100, 30))  # Mean 100, std 30
        return 500  # Default
    
    # Generate features
    features = []
    for i in range(num_packets):
        protocol = protocol_choices[i]
        
        # Generate source and destination
        if random.random() < 0.7:  # 70% internal to external or vice versa
            if random.random() < 0.5:  # Internal to external
                src_ip = random.choice(client_ips)
                dst_ip = random.choice(external_ips)
            else:  # External to internal
                src_ip = random.choice(external_ips)
                dst_ip = random.choice(server_ips)
        else:  # Internal to internal
            src_ip = random.choice(client_ips)
            dst_ip = random.choice(server_ips)
        
        # Generate ports based on protocol
        if protocol in ('TCP', 'HTTP', 'HTTPS'):
            src_port = random.randint(49152, 65535)  # Ephemeral ports
            if protocol == 'HTTP':
                dst_port = 80
            elif protocol == 'HTTPS':
                dst_port = 443
            else:
                dst_port = random.choice([22, 25, 80, 443, 8080])
        elif protocol == 'UDP':
            src_port = random.randint(49152, 65535)
            dst_port = random.choice([53, 123, 161, 162])
        elif protocol == 'DNS':
            src_port = random.randint(49152, 65535)
            dst_port = 53
        else:
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(1, 1023)
        
        # Determine if IPs are private
        src_is_private = ipaddress.ip_address(src_ip).is_private
        dst_is_private = ipaddress.ip_address(dst_ip).is_private
        
        # Add packet to features
        features.append({
            'timestamp': timestamps[i],
            'packet_id': i,
            'length': get_packet_size(protocol),
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'src_is_private': src_is_private,
            'dst_is_private': dst_is_private,
            'src_country': 'US' if not src_is_private else None,
            'dst_country': 'US' if not dst_is_private else None,
        })
    
    return pd.DataFrame(features)

def generate_anomalous_traffic(normal_df, num_anomalies=50, seed=43):
    """Generate synthetic anomalous network traffic data."""
    random.seed(seed)
    np.random.seed(seed)
    
    # Start with a copy of some normal traffic
    normal_sample = normal_df.sample(num_anomalies, random_state=seed).copy()
    
    # Add different types of anomalies
    anomaly_types = [
        'port_scan',
        'data_exfiltration',
        'unusual_protocol',
        'suspicious_country',
        'high_volume'
    ]
    
    suspicious_countries = ['RU', 'CN', 'KP', 'IR']
    
    for i, anomaly_type in enumerate(anomaly_types):
        # Apply each anomaly type to a subset of the anomalous traffic
        subset_size = num_anomalies // len(anomaly_types)
        start_idx = i * subset_size
        end_idx = (i + 1) * subset_size if i < len(anomaly_types) - 1 else num_anomalies
        
        subset = normal_sample.iloc[start_idx:end_idx]
        
        if anomaly_type == 'port_scan':
            # Simulate port scanning from single source to multiple ports
            src_ip = '10.0.0.99'  # Attacker IP
            for j, idx in enumerate(subset.index):
                normal_sample.loc[idx, 'src_ip'] = src_ip
                normal_sample.loc[idx, 'dst_port'] = 1000 + j  # Different ports
                normal_sample.loc[idx, 'protocol'] = 'TCP'
                normal_sample.loc[idx, 'length'] = 60  # Small packets
        
        elif anomaly_type == 'data_exfiltration':
            # Simulate large data transfers to external IP
            dst_ip = '203.0.113.100'  # External suspicious IP
            for idx in subset.index:
                normal_sample.loc[idx, 'dst_ip'] = dst_ip
                normal_sample.loc[idx, 'dst_is_private'] = False
                normal_sample.loc[idx, 'length'] = random.randint(2000, 9000)  # Large packets
                normal_sample.loc[idx, 'protocol'] = 'TCP'
        
        elif anomaly_type == 'unusual_protocol':
            # Simulate unusual protocol usage
            for idx in subset.index:
                normal_sample.loc[idx, 'protocol'] = 'ICMP'
                normal_sample.loc[idx, 'src_port'] = None
                normal_sample.loc[idx, 'dst_port'] = None
        
        elif anomaly_type == 'suspicious_country':
            # Traffic to/from suspicious countries
            for idx in subset.index:
                normal_sample.loc[idx, 'dst_country'] = random.choice(suspicious_countries)
                normal_sample.loc[idx, 'dst_is_private'] = False
                normal_sample.loc[idx, 'dst_ip'] = '185.159.160.' + str(random.randint(1, 254))
        
        elif anomaly_type == 'high_volume':
            # High volume traffic to single destination
            dst_ip = '172.16.0.200'
            for idx in subset.index:
                normal_sample.loc[idx, 'dst_ip'] = dst_ip
                normal_sample.loc[idx, 'length'] = random.randint(1500, 3000)
    
    return normal_sample

def main():
    """Main simulation function."""
    print_banner("Network Traffic Anomaly Detection System - Simulation")
    
    # Set up data directories
    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.MODEL_DIR, exist_ok=True)
    
    # Initialize components
    anomaly_detector = AnomalyDetector()
    visualizer = Visualizer()
    
    print_alert("Generating synthetic normal traffic for training...", "INFO")
    normal_traffic = generate_normal_traffic(num_packets=5000)
    save_dataframe(normal_traffic, os.path.join(config.DATA_DIR, 'normal_traffic.csv'))
    
    # Train the model with normal traffic
    print_alert("Training anomaly detection model...", "INFO")
    anomaly_detector.train(normal_traffic)
    
    # Generate testing data including anomalies
    print_alert("Generating test data with anomalies...", "INFO")
    test_normal = generate_normal_traffic(num_packets=1000, seed=100)
    test_anomalies = generate_anomalous_traffic(test_normal, num_anomalies=200, seed=101)
    test_data = pd.concat([test_normal, test_anomalies]).sample(frac=1).reset_index(drop=True)
    save_dataframe(test_data, os.path.join(config.DATA_DIR, 'test_data.csv'))
    
    # Detect anomalies
    print_alert("Running anomaly detection...", "INFO")
    result_df = anomaly_detector.detect_anomalies(test_data)
    
    if result_df is not None:
        # Count anomalies detected
        anomaly_count = result_df['is_anomaly'].sum()
        print_alert(f"Detected {anomaly_count} anomalies in {len(result_df)} packets", "MEDIUM")
        
        # Analyze anomalies
        analysis = anomaly_detector.analyze_anomalies(result_df)
        
        # Visualize results
        visualizer.visualize_packet_capture(test_data)
        visualizer.visualize_anomalies(result_df)
        
        # Visualize threats
        if 'potential_threats' in analysis and analysis['potential_threats']:
            visualizer.visualize_threats(analysis['potential_threats'])
            
            # Alert on high-confidence threats
            for threat in analysis['potential_threats']:
                if threat.get('confidence', 0) > 0.7:  # 70% confidence threshold
                    alert_level = "HIGH" if threat.get('confidence', 0) > 0.9 else "MEDIUM"
                    print_alert(
                        f"High confidence threat detected: {threat.get('type', 'UNKNOWN')}",
                        alert_level
                    )
        
        # Print summary
        print_banner("Simulation Results")
        print(f"Total test packets: {len(test_data)}")
        print(f"Injected anomalies: {len(test_anomalies)}")
        print(f"Detected anomalies: {anomaly_count}")
        
        # Calculate precision and recall
        true_positives = result_df[result_df.index.isin(test_anomalies.index) & result_df['is_anomaly']].shape[0]
        false_positives = result_df[~result_df.index.isin(test_anomalies.index) & result_df['is_anomaly']].shape[0]
        false_negatives = result_df[result_df.index.isin(test_anomalies.index) & ~result_df['is_anomaly']].shape[0]
        
        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        
        print(f"Precision: {precision:.2f}")
        print(f"Recall: {recall:.2f}")
        
    else:
        print_alert("Anomaly detection failed.", "HIGH")

if __name__ == "__main__":
    main() 