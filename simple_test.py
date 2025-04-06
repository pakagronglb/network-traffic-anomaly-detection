#!/usr/bin/env python3
"""
Simplified simulation test for the Network Traffic Anomaly Detection System.
"""

import os
import sys
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import random
from colorama import Fore, Back, Style, init

# Initialize colorama
init(autoreset=True)

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Create the basic directory structure
os.makedirs('data', exist_ok=True)
os.makedirs('models', exist_ok=True)

print(Fore.CYAN + "==============================================")
print(Fore.CYAN + "= Network Traffic Anomaly Detection - Simple Test =")
print(Fore.CYAN + "==============================================")
print(Fore.GREEN + "\nGenerating sample network traffic data...")

# Generate synthetic normal traffic
def generate_normal_traffic(num_packets=1000):
    # Base timestamp
    base_time = datetime.now()
    
    # Common protocols with their probabilities
    protocols = {
        'TCP': 0.6,  # 60% of traffic
        'UDP': 0.2,  # 20% of traffic
        'HTTPS': 0.1,  # 10% of traffic
        'HTTP': 0.05,  # 5% of traffic
        'DNS': 0.05,  # 5% of traffic
    }
    
    # Source and destination IPs
    src_ips = [f'192.168.1.{i}' for i in range(1, 20)]
    dst_ips = [f'10.0.0.{i}' for i in range(1, 10)] + [f'8.8.8.{i}' for i in range(1, 5)]
    
    # Generate features
    data = []
    for i in range(num_packets):
        timestamp = base_time + timedelta(seconds=i*random.uniform(0.1, 0.5))  # Variable time delta
        protocol = random.choices(list(protocols.keys()), list(protocols.values()))[0]
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        
        # Generate packet size based on protocol
        if protocol == 'TCP':
            length = int(np.random.normal(500, 150))
        elif protocol == 'UDP':
            length = int(np.random.normal(300, 100))
        elif protocol == 'HTTP':
            length = int(np.random.normal(800, 300))
        elif protocol == 'HTTPS':
            length = int(np.random.normal(1000, 400))
        elif protocol == 'DNS':
            length = int(np.random.normal(100, 30))
        else:
            length = random.randint(64, 1500)
            
        # Ensure length is positive
        length = max(64, length)
        
        # Generate ports based on protocol
        if protocol == 'HTTP':
            dst_port = 80
            src_port = random.randint(1024, 65535)
        elif protocol == 'HTTPS':
            dst_port = 443
            src_port = random.randint(1024, 65535)
        elif protocol == 'DNS':
            dst_port = 53
            src_port = random.randint(1024, 65535)
        else:
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(1, 1023)
        
        data.append({
            'timestamp': timestamp.isoformat(),
            'protocol': protocol,
            'src_ip': src_ip, 
            'dst_ip': dst_ip,
            'length': length,
            'src_port': src_port,
            'dst_port': dst_port,
            'flags': random.choice(['', 'ACK', 'SYN', 'FIN', 'ACK+SYN']) if protocol == 'TCP' else '',
        })
    
    return pd.DataFrame(data)

# Generate synthetic anomalous traffic
def generate_anomalous_traffic(num_packets=100):
    # Base timestamp
    base_time = datetime.now()
    
    # Generate features for anomalies
    data = []
    
    # 1. Port scan (many ports, same source)
    src_ip = '172.16.0.99'
    for i in range(30):
        timestamp = base_time + timedelta(seconds=i*0.1)
        data.append({
            'timestamp': timestamp.isoformat(),
            'protocol': 'TCP',
            'src_ip': src_ip,
            'dst_ip': '10.0.0.1',
            'length': 64,  # Small packets
            'src_port': random.randint(1024, 65535),
            'dst_port': i + 1,  # Sequential ports
            'flags': 'SYN',  # SYN scan
        })
    
    # 2. Data exfiltration (large packets)
    for i in range(20):
        timestamp = base_time + timedelta(seconds=i*0.1)
        data.append({
            'timestamp': timestamp.isoformat(),
            'protocol': 'TCP',
            'src_ip': '192.168.1.5',
            'dst_ip': '203.0.113.5',  # External IP
            'length': random.randint(1500, 9000),  # Large packets
            'src_port': random.randint(1024, 65535),
            'dst_port': 443,
            'flags': 'ACK',
        })
    
    # 3. DNS tunneling (unusual DNS packet sizes)
    for i in range(15):
        timestamp = base_time + timedelta(seconds=i*0.2)
        data.append({
            'timestamp': timestamp.isoformat(),
            'protocol': 'DNS',
            'src_ip': '192.168.1.10',
            'dst_ip': '8.8.8.8',  # DNS server
            'length': random.randint(800, 1200),  # Unusually large DNS packets
            'src_port': random.randint(1024, 65535),
            'dst_port': 53,
            'flags': '',
        })
        
    # 4. Brute force SSH login attempts
    for i in range(20):
        timestamp = base_time + timedelta(seconds=i*0.05)  # Very rapid connections
        data.append({
            'timestamp': timestamp.isoformat(),
            'protocol': 'TCP',
            'src_ip': '45.33.22.10',  # Attacker IP
            'dst_ip': '192.168.1.1',  # Target server
            'length': random.randint(100, 300),
            'src_port': random.randint(1024, 65535),
            'dst_port': 22,  # SSH port
            'flags': 'SYN',
        })
        
    # 5. Unusual protocol behavior (HTTP on non-standard port)
    for i in range(15):
        timestamp = base_time + timedelta(seconds=i*0.3)
        data.append({
            'timestamp': timestamp.isoformat(),
            'protocol': 'HTTP',
            'src_ip': '192.168.1.15',
            'dst_ip': '198.51.100.23',  # Suspicious external IP
            'length': random.randint(300, 800),
            'src_port': random.randint(1024, 65535),
            'dst_port': 4444,  # Unusual port for HTTP
            'flags': '',
        })
    
    return pd.DataFrame(data)

# Main testing function
def test_anomaly_detection():
    # Generate normal traffic for training
    print(Fore.YELLOW + "Generating training data...")
    training_data = generate_normal_traffic(3000)
    training_data.to_csv('data/training_data.csv', index=False)
    print(Fore.GREEN + f"Generated {len(training_data)} normal traffic records for training")
    
    # Generate testing data with anomalies
    print(Fore.YELLOW + "\nGenerating test data with anomalies...")
    normal_test = generate_normal_traffic(1000)
    anomalous_test = generate_anomalous_traffic()
    test_data = pd.concat([normal_test, anomalous_test]).sample(frac=1).reset_index(drop=True)
    test_data.to_csv('data/test_data.csv', index=False)
    print(Fore.GREEN + f"Generated {len(test_data)} testing records ({len(anomalous_test)} anomalies)")
    
    print(Fore.YELLOW + "\nPerforming anomaly detection...")
    
    # =====================================================
    # Detection Method 1: Statistical analysis (z-score)
    # =====================================================
    print(Fore.BLUE + "\n[Method 1] Statistical Analysis (Z-Score)")
    
    # Train on normal data - packet length distribution
    length_mean = training_data['length'].mean()
    length_std = training_data['length'].std()
    
    # Set threshold (anything beyond 3 standard deviations is anomalous)
    threshold = 3
    
    # Detect anomalies based on packet length
    test_data['length_zscore'] = abs((test_data['length'] - length_mean) / length_std)
    test_data['length_anomaly'] = test_data['length_zscore'] > threshold
    
    # Count detected anomalies
    length_anomalies = test_data['length_anomaly'].sum()
    
    # Calculate how many true anomalies were detected
    length_true_positives = sum(idx in anomalous_test.index for idx in test_data[test_data['length_anomaly']].index)
    
    print(Fore.WHITE + f"Detected {length_anomalies} anomalies based on packet length")
    
    # =====================================================
    # Detection Method 2: Protocol-Port Analysis
    # =====================================================
    print(Fore.BLUE + "\n[Method 2] Protocol-Port Analysis")
    
    # Create a baseline of normal protocol-port combinations
    protocol_port_counts = training_data.groupby(['protocol', 'dst_port']).size().reset_index(name='count')
    common_combinations = set(zip(protocol_port_counts['protocol'], protocol_port_counts['dst_port']))
    
    # Flag unusual protocol-port combinations
    test_data['protocol_port_anomaly'] = test_data.apply(
        lambda row: (row['protocol'], row['dst_port']) not in common_combinations,
        axis=1
    )
    
    protocol_anomalies = test_data['protocol_port_anomaly'].sum()
    protocol_true_positives = sum(idx in anomalous_test.index for idx in test_data[test_data['protocol_port_anomaly']].index)
    
    print(Fore.WHITE + f"Detected {protocol_anomalies} anomalies based on unusual protocol-port combinations")
    
    # =====================================================
    # Detection Method 3: Connection Rate Analysis
    # =====================================================
    print(Fore.BLUE + "\n[Method 3] Connection Rate Analysis")
    
    # Convert timestamps to datetime objects
    test_data['timestamp_dt'] = pd.to_datetime(test_data['timestamp'])
    
    # Count connections per source IP in short time windows
    test_data['minute'] = test_data['timestamp_dt'].dt.floor('1min')
    conn_rate = test_data.groupby(['src_ip', 'minute']).size().reset_index(name='conn_count')
    
    # Get baseline connection rates from training data
    training_data['timestamp_dt'] = pd.to_datetime(training_data['timestamp'])
    training_data['minute'] = training_data['timestamp_dt'].dt.floor('1min')
    training_conn_rate = training_data.groupby(['minute']).size().mean()
    
    # Set connection rate threshold (3x the average)
    conn_threshold = training_conn_rate * 3
    
    # Flag high connection rates
    high_conn_ips = conn_rate[conn_rate['conn_count'] > conn_threshold]['src_ip'].unique()
    test_data['conn_rate_anomaly'] = test_data['src_ip'].isin(high_conn_ips)
    
    conn_anomalies = test_data['conn_rate_anomaly'].sum()
    conn_true_positives = sum(idx in anomalous_test.index for idx in test_data[test_data['conn_rate_anomaly']].index)
    
    print(Fore.WHITE + f"Detected {conn_anomalies} anomalies based on connection rates")
    
    # =====================================================
    # Combine all detection methods (Union)
    # =====================================================
    test_data['is_anomaly'] = (
        test_data['length_anomaly'] | 
        test_data['protocol_port_anomaly'] | 
        test_data['conn_rate_anomaly']
    )
    
    # Count total unique anomalies detected
    detected_anomalies = test_data['is_anomaly'].sum()
    
    # Calculate true positives across all methods
    true_positives = sum(idx in anomalous_test.index for idx in test_data[test_data['is_anomaly']].index)
    
    # Calculate metrics
    if detected_anomalies > 0:
        precision = true_positives / detected_anomalies
    else:
        precision = 0
        
    if len(anomalous_test) > 0:
        recall = true_positives / len(anomalous_test)
    else:
        recall = 0
    
    # Print combined results
    print(Fore.MAGENTA + "\n" + "="*50)
    print(Fore.MAGENTA + "COMBINED DETECTION RESULTS")
    print(Fore.MAGENTA + "="*50)
    print(Fore.WHITE + f"Total test records: {len(test_data)}")
    print(Fore.WHITE + f"Actual anomalies: {len(anomalous_test)}")
    print(Fore.GREEN + f"Total detected anomalies: {detected_anomalies}")
    print(Fore.GREEN + f"True positives: {true_positives}")
    print(Fore.GREEN + f"Precision: {precision:.2f}")
    print(Fore.GREEN + f"Recall: {recall:.2f}")
    
    # Individual method performance
    print(Fore.YELLOW + "\nPerformance by detection method:")
    methods = [
        ("Packet Length Analysis", length_anomalies, length_true_positives),
        ("Protocol-Port Analysis", protocol_anomalies, protocol_true_positives),
        ("Connection Rate Analysis", conn_anomalies, conn_true_positives)
    ]
    
    for method_name, anomaly_count, tp_count in methods:
        method_precision = tp_count / anomaly_count if anomaly_count > 0 else 0
        method_recall = tp_count / len(anomalous_test) if len(anomalous_test) > 0 else 0
        print(Fore.CYAN + f"- {method_name}:")
        print(f"  Detected: {anomaly_count}, True Positives: {tp_count}, Precision: {method_precision:.2f}, Recall: {method_recall:.2f}")
    
    # Show some sample anomalies by type
    print(Fore.YELLOW + "\nSample detected anomalies by type:")
    
    # Sample length-based anomalies
    length_samples = test_data[test_data['length_anomaly']].sample(min(3, length_anomalies))
    if not length_samples.empty:
        print(Fore.RED + "\nPacket Length Anomalies:")
        for _, anomaly in length_samples.iterrows():
            print(f"- {anomaly['src_ip']} → {anomaly['dst_ip']} ({anomaly['protocol']}): {anomaly['length']} bytes, z-score: {anomaly['length_zscore']:.2f}")
    
    # Sample protocol-port anomalies
    protocol_samples = test_data[test_data['protocol_port_anomaly']].sample(min(3, protocol_anomalies))
    if not protocol_samples.empty:
        print(Fore.RED + "\nProtocol-Port Anomalies:")
        for _, anomaly in protocol_samples.iterrows():
            print(f"- {anomaly['src_ip']} → {anomaly['dst_ip']} ({anomaly['protocol']} on port {anomaly['dst_port']})")
    
    # Sample connection rate anomalies
    conn_samples = test_data[test_data['conn_rate_anomaly']].sample(min(3, conn_anomalies))
    if not conn_samples.empty:
        print(Fore.RED + "\nConnection Rate Anomalies:")
        for _, anomaly in conn_samples.iterrows():
            src_ip = anomaly['src_ip']
            count = conn_rate[conn_rate['src_ip'] == src_ip]['conn_count'].max()
            print(f"- {src_ip} → {anomaly['dst_ip']} (Connection rate: {count} connections/min)")
    
    print(Fore.GREEN + "\nTest complete!")

if __name__ == "__main__":
    test_anomaly_detection() 