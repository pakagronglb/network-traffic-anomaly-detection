"""
Configuration settings for the Network Traffic Anomaly Detection System.
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent

# Data paths
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODEL_DIR = os.path.join(BASE_DIR, 'models')

# Create directories if they don't exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

# Network capture settings
CAPTURE_INTERFACE = 'eth0'  # Change to your network interface (e.g., 'eth0', 'wlan0')
CAPTURE_FILTER = ""  # BPF filter (e.g., "tcp port 80" or "")
CAPTURE_TIMEOUT = 30  # seconds for each capture session
PACKET_COUNT = 1000  # number of packets to capture in each session

# Analysis settings
BASELINE_MIN_PACKETS = 10000  # Minimum packets to establish baseline
TRAINING_DATA_FILE = os.path.join(DATA_DIR, 'training_data.csv')
MODEL_FILE = os.path.join(MODEL_DIR, 'anomaly_model.joblib')
FEATURE_SCALER_FILE = os.path.join(MODEL_DIR, 'feature_scaler.joblib')
ANOMALY_THRESHOLD = 0.9  # Threshold for anomaly detection (higher = more sensitive)

# Feature extraction settings
TIME_WINDOW = 60  # seconds
PROTOCOLS_TO_MONITOR = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH']

# Geo IP settings
GEOIP_ENABLED = True  # Set to False if you don't want geographic analysis
SUSPICIOUS_COUNTRIES = ['RU', 'CN', 'KP', 'IR']  # Example list of countries of interest

# Visualization settings
PLOT_UPDATE_INTERVAL = 5  # seconds
DASHBOARD_ITEMS = {
    'show_protocol_distribution': True,
    'show_packet_volume': True,
    'show_connection_map': True,
    'show_anomaly_scores': True,
    'show_geographic_traffic': GEOIP_ENABLED,
}

# Alert settings
ALERT_LEVELS = {
    'LOW': 0.7,
    'MEDIUM': 0.8,
    'HIGH': 0.9,
    'CRITICAL': 0.95
}
LOG_FILE = os.path.join(DATA_DIR, 'anomaly_alerts.log')
