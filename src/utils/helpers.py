"""
Helper functions for the Network Traffic Anomaly Detection System.
"""

import os
import logging
import socket
import ipaddress
import pandas as pd
import numpy as np
from datetime import datetime
import geoip2.database
from ipwhois import IPWhois
import yaml
import json
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configure logging
def setup_logging(log_file, level=logging.INFO):
    """Set up logging configuration."""
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger('network_anomaly')

# IP and network related functions
def is_private_ip(ip_str):
    """Check if an IP address is private."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False

def get_hostname(ip_str):
    """Try to resolve IP to hostname."""
    try:
        return socket.gethostbyaddr(ip_str)[0]
    except (socket.herror, socket.gaierror):
        return None

def get_geo_info(ip_str, geoip_database):
    """Get geographic information for an IP address."""
    if is_private_ip(ip_str):
        return {
            'country_code': 'LOCAL',
            'country_name': 'Local Network',
            'city': '',
            'latitude': 0,
            'longitude': 0
        }
    
    try:
        with geoip2.database.Reader(geoip_database) as reader:
            response = reader.city(ip_str)
            return {
                'country_code': response.country.iso_code,
                'country_name': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
    except Exception as e:
        logging.debug(f"GeoIP lookup failed for {ip_str}: {e}")
        return {
            'country_code': 'UNKNOWN',
            'country_name': 'Unknown',
            'city': '',
            'latitude': 0,
            'longitude': 0
        }

def get_whois_info(ip_str):
    """Get WHOIS information for an IP address."""
    if is_private_ip(ip_str):
        return {'org': 'Local Network', 'asn': 'NA', 'asn_description': 'Local Network'}
    
    try:
        whois = IPWhois(ip_str)
        result = whois.lookup_whois()
        return {
            'org': result.get('asn_description', 'Unknown'),
            'asn': result.get('asn', 'Unknown'),
            'asn_description': result.get('asn_description', 'Unknown')
        }
    except Exception as e:
        logging.debug(f"WHOIS lookup failed for {ip_str}: {e}")
        return {'org': 'Unknown', 'asn': 'Unknown', 'asn_description': 'Unknown'}

# Data handling functions
def save_dataframe(df, file_path, format='csv'):
    """Save a pandas DataFrame to file."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    if format.lower() == 'csv':
        df.to_csv(file_path, index=False)
    elif format.lower() == 'parquet':
        df.to_parquet(file_path, index=False)
    elif format.lower() == 'pickle' or format.lower() == 'pkl':
        df.to_pickle(file_path)
    else:
        raise ValueError(f"Unsupported format: {format}")

def load_dataframe(file_path, format=None):
    """Load a pandas DataFrame from file."""
    if not os.path.exists(file_path):
        return None
    
    if format is None:
        format = os.path.splitext(file_path)[1][1:].lower()
        
    if format == 'csv':
        return pd.read_csv(file_path)
    elif format == 'parquet':
        return pd.read_parquet(file_path)
    elif format in ('pickle', 'pkl'):
        return pd.read_pickle(file_path)
    else:
        raise ValueError(f"Unsupported format: {format}")

# Terminal output formatting
def print_alert(message, level='INFO'):
    """Print a colored alert message based on severity level."""
    colors = {
        'INFO': Fore.BLUE,
        'LOW': Fore.GREEN,
        'MEDIUM': Fore.YELLOW,
        'HIGH': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }
    color = colors.get(level, Fore.WHITE)
    print(f"{color}[{level}] {message}{Style.RESET_ALL}")

def print_banner(text):
    """Print a banner with the given text."""
    width = len(text) + 4
    print("=" * width)
    print(f"= {text} =")
    print("=" * width)

def print_table(data, headers):
    """Print data as a formatted table."""
    from tabulate import tabulate
    print(tabulate(data, headers=headers, tablefmt="grid"))

# Configuration functions
def load_config_file(config_file):
    """Load configuration from YAML file."""
    if not os.path.exists(config_file):
        return {}
    
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def save_config_file(config_data, config_file):
    """Save configuration to YAML file."""
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    
    with open(config_file, 'w') as f:
        yaml.dump(config_data, f, default_flow_style=False)

# Time and date functions
def get_timestamp():
    """Get current timestamp in ISO format."""
    return datetime.now().isoformat()

def get_time_windows(timestamps, window_size_seconds):
    """Split timestamps into time windows."""
    if len(timestamps) == 0:
        return []
    
    timestamps = pd.to_datetime(timestamps)
    min_time = timestamps.min()
    max_time = timestamps.max()
    
    window_edges = pd.date_range(
        start=min_time, 
        end=max_time, 
        freq=f'{window_size_seconds}S'
    )
    
    if window_edges[-1] < max_time:
        window_edges = window_edges.append(pd.DatetimeIndex([max_time]))
    
    return window_edges
