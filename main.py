#!/usr/bin/env python3
"""
Network Traffic Anomaly Detection System - Main Entry Point
"""

import os
import sys
import time
import argparse
import pandas as pd
from datetime import datetime
import signal
import threading

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import project modules
from config import config
from src.capture.packet_capture import PacketCapture
from src.analysis.anomaly_detector import AnomalyDetector
from src.visualization.visualizer import Visualizer
from src.utils.helpers import setup_logging, print_alert, print_banner

# Global flags for signal handling
stop_requested = threading.Event()

def signal_handler(sig, frame):
    """Handle Ctrl+C and other termination signals."""
    print_alert("\nShutdown requested, cleaning up...", "INFO")
    stop_requested.set()

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Network Traffic Anomaly Detection System")
    
    parser.add_argument("-i", "--interface", dest="interface",
                      help="Network interface to capture traffic from")
    
    parser.add_argument("-c", "--count", dest="count", type=int,
                      help="Number of packets to capture per session")
    
    parser.add_argument("-t", "--timeout", dest="timeout", type=int,
                      help="Timeout for each capture session in seconds")
    
    parser.add_argument("-f", "--filter", dest="capture_filter",
                      help="BPF filter for packet capture")
    
    parser.add_argument("--visualize-only", dest="visualize_only", action="store_true",
                      help="Only visualize existing data without capturing new packets")
    
    parser.add_argument("--train-only", dest="train_only", action="store_true",
                      help="Only train the model without running detection")
    
    parser.add_argument("--no-geo", dest="no_geo", action="store_true",
                      help="Disable geographic analysis")
    
    parser.add_argument("--threshold", dest="threshold", type=float,
                      help="Anomaly detection threshold (0.0-1.0)")
    
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                      help="Verbose output")
    
    return parser.parse_args()

def update_config(args):
    """Update configuration with command line arguments."""
    if args.interface:
        config.CAPTURE_INTERFACE = args.interface
    
    if args.count:
        config.PACKET_COUNT = args.count
    
    if args.timeout:
        config.CAPTURE_TIMEOUT = args.timeout
    
    if args.capture_filter:
        config.CAPTURE_FILTER = args.capture_filter
    
    if args.no_geo:
        config.GEOIP_ENABLED = False
    
    if args.threshold:
        config.ANOMALY_THRESHOLD = max(0.0, min(1.0, args.threshold))  # Clamp to 0.0-1.0

def get_dashboard_data(packet_capture, anomaly_detector, current_anomalies=None):
    """Gather data for the dashboard visualization."""
    dashboard_data = {
        'packet_count': packet_capture.packet_count,
        'protocol_counts': {},
        'anomaly_score': 0.0,
        'threat_counts': {}
    }
    
    # Calculate average anomaly score if available
    if current_anomalies is not None and 'anomaly_score' in current_anomalies.columns:
        dashboard_data['anomaly_score'] = current_anomalies['anomaly_score'].mean()
    
    # Get protocol counts if available
    protocol_stats = packet_capture.get_protocol_stats()
    for protocol, stats in protocol_stats.items():
        dashboard_data['protocol_counts'][protocol] = stats['count']
    
    # Get threat counts if available
    if current_anomalies is not None and 'is_anomaly' in current_anomalies.columns:
        # Filter to anomalies
        anomalies = current_anomalies[current_anomalies['is_anomaly'] == True]
        if len(anomalies) > 0:
            # Get threat analysis
            threats = anomaly_detector.analyze_anomalies(current_anomalies)
            if 'potential_threats' in threats:
                # Count by threat type
                threat_types = {}
                for threat in threats['potential_threats']:
                    threat_type = threat.get('type', 'UNKNOWN')
                    if threat_type not in threat_types:
                        threat_types[threat_type] = 0
                    threat_types[threat_type] += 1
                
                dashboard_data['threat_counts'] = threat_types
    
    return dashboard_data

def main():
    """Main application entry point."""
    print_banner("Network Traffic Anomaly Detection System")
    
    # Parse arguments
    args = parse_arguments()
    update_config(args)
    
    # Set up logging
    log_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_logging(config.LOG_FILE, getattr(sys.modules["logging"], log_level))
    
    # Initialize components
    packet_capture = PacketCapture(
        interface=config.CAPTURE_INTERFACE,
        capture_filter=config.CAPTURE_FILTER
    )
    
    anomaly_detector = AnomalyDetector()
    visualizer = Visualizer()
    
    # Check if we need to train first
    if args.train_only or not anomaly_detector.baseline_established:
        print_alert("Training mode - capturing baseline traffic...", "INFO")
        
        # Capture initial baseline data
        total_packets = 0
        while total_packets < config.BASELINE_MIN_PACKETS and not stop_requested.is_set():
            print_alert(f"Capturing baseline packets ({total_packets}/{config.BASELINE_MIN_PACKETS})...", "INFO")
            packet_capture.start_capture()
            packet_capture.capture_thread.join()  # Wait for capture to complete
            
            # Extract features and accumulate packets
            features_df = packet_capture.extract_features()
            if not features_df.empty:
                total_packets += len(features_df)
                
                # Train with accumulated data
                if total_packets >= config.BASELINE_MIN_PACKETS:
                    print_alert("Training anomaly detection model...", "INFO")
                    anomaly_detector.train(features_df)
            
            # Check if training only
            if args.train_only and anomaly_detector.baseline_established:
                print_alert("Training completed successfully.", "INFO")
                return
    
    # Start visualization in a separate thread
    if not args.train_only:
        visualizer.start_visualization(
            lambda: get_dashboard_data(packet_capture, anomaly_detector)
        )
    
    # Main processing loop
    try:
        current_anomalies = None
        
        while not stop_requested.is_set():
            # Capture packets
            print_alert(f"Starting packet capture on {config.CAPTURE_INTERFACE}...", "INFO")
            packet_capture.start_capture()
            packet_capture.capture_thread.join()  # Wait for capture to complete
            
            # Extract features
            features_df = packet_capture.extract_features()
            
            if not features_df.empty:
                # Detect anomalies
                current_anomalies = anomaly_detector.detect_anomalies(features_df)
                
                if current_anomalies is not None:
                    # Count anomalies
                    anomaly_count = current_anomalies['is_anomaly'].sum()
                    
                    if anomaly_count > 0:
                        print_alert(f"Detected {anomaly_count} anomalies in {len(current_anomalies)} packets", "MEDIUM")
                        
                        # Analyze anomalies
                        analysis = anomaly_detector.analyze_anomalies(current_anomalies)
                        
                        # Visualize anomalies
                        visualizer.visualize_anomalies(current_anomalies)
                        
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
                    
                    # Update the model periodically
                    if anomaly_detector.processed_packets % 10000 == 0:
                        print_alert("Updating anomaly detection model...", "INFO")
                        anomaly_detector.update_model(features_df)
            
            # Update visualization data
            visualization_data = get_dashboard_data(packet_capture, anomaly_detector, current_anomalies)
            visualizer.update_data(visualization_data)
            
    except Exception as e:
        logger.error(f"Error in main loop: {str(e)}")
        print_alert(f"Error: {str(e)}", "HIGH")
    
    finally:
        # Clean up
        print_alert("Stopping all processes...", "INFO")
        packet_capture.stop_capture_process()
        visualizer.stop_visualization_process()
        print_alert("Shutdown complete.", "INFO")

if __name__ == "__main__":
    main()
