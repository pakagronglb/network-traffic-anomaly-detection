"""
Network traffic anomaly detection using machine learning.
"""

import os
import numpy as np
import pandas as pd
from datetime import datetime
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.pipeline import Pipeline

# Import project modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config import config
from src.utils.helpers import save_dataframe, print_alert

class AnomalyDetector:
    """Detect anomalies in network traffic using machine learning."""
    
    def __init__(self, model_dir=None):
        """Initialize the anomaly detector."""
        self.model_dir = model_dir or config.MODEL_DIR
        self.model = None
        self.scaler = None
        self.baseline_established = False
        self.is_training = False
        self.feature_columns = []
        self.categorical_columns = [
            'protocol', 'src_country', 'dst_country', 
            'src_is_private', 'dst_is_private'
        ]
        self.processed_packets = 0
        
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Try to load existing model
        self._load_model()
    
    def _load_model(self):
        """Load a trained model if available."""
        model_path = os.path.join(self.model_dir, 'anomaly_model.joblib')
        scaler_path = os.path.join(self.model_dir, 'feature_scaler.joblib')
        
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            try:
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                self.baseline_established = True
                print_alert("Loaded existing anomaly detection model", "INFO")
            except Exception as e:
                print_alert(f"Error loading model: {str(e)}", "WARNING")
                self.model = None
                self.scaler = None
                self.baseline_established = False
    
    def _save_model(self):
        """Save the trained model."""
        if self.model and self.scaler:
            model_path = os.path.join(self.model_dir, 'anomaly_model.joblib')
            scaler_path = os.path.join(self.model_dir, 'feature_scaler.joblib')
            
            try:
                joblib.dump(self.model, model_path)
                joblib.dump(self.scaler, scaler_path)
                print_alert("Saved anomaly detection model", "INFO")
            except Exception as e:
                print_alert(f"Error saving model: {str(e)}", "WARNING")
    
    def preprocess_features(self, df):
        """Preprocess and engineer features for anomaly detection."""
        if df.empty:
            return None
        
        # Make a copy to avoid modifying the original
        processed_df = df.copy()
        
        # Handle missing values
        processed_df.fillna({
            'protocol': 'UNKNOWN',
            'src_country': 'UNKNOWN',
            'dst_country': 'UNKNOWN',
            'src_port': 0,
            'dst_port': 0,
            'length': 0,
            'src_is_private': False,
            'dst_is_private': False
        }, inplace=True)
        
        # Convert categorical variables to one-hot encoding
        for cat_col in self.categorical_columns:
            if cat_col in processed_df.columns:
                # Skip if the column is missing or all values are the same
                if processed_df[cat_col].nunique() > 1:
                    dummies = pd.get_dummies(processed_df[cat_col], prefix=cat_col, drop_first=False)
                    processed_df = pd.concat([processed_df, dummies], axis=1)
        
        # Create derived features
        # Packet size ratio (relative to average packet size)
        if 'length' in processed_df.columns and len(processed_df) > 1:
            avg_length = processed_df['length'].mean()
            if avg_length > 0:
                processed_df['length_ratio'] = processed_df['length'] / avg_length
        
        # Protocol ratios - percentage of each protocol
        if 'protocol' in processed_df.columns:
            protocol_counts = processed_df['protocol'].value_counts(normalize=True)
            for protocol, ratio in protocol_counts.items():
                processed_df[f'protocol_ratio_{protocol}'] = ratio
        
        # Destination port entropy (measure of port distribution)
        if 'dst_port' in processed_df.columns:
            port_counts = processed_df['dst_port'].value_counts(normalize=True)
            port_entropy = -sum(p * np.log2(p) for p in port_counts if p > 0)
            processed_df['dst_port_entropy'] = port_entropy
        
        # Source port entropy
        if 'src_port' in processed_df.columns:
            port_counts = processed_df['src_port'].value_counts(normalize=True)
            port_entropy = -sum(p * np.log2(p) for p in port_counts if p > 0)
            processed_df['src_port_entropy'] = port_entropy
        
        # Geographic diversity (number of unique countries)
        if 'src_country' in processed_df.columns and 'dst_country' in processed_df.columns:
            src_countries = processed_df['src_country'].nunique()
            dst_countries = processed_df['dst_country'].nunique()
            processed_df['geo_diversity'] = src_countries + dst_countries
        
        # Number of connections per IP
        if 'src_ip' in processed_df.columns and 'dst_ip' in processed_df.columns:
            src_ip_counts = processed_df['src_ip'].value_counts()
            dst_ip_counts = processed_df['dst_ip'].value_counts()
            
            # Map counts back to DataFrame
            processed_df['src_ip_connection_count'] = processed_df['src_ip'].map(src_ip_counts)
            processed_df['dst_ip_connection_count'] = processed_df['dst_ip'].map(dst_ip_counts)
        
        # Drop non-numeric and non-feature columns
        exclude_columns = [
            'timestamp', 'packet_id', 'src_ip', 'dst_ip', 
            'protocol', 'src_country', 'dst_country', 'dns_query'
        ]
        feature_df = processed_df.drop([col for col in exclude_columns if col in processed_df.columns], axis=1)
        
        # Only keep numeric columns
        numeric_cols = feature_df.select_dtypes(include=['number']).columns.tolist()
        feature_df = feature_df[numeric_cols]
        
        # Store feature columns for future use
        self.feature_columns = feature_df.columns.tolist()
        
        return feature_df
    
    def train(self, df):
        """Train the anomaly detection model on baseline network traffic."""
        if df.empty:
            print_alert("No data provided for training", "WARNING")
            return False
        
        self.is_training = True
        print_alert("Training anomaly detection model...", "INFO")
        
        # Preprocess features
        feature_df = self.preprocess_features(df)
        if feature_df is None or feature_df.empty:
            print_alert("Failed to extract features for training", "WARNING")
            self.is_training = False
            return False
        
        try:
            # Initialize and fit the scaler
            self.scaler = StandardScaler()
            scaled_features = self.scaler.fit_transform(feature_df)
            
            # Create and train the Isolation Forest model
            self.model = IsolationForest(
                n_estimators=100,
                max_samples='auto',
                contamination=0.05,  # Expected percentage of anomalies
                random_state=42,
                verbose=0
            )
            
            self.model.fit(scaled_features)
            self.baseline_established = True
            self.processed_packets += len(df)
            
            # Save the trained model
            self._save_model()
            
            print_alert(f"Baseline established with {len(df)} packets", "INFO")
            self.is_training = False
            return True
            
        except Exception as e:
            print_alert(f"Error training model: {str(e)}", "HIGH")
            self.is_training = False
            return False
    
    def detect_anomalies(self, df):
        """Detect anomalies in network traffic."""
        if not self.baseline_established:
            print_alert("No baseline established yet. Training first...", "WARNING")
            self.train(df)
            return None
        
        if df.empty:
            print_alert("No data provided for anomaly detection", "WARNING")
            return None
        
        # Preprocess features
        feature_df = self.preprocess_features(df)
        if feature_df is None or feature_df.empty:
            print_alert("Failed to extract features for anomaly detection", "WARNING")
            return None
        
        # Make sure all expected feature columns exist
        for col in self.feature_columns:
            if col not in feature_df.columns:
                feature_df[col] = 0
        
        # Only use columns that were in the training data
        feature_df = feature_df[self.feature_columns]
        
        try:
            # Scale the features
            scaled_features = self.scaler.transform(feature_df)
            
            # Predict anomaly scores (-1 for anomalies, 1 for normal)
            anomaly_scores = self.model.decision_function(scaled_features)
            predictions = self.model.predict(scaled_features)
            
            # Convert to binary anomaly indicator (1 for anomaly, 0 for normal)
            # and normalize scores to 0-1 range
            binary_predictions = np.where(predictions == -1, 1, 0)
            normalized_scores = 1 - (anomaly_scores - np.min(anomaly_scores)) / (np.max(anomaly_scores) - np.min(anomaly_scores))
            
            # Add predictions and scores to the original dataframe
            result_df = df.copy()
            result_df['anomaly'] = binary_predictions
            result_df['anomaly_score'] = normalized_scores
            
            # Flag anomalies based on threshold
            result_df['is_anomaly'] = result_df['anomaly_score'] > config.ANOMALY_THRESHOLD
            
            self.processed_packets += len(df)
            
            return result_df
            
        except Exception as e:
            print_alert(f"Error detecting anomalies: {str(e)}", "HIGH")
            return None
    
    def analyze_anomalies(self, df_with_anomalies):
        """Analyze detected anomalies to identify patterns and potential threats."""
        if df_with_anomalies is None or 'is_anomaly' not in df_with_anomalies.columns:
            return {}
        
        # Filter to anomalous packets
        anomalies = df_with_anomalies[df_with_anomalies['is_anomaly'] == True].copy()
        if len(anomalies) == 0:
            return {'count': 0, 'percentage': 0, 'types': {}}
        
        analysis = {
            'count': len(anomalies),
            'percentage': (len(anomalies) / len(df_with_anomalies)) * 100,
            'types': {}
        }
        
        # Analyze by protocol
        if 'protocol' in anomalies.columns:
            analysis['types']['protocol'] = anomalies['protocol'].value_counts().to_dict()
        
        # Analyze by country
        if 'src_country' in anomalies.columns and 'dst_country' in anomalies.columns:
            analysis['types']['src_country'] = anomalies['src_country'].value_counts().to_dict()
            analysis['types']['dst_country'] = anomalies['dst_country'].value_counts().to_dict()
        
        # Analyze by ports
        if 'src_port' in anomalies.columns and 'dst_port' in anomalies.columns:
            analysis['types']['src_port'] = anomalies['src_port'].value_counts().head(5).to_dict()
            analysis['types']['dst_port'] = anomalies['dst_port'].value_counts().head(5).to_dict()
        
        # Analyze by packet size
        if 'length' in anomalies.columns:
            analysis['types']['avg_packet_size'] = anomalies['length'].mean()
            analysis['types']['max_packet_size'] = anomalies['length'].max()
        
        # Identify potential threat types
        analysis['potential_threats'] = self._identify_threat_types(anomalies)
        
        return analysis
    
    def _identify_threat_types(self, anomalies):
        """Identify potential threat types based on anomaly characteristics."""
        threats = []
        
        # Check for potential port scanning
        if 'dst_port' in anomalies.columns and len(anomalies) > 3:
            # Many different destination ports from same source IP
            src_ips = anomalies['src_ip'].value_counts()
            for src_ip, count in src_ips.items():
                if count > 3:
                    ports = anomalies[anomalies['src_ip'] == src_ip]['dst_port'].nunique()
                    if ports > 5:
                        threats.append({
                            'type': 'PORT_SCAN',
                            'source_ip': src_ip,
                            'ports_count': ports,
                            'confidence': min(1.0, ports / 20)  # Scale confidence based on number of ports
                        })
        
        # Check for potential data exfiltration
        if 'length' in anomalies.columns:
            # Large outbound packets
            large_packets = anomalies[anomalies['length'] > 1500]
            if len(large_packets) > 0:
                # Group by destination
                dst_counts = large_packets['dst_ip'].value_counts()
                for dst_ip, count in dst_counts.items():
                    if count > 2:
                        total_bytes = large_packets[large_packets['dst_ip'] == dst_ip]['length'].sum()
                        if total_bytes > 10000:  # More than 10KB
                            threats.append({
                                'type': 'DATA_EXFILTRATION',
                                'destination_ip': dst_ip,
                                'total_bytes': total_bytes,
                                'confidence': min(1.0, total_bytes / 100000)  # Scale confidence based on data volume
                            })
        
        # Check for suspicious geographic traffic
        if 'dst_country' in anomalies.columns:
            for country in config.SUSPICIOUS_COUNTRIES:
                suspicious = anomalies[anomalies['dst_country'] == country]
                if len(suspicious) > 0:
                    threats.append({
                        'type': 'SUSPICIOUS_COUNTRY',
                        'country': country,
                        'packet_count': len(suspicious),
                        'confidence': min(1.0, len(suspicious) / 10)  # Scale confidence based on packet count
                    })
        
        # Check for potential C&C communication
        if 'dst_ip' in anomalies.columns and 'protocol' in anomalies.columns:
            # Regular communication to the same destination
            dst_counts = anomalies['dst_ip'].value_counts()
            for dst_ip, count in dst_counts.items():
                if count > 3:
                    protocols = anomalies[anomalies['dst_ip'] == dst_ip]['protocol'].value_counts()
                    # Beaconing often uses the same protocol repeatedly
                    if protocols.max() / protocols.sum() > 0.8:  # 80% same protocol
                        threats.append({
                            'type': 'COMMAND_AND_CONTROL',
                            'destination_ip': dst_ip,
                            'dominant_protocol': protocols.idxmax(),
                            'confidence': min(1.0, count / 20)  # Scale confidence based on packet count
                        })
        
        return threats
    
    def update_model(self, df, with_new_data=True):
        """Update the anomaly detection model with new traffic data."""
        if df.empty:
            return False
        
        if not self.baseline_established or not with_new_data:
            # Train from scratch if no baseline exists
            return self.train(df)
        
        print_alert("Updating anomaly detection model...", "INFO")
        
        try:
            # First detect anomalies to exclude them from training
            result_df = self.detect_anomalies(df)
            if result_df is None:
                return False
            
            # Only use normal traffic for updating the model
            normal_df = result_df[result_df['is_anomaly'] == False]
            if len(normal_df) < 10:  # Too few normal packets
                print_alert("Too few normal packets to update model", "WARNING")
                return False
            
            # Preprocess features
            feature_df = self.preprocess_features(normal_df)
            if feature_df is None or feature_df.empty:
                return False
            
            # Scale features
            scaled_features = self.scaler.transform(feature_df)
            
            # Partial fit to update the model
            # Note: Isolation Forest doesn't support partial_fit, so we retrain
            # Could implement incremental learning with different algorithm
            self.model = IsolationForest(
                n_estimators=100,
                max_samples='auto',
                contamination=0.05,
                random_state=42,
                verbose=0
            )
            self.model.fit(scaled_features)
            
            # Save updated model
            self._save_model()
            
            print_alert(f"Updated model with {len(normal_df)} normal packets", "INFO")
            return True
            
        except Exception as e:
            print_alert(f"Error updating model: {str(e)}", "HIGH")
            return False
