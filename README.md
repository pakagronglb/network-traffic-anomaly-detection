# 🛡️ Network Traffic Anomaly Detection System

A machine learning-based system for detecting anomalies in network traffic that could indicate security incidents.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Scapy](https://img.shields.io/badge/scapy-2.5.0-orange.svg)
![Pandas](https://img.shields.io/badge/pandas-2.0.3-green.svg)
![Scikit-learn](https://img.shields.io/badge/scikit--learn-1.3.0-red.svg)
![Matplotlib](https://img.shields.io/badge/matplotlib-3.7.2-blue.svg)
![Plotext](https://img.shields.io/badge/plotext-5.2.8-purple.svg)
![GeoIP](https://img.shields.io/badge/geoip2-4.7.0-yellow.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Features

- Captures and analyzes network traffic in real-time
- Uses machine learning to establish baseline network behavior
- Detects anomalies in:
  - Protocol usage
  - Connection patterns
  - Data transfer volumes
  - Geographic origins/destinations
  - Command-and-control patterns
  - Potential data exfiltration
- Terminal-based visualization of network anomalies
- Alerting system for suspicious activities

## 📋 Requirements

- Python 3.8+
- Scapy (packet manipulation)
- Pandas (data analysis)
- Scikit-learn (machine learning)
- matplotlib/plotext (terminal visualization)
- GeoIP database (for geographic analysis)

## 📥 Installation

1. Clone this repository
   ```bash
   git clone https://github.com/pakagronglb/network-traffic-anomaly-detection.git
   cd network-traffic-anomaly-detection
   ```

2. Create a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Download the GeoLite2 City database from MaxMind:
   - Go to https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
   - Create a free account and download the GeoLite2 City database
   - Place the `.mmdb` file in the `data/` directory as `data/GeoLite2-City.mmdb`

## ⚙️ Configuration

### 🌐 Network Interface

Edit `config/config.py` to set the network interface to monitor:

```python
# Default configuration
CAPTURE_INTERFACE = 'eth0'  # Change to your network interface
PACKET_COUNT = 0  # 0 for unlimited
TIMEOUT = None  # None for no timeout
BPF_FILTER = None  # None for no filter
```

Common interface names:
- Linux: `eth0`, `wlan0`, `ens33`
- macOS: `en0` (wireless), `en1` (wired)
- Windows: Use `python -c "from scapy.all import IFACES; print(IFACES)"` to list interfaces

### 🔧 Advanced Configuration Options

Additional options can be set in `config/config.py`:

```python
# Machine Learning Settings
ANOMALY_THRESHOLD = 0.95  # Detection threshold (0.0-1.0)
TRAINING_DATA_SIZE = 10000  # Number of packets for baseline
MODEL_PATH = 'models/anomaly_model.joblib'

# Alert Settings
ALERT_LEVEL = 'medium'  # 'low', 'medium', 'high'
NOTIFICATION_TYPE = 'console'  # 'console', 'file', 'email'
ALERT_LOG_PATH = 'logs/alerts.log'

# Geographic Analysis
GEO_IP_DATABASE = 'data/GeoLite2-City.mmdb'
ENABLE_GEO_ANALYSIS = True
```

## 🚀 Usage

### 📌 Basic Usage

Start the packet capture and analysis:
```bash
sudo ./main.py
```

> **Note**: Root/administrator privileges are required for packet capture on most systems.

### 💻 Command-Line Arguments

The system supports various command-line arguments to customize behavior:

```bash
sudo ./main.py -i eth0 -c 1000 -t 60 -f "tcp port 80" -v
```

| Argument | Description | Example |
|----------|-------------|---------|
| `-i, --interface` | Network interface to capture | `-i eth0` |
| `-c, --count` | Number of packets to capture (0=unlimited) | `-c 1000` |
| `-t, --timeout` | Capture timeout in seconds | `-t 60` |
| `-f, --filter` | BPF filter for packet capture | `-f "tcp port 443"` |
| `-m, --train-mode` | Run in training mode to establish baseline | `-m` |
| `-g, --geo` | Enable geographic analysis | `-g` |
| `-a, --anomaly-threshold` | Set anomaly detection threshold (0.0-1.0) | `-a 0.98` |
| `-v, --verbose` | Enable verbose output | `-v` |

### 📊 Use Cases

#### 📈 Establishing a Baseline

First, run the system in training mode to establish normal network behavior:

```bash
sudo ./main.py --train-mode -c 50000
```

This captures 50,000 packets to establish a baseline of normal traffic.

#### 👁️ Real-time Monitoring

After establishing a baseline, monitor traffic in real-time:

```bash
sudo ./main.py -v
```

#### 🔬 Monitoring Specific Traffic

To focus on specific protocols or services:

```bash
# Monitor web traffic only
sudo ./main.py -f "tcp port 80 or tcp port 443"

# Monitor DNS traffic
sudo ./main.py -f "udp port 53"

# Monitor traffic to/from a specific IP
sudo ./main.py -f "host 192.168.x.x"
```

#### 🧪 Testing with Simulation

If you don't have proper network access or permissions, use the simulation mode:

```bash
python simple_test.py
```

This will generate synthetic traffic and demonstrate the anomaly detection capabilities.

## 📊 Visualization and Outputs

The system provides several visualization options:

1. **Console output**: Real-time statistics in the terminal
2. **Terminal-based graphs**: Network traffic patterns using plotext
3. **Alerts**: Highlighted warnings for detected anomalies
4. **Data exports**: CSV files with traffic data (stored in `data/`)

## 📂 Project Structure

```
network_anomaly_detection/
├── config/           # Configuration files
├── data/             # Data storage
├── models/           # Trained ML models
├── src/              # Source code
│   ├── capture/      # Network traffic capture
│   ├── analysis/     # ML and anomaly detection
│   ├── visualization/ # Terminal visualization
│   └── utils/        # Helper functions
├── main.py           # Main entry point
├── simple_test.py    # Simulation script for testing
└── requirements.txt  # Dependencies
```

## 🛠️ Troubleshooting

### 🔒 Permission Issues

If you encounter permission errors:

```bash
# On Linux/macOS
sudo chmod +x main.py
sudo ./main.py

# Or run with sudo python
sudo python main.py
```

### 🔎 No Packets Captured

If no packets are being captured:

1. Verify you have the correct interface name: `ifconfig` or `ip addr`
2. Ensure you're running with sufficient permissions
3. Try using a more specific BPF filter to debug: `sudo ./main.py -f "icmp" -v`
4. Check if another application is using the network interface

### 🗺️ Missing GeoIP Database

If you encounter errors related to GeoIP:

1. Verify the database file exists at `data/GeoLite2-City.mmdb`
2. Disable geographic analysis if not needed: `sudo ./main.py --geo=false`

### 📦 Dependencies Issues

If you encounter module import errors:

```bash
pip install -r requirements.txt --upgrade
```

## 🔥 Advanced Usage

### 🔌 Integrating with Other Tools

The system can be used with other security tools:

```bash
# Pipe packets to Wireshark for detailed analysis
sudo ./main.py -o pcap -w capture.pcap

# Run as part of a security monitoring script
./monitor.sh | sudo ./main.py --filter "host 10.0.0.1"
```

### 🧠 Custom ML Models

Advanced users can develop custom anomaly detection models:

1. Create a new model class in `src/analysis/models/`
2. Implement the required interface methods
3. Update the configuration to use your custom model

## 🐉 Note for Kali Linux Deployment

This project is designed to be compatible with Kali Linux for security testing and monitoring. Additional permissions may be required for packet capture functionality when deployed on Kali.

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

MIT