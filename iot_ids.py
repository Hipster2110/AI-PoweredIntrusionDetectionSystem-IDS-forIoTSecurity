from flask import Flask, render_template, request, jsonify
import scapy.all as scapy
import pandas as pd
import numpy as np
import nmap
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
import seaborn as sns
import matplotlib.pyplot as plt

app = Flask(__name__)

# Load pre-trained AI model (if available)
try:
    model = tf.keras.models.load_model("iot_intrusion_model.h5")
except:
    model = None

# Scan network for IoT devices
def scan_network(network_range):
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = [{"IP": pkt[1].psrc, "MAC": pkt[1].hwsrc} for pkt in answered_list]
    return devices

# Capture network traffic for AI analysis
def capture_traffic(interface="wlan0", packet_count=100):
    packets = scapy.sniff(iface=interface, count=packet_count)
    data = [{"time": pkt.time, "len": len(pkt), "proto": pkt.proto} for pkt in packets if hasattr(pkt, "proto")]
    return pd.DataFrame(data)

# AI-based anomaly detection
def detect_anomalies(data):
    global model
    if model is None:
        return ["No AI Model Found! Train and Load a Model First."]
    
    scaler = StandardScaler()
    data_scaled = scaler.fit_transform(data)
    predictions = model.predict(data_scaled)
    anomalies = ["Normal" if pred < 0.5 else "Threat Detected!" for pred in predictions]
    return anomalies

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    network = request.form['network']
    devices = scan_network(network)
    return jsonify(devices)

@app.route('/analyze', methods=['POST'])
def analyze():
    interface = request.form['interface']
    traffic_data = capture_traffic(interface)
    anomalies = detect_anomalies(traffic_data[["len", "proto"]])
    return jsonify(anomalies)

if __name__ == '__main__':
    app.run(debug=True)
