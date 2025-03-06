from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import scapy.all as scapy
import pandas as pd
import tensorflow as tf
import numpy as np
import subprocess
import threading
from web3 import Web3
import time

app = Flask(__name__)
socketio = SocketIO(app)

# Load trained AI model (LSTM for sequential anomaly detection)
model = tf.keras.models.load_model("iot_intrusion_model_lstm.h5")

# Setup blockchain for immutable log storage
w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))  # Use your own Ethereum node here
contract_address = "YOUR_CONTRACT_ADDRESS"
abi = "YOUR_CONTRACT_ABI"
contract = w3.eth.contract(address=contract_address, abi=abi)

# Scan network for IoT devices
def scan_network(network_range):
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered_list = scapy.srp(arp_request / broadcast, timeout=1, verbose=False)[0]

    devices = [{"IP": pkt[1].psrc, "MAC": pkt[1].hwsrc} for pkt in answered_list]
    return devices

# Capture and analyze network traffic with LSTM-based anomaly detection
def analyze_traffic(interface="wlan0", packet_count=100):
    packets = scapy.sniff(iface=interface, count=packet_count)
    data = [{"len": len(pkt), "proto": pkt.proto} for pkt in packets if hasattr(pkt, "proto")]
    df = pd.DataFrame(data)

    if not df.empty:
        anomalies = detect_anomalies(df)
        for anomaly, pkt in zip(anomalies, packets):
            if anomaly == "Threat Detected!":
                malicious_ip = pkt[scapy.IP].src
                socketio.emit("threat_alert", {"ip": malicious_ip})
                auto_block_ip(malicious_ip)
                store_log_in_blockchain(malicious_ip)

# LSTM-based anomaly detection for sequential traffic analysis
def detect_anomalies(data):
    scaler = tf.keras.models.load_model("scaler_lstm.pkl")
    data_scaled = scaler.transform(data)
    predictions = model.predict(data_scaled)
    return ["Normal" if pred < 0.5 else "Threat Detected!" for pred in predictions]

# Auto-block suspicious IP using iptables
def auto_block_ip(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    print(f"🚨 Blocked suspicious IP: {ip}")

# Store attack logs on the blockchain for immutability
def store_log_in_blockchain(ip):
    account = w3.eth.accounts[0]  # Your Ethereum account for signing transactions
    txn = contract.functions.storeLog(ip, time.time()).buildTransaction({
        'from': account,
        'gas': 2000000,
        'gasPrice': w3.toWei('20', 'gwei'),
        'nonce': w3.eth.getTransactionCount(account),
    })
    signed_txn = w3.eth.account.signTransaction(txn, private_key="YOUR_PRIVATE_KEY")
    w3.eth.sendRawTransaction(signed_txn.rawTransaction)

# Start traffic monitoring in a separate thread
def start_monitoring(interface="wlan0"):
    while True:
        analyze_traffic(interface)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    network = request.form['network']
    devices = scan_network(network)
    return jsonify(devices)

if __name__ == '__main__':
    # Start traffic monitoring in a separate thread
    threading.Thread(target=start_monitoring, daemon=True).start()
    socketio.run(app, debug=True)
