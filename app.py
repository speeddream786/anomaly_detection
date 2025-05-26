from flask import Flask, request, jsonify
from threading import Thread, Event
from scapy.all import sniff
import time

app = Flask(__name__)

stop_sniffing = Event()
new_data_available = Event()
from scapy.all import sniff, IP, TCP, UDP
from threading import Thread
from queue import Queue
from datetime import datetime
import numpy as np

model_features = ['Bwd Packet Length Std', 'act_data_pkt_fwd', 'Subflow Bwd Packets',
       'Total Backward Packets', 'Fwd IAT Total', 'Fwd IAT Min',
       'Fwd IAT Mean', 'Flow Duration', 'Fwd IAT Std', 'Fwd IAT Max',
       'Flow IAT Min', 'Flow Bytes/s', 'Flow IAT Std',
       'Total Length of Fwd Packets', 'Fwd Packets/s', 'Flow IAT Mean',
       'Flow IAT Max', 'Flow Packets/s', 'Subflow Fwd Bytes', 'Bwd IAT Min']
flows = {}
predict_queue = Queue()
  
def process_packet(packet):

    if IP in packet:
        src_ip = packet[IP].src
        src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
        proto = packet[IP].proto
        timestamp = packet.time
        length = len(packet)
        
        formatted_time = datetime.fromtimestamp(timestamp).strftime("%d-%m-%Y %H:%M")
        
        # Unique Flow ID
        if (dst_ip, dst_port, src_ip, src_port, proto) not in flows:
            flow_id = (src_ip, src_port, dst_ip, dst_port, proto)
        else:
            flow_id = (dst_ip, dst_port, src_ip, src_port, proto)
            
        if flow_id not in flows:
            flows[flow_id] = {
                "Flow ID": f"{src_ip}-{src_port}-{dst_ip}-{dst_port}-{proto}",
                "Source IP": src_ip,
                "Source Port": src_port,
                "Destination IP": dst_ip,
                "Destination Port": dst_port,
                "Protocol": proto,
                "Timestamp": formatted_time,
                "Flow Duration": 0,
                "Total Fwd Packets": 0,
                "Total Backward Packets": 0,
                "Total Length of Fwd Packets": 0,
                "Total Length of Bwd Packets": 0,
                "Fwd Packet Length Mean": 0,
                "Bwd Packet Length Mean": 0,
                "Flow Bytes/s": 0,
                "Flow Packets/s": 0,
                "Flow IAT Mean": 0,
                "Flow IAT Std": 0,
                "Flow IAT Min": 0,
                "Flow IAT Max": 0,
                "Min Packet Length": float('inf'),
                "Max Packet Length": 0,
                "Packet Length Mean": 0,
                "Packet Length Std": 0,
                "Packet Count": 0,
                "First Timestamp": timestamp,
                "Packet Times": [],
                "Fwd Packet Times": [],
                "Bwd Packet Times": [],
                "Fwd IATs": [],
                "Bwd IATs": [],
                "Bwd Packet Lengths": [],
                "act_data_pkt_fwd": 0,
                "Subflow Fwd Bytes": 0,
                "Subflow Bwd Packets": 0,
                "Fwd IAT Min": 0,
                "Fwd IAT Max": 0,
                "Fwd IAT Mean": 0,
                "Fwd IAT Std": 0,
                "Fwd IAT Total": 0,
                "Fwd Packets/s": 0,
                "Bwd IAT Min": 0
            }

        flow = flows[flow_id]

        # General update
        flow["Packet Times"].append(timestamp)
        flow["Flow Duration"] = timestamp - flow["First Timestamp"]
        flow["Packet Count"] += 1
        flow["Min Packet Length"] = min(flow["Min Packet Length"], length)
        flow["Max Packet Length"] = max(flow["Max Packet Length"], length)

        # Direction check
        if (src_ip, src_port, dst_ip, dst_port, proto) == flow_id:
            # Forward packet
            flow["Total Fwd Packets"] += 1
            flow["Total Length of Fwd Packets"] += length
            flow["Fwd Packet Times"].append(timestamp)
            if len(flow["Fwd Packet Times"]) > 1:
                flow["Fwd IATs"].append(timestamp - flow["Fwd Packet Times"][-2])
            if length > 0:
                flow["act_data_pkt_fwd"] += 1
        else:
            # Backward packet
            flow["Total Backward Packets"] += 1
            flow["Total Length of Bwd Packets"] += length
            flow["Bwd Packet Times"].append(timestamp)
            flow["Bwd Packet Lengths"].append(length)
            if len(flow["Bwd Packet Times"]) > 1:
                flow["Bwd IATs"].append(timestamp - flow["Bwd Packet Times"][-2])

        # Stats calculation
        if len(flow["Packet Times"]) > 1:
            iat_values = np.diff(flow["Packet Times"])
            flow["Flow IAT Mean"] = np.mean(iat_values)
            flow["Flow IAT Std"] = np.std(iat_values)
            flow["Flow IAT Min"] = np.min(iat_values)
            flow["Flow IAT Max"] = np.max(iat_values)
        else:
            flow["Flow IAT Mean"] = flow["Flow IAT Std"] = flow["Flow IAT Min"] = flow["Flow IAT Max"] = 0

        # Mean & Std
        flow["Fwd Packet Length Mean"] = (flow["Total Length of Fwd Packets"] / flow["Total Fwd Packets"]) if flow["Total Fwd Packets"] > 0 else 0
        flow["Bwd Packet Length Mean"] = (flow["Total Length of Bwd Packets"] / flow["Total Backward Packets"]) if flow["Total Backward Packets"] > 0 else 0
        flow["Packet Length Mean"] = ((flow["Total Length of Fwd Packets"] + flow["Total Length of Bwd Packets"]) / flow["Packet Count"])
        
        if flow["Flow Duration"] > 0:
            flow["Flow Bytes/s"] = (flow["Total Length of Fwd Packets"] + flow["Total Length of Bwd Packets"]) / flow["Flow Duration"]
            flow["Flow Packets/s"] = flow["Packet Count"] / flow["Flow Duration"]
            flow["Fwd Packets/s"] = flow["Total Fwd Packets"] / flow["Flow Duration"]

        flow["Bwd Packet Length Std"] = np.std(flow["Bwd Packet Lengths"]) if flow["Bwd Packet Lengths"] else 0
        flow["Bwd IAT Min"] = np.min(flow["Bwd IATs"]) if flow["Bwd IATs"] else 0

        if flow["Fwd IATs"]:
            flow["Fwd IAT Min"] = np.min(flow["Fwd IATs"])
            flow["Fwd IAT Max"] = np.max(flow["Fwd IATs"])
            flow["Fwd IAT Mean"] = np.mean(flow["Fwd IATs"])
            flow["Fwd IAT Std"] = np.std(flow["Fwd IATs"])
            flow["Fwd IAT Total"] = np.sum(flow["Fwd IATs"])
        else:
            flow["Fwd IAT Min"] = flow["Fwd IAT Max"] = flow["Fwd IAT Mean"] = flow["Fwd IAT Std"] = flow["Fwd IAT Total"] = 0

        # Subflow values (assumed per flow)
        flow["Subflow Fwd Bytes"] = flow["Total Length of Fwd Packets"]
        flow["Subflow Bwd Packets"] = flow["Total Backward Packets"]


        predict_queue.put(flow_id)
def packet_sniffer():

    while not stop_sniffing.is_set():

        sniff(prn=process_packet,count=10000) 

@app.route("/start", methods=["POST"])
def start_sniffing():
    stop_sniffing.clear()
    Thread(target=packet_sniffer, daemon=True).start()

    return jsonify({"message": "Sniffing already in progress"})

@app.route("/stop", methods=["POST"])
def stop_sniff():
    stop_sniffing.set()
    return jsonify({"message": "Sniffing stopped"})

import pickle
import pandas as pd

with open("voting_classifier_model.pkl", "rb") as f:
    model = pickle.load(f)
result=[]
show_features=[
    'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol',
    'Total Fwd Packets', 'Total Backward Packets', 'Flow Duration',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
    'Flow IAT Min', 'Flow IAT Max', 'Fwd Packets/s', 'Prediction'
]
@app.route("/predict", methods=["GET"])
def get_prediction():
    data_list=[]

    while not predict_queue.empty():
      data_list.append(predict_queue.get())
    flow_data=[flows[data] for data in data_list]


    if len(flow_data)>0:
            df = pd.DataFrame(flow_data)
            df1 = df[model_features]
            res=model.predict(df1)
            df['Prediction'] = res
            df = df[show_features]
            df=df.drop_duplicates()
            result.extend(df.to_dict(orient='records'))

    return jsonify({"data": result})
from flask import Flask, request, jsonify, render_template
@app.route('/')
def index():
    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)
