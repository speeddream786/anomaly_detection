from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import time
import numpy as np
from datetime import datetime


flows = {}

def process_packet(packet):
    global flows

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


print("Capturing network traffic...")
sniff(prn=process_packet, filter="ip", count=10000)  


df = pd.DataFrame.from_dict(flows, orient='index')
df.drop(columns=["Packet Times", "First Timestamp", "Packet Count"], inplace=True)


df.to_csv("network_flow_features.csv", index=False)
