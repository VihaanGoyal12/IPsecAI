"""
IPsecAI Streaming Engine
Simulates real-time IPsec packet/flow stream with AI classification.
Supports in-process generator and optional Kafka client integration.
"""

import time
import random
from typing import Dict, Any, List, Generator
from datetime import datetime

from backend.models.schema import FlowMetadata
from backend.ml.traffic_classifier import TrafficClassifier


class StreamEngine:
    def __init__(self):
        self.classifier = TrafficClassifier()
        self.kafka_available = False
        self._check_kafka()

    def _check_kafka(self):
        try:
            import kafka
            self.kafka_available = True
        except ImportError:
            self.kafka_available = False

    def generate_live_stream_batch(self, count: int = 5) -> List[Dict[str, Any]]:
        """
        Generates a batch of simulated live flow arrivals with AI inference.
        """
        classes = ["VoIP", "Video Streaming", "Web Browsing", "Email", "Messaging", "ICMP"]
        results = []

        for i in range(count):
            app_type = random.choice(classes)
            now_str = datetime.utcnow().strftime("%H:%M:%S")

            if app_type == "VoIP":
                pkt_cnt = random.randint(400, 600)
                avg_sz = round(random.uniform(170, 195), 1)
                dur = round(random.uniform(8.0, 15.0), 2)
                iat = 20.0
                ratio = 1.02
                burst = 2
            elif app_type == "Video Streaming":
                pkt_cnt = random.randint(1500, 2500)
                avg_sz = round(random.uniform(1280, 1400), 1)
                dur = round(random.uniform(30.0, 60.0), 2)
                iat = 15.0
                ratio = 0.07
                burst = 18
            elif app_type == "Web Browsing":
                pkt_cnt = random.randint(80, 220)
                avg_sz = round(random.uniform(650, 850), 1)
                dur = round(random.uniform(10.0, 25.0), 2)
                iat = 120.0
                ratio = 0.35
                burst = 8
            elif app_type == "Email":
                pkt_cnt = random.randint(40, 90)
                avg_sz = round(random.uniform(500, 620), 1)
                dur = round(random.uniform(8.0, 18.0), 2)
                iat = 220.0
                ratio = 0.65
                burst = 4
            elif app_type == "Messaging":
                pkt_cnt = random.randint(15, 35)
                avg_sz = round(random.uniform(240, 320), 1)
                dur = round(random.uniform(15.0, 30.0), 2)
                iat = 800.0
                ratio = 0.85
                burst = 3
            else:  # ICMP
                pkt_cnt = random.randint(20, 40)
                avg_sz = 84.0
                dur = round(float(pkt_cnt), 2)
                iat = 1000.0
                ratio = 1.0
                burst = 1

            bytes_val = int(pkt_cnt * avg_sz)
            flow = FlowMetadata(
                flow_id=f"STRM-{random.randint(1000, 9999)}",
                src_ip=f"198.51.100.{random.randint(10, 50)}",
                dst_ip=f"203.0.113.{random.randint(60, 90)}",
                src_port=4500,
                dst_port=4500,
                protocol="ESP",
                packet_count=pkt_cnt,
                byte_count=bytes_val,
                duration_seconds=dur,
                avg_packet_size=avg_sz,
                packet_size_std=20.0 if app_type == "VoIP" else 150.0,
                avg_interarrival_ms=iat,
                interarrival_std_ms=5.0,
                bytes_ratio_in_out=ratio,
                burst_count=burst,
                first_seen=now_str,
                last_seen=now_str
            )

            clf = self.classifier.classify_flow(flow)

            results.append({
                "time": now_str,
                "flow_id": flow.flow_id,
                "endpoints": f"{flow.src_ip} -> {flow.dst_ip}",
                "packet_count": flow.packet_count,
                "bytes": f"{flow.byte_count:,}",
                "protocol": "ESP (UDP 4500)",
                "inferred_traffic_type": clf.predicted_class,
                "ai_confidence": f"{int(clf.confidence_score * 100)}%",
                "source": "AI-Inferred"
            })

        return results
