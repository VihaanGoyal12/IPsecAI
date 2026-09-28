"""
IPsecAI Synthetic Flow Dataset Generator
Generates realistic, statistically grounded flow metadata for encrypted traffic classification.
Classes: Web Browsing, VoIP, Video Streaming, Email, Messaging, ICMP.
Features: packet_count, byte_count, duration_seconds, avg_packet_size, packet_size_std,
          avg_interarrival_ms, interarrival_std_ms, bytes_ratio_in_out, burst_count.
"""

import numpy as np
import pandas as pd
from typing import Tuple, List, Dict


CLASSES = [
    "Web Browsing",
    "VoIP",
    "Video Streaming",
    "Email",
    "Messaging",
    "ICMP"
]

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration_seconds",
    "avg_packet_size",
    "packet_size_std",
    "avg_interarrival_ms",
    "interarrival_std_ms",
    "bytes_ratio_in_out",
    "burst_count"
]


def generate_synthetic_flow_dataset(samples_per_class: int = 150, seed: int = 42) -> pd.DataFrame:
    """
    Generates synthetic flow features reflecting empirical networking characteristics.
    """
    np.random.seed(seed)
    rows = []

    for label in CLASSES:
        for _ in range(samples_per_class):
            if label == "VoIP":
                # VoIP: Frequent, small, uniform packets (e.g. G.711 / G.729 RTP payload in ESP)
                pkt_count = int(np.random.normal(500, 80))
                pkt_count = max(50, pkt_count)
                avg_size = np.random.normal(180, 12)
                size_std = np.random.normal(15, 4)
                duration = pkt_count * 0.02 + np.random.normal(0, 0.5)  # ~20ms interval
                duration = max(1.0, duration)
                avg_iat = np.random.normal(20.0, 2.0)
                iat_std = np.random.normal(4.0, 1.0)
                byte_ratio = np.random.normal(1.02, 0.08)  # Symmetric duplex
                bursts = int(np.random.normal(2, 1))

            elif label == "Video Streaming":
                # Video: High packet count, large MTU-bounded packets, high downstream ratio
                pkt_count = int(np.random.normal(1800, 300))
                pkt_count = max(200, pkt_count)
                avg_size = np.random.normal(1320, 60)
                size_std = np.random.normal(190, 30)
                duration = np.random.normal(45.0, 10.0)
                duration = max(5.0, duration)
                avg_iat = np.random.normal(15.0, 5.0)
                iat_std = np.random.normal(22.0, 6.0)
                byte_ratio = np.random.normal(0.08, 0.03)  # Heavily downstream
                bursts = int(np.random.normal(18, 4))

            elif label == "Web Browsing":
                # Web: Bursty requests/responses, mixed packet sizes, client think-time
                pkt_count = int(np.random.normal(140, 40))
                pkt_count = max(20, pkt_count)
                avg_size = np.random.normal(720, 120)
                size_std = np.random.normal(450, 60)
                duration = np.random.normal(18.0, 5.0)
                duration = max(2.0, duration)
                avg_iat = np.random.normal(120.0, 40.0)
                iat_std = np.random.normal(180.0, 50.0)
                byte_ratio = np.random.normal(0.35, 0.12)
                bursts = int(np.random.normal(8, 2))

            elif label == "Email":
                # Email: Periodic synchronization, medium bursts
                pkt_count = int(np.random.normal(60, 20))
                pkt_count = max(10, pkt_count)
                avg_size = np.random.normal(550, 80)
                size_std = np.random.normal(320, 40)
                duration = np.random.normal(12.0, 4.0)
                duration = max(1.5, duration)
                avg_iat = np.random.normal(240.0, 60.0)
                iat_std = np.random.normal(160.0, 40.0)
                byte_ratio = np.random.normal(0.65, 0.20)
                bursts = int(np.random.normal(4, 1))

            elif label == "Messaging":
                # Messaging: Low packet count, small payloads, long idle times
                pkt_count = int(np.random.normal(25, 8))
                pkt_count = max(5, pkt_count)
                avg_size = np.random.normal(280, 40)
                size_std = np.random.normal(90, 20)
                duration = np.random.normal(25.0, 8.0)
                duration = max(3.0, duration)
                avg_iat = np.random.normal(850.0, 200.0)
                iat_std = np.random.normal(400.0, 100.0)
                byte_ratio = np.random.normal(0.85, 0.25)
                bursts = int(np.random.normal(3, 1))

            elif label == "ICMP":
                # ICMP (e.g. echo request/reply tunnel probing): Very uniform, tiny size, fixed 1000ms
                pkt_count = int(np.random.normal(30, 5))
                pkt_count = max(4, pkt_count)
                avg_size = np.random.normal(84, 4)
                size_std = np.random.normal(2, 1)
                duration = pkt_count * 1.0 + np.random.normal(0, 0.1)
                duration = max(1.0, duration)
                avg_iat = np.random.normal(1000.0, 15.0)
                iat_std = np.random.normal(10.0, 4.0)
                byte_ratio = np.random.normal(1.0, 0.01)
                bursts = 1

            avg_size = max(40.0, avg_size)
            size_std = max(0.5, size_std)
            avg_iat = max(1.0, avg_iat)
            iat_std = max(0.1, iat_std)
            byte_ratio = max(0.001, byte_ratio)
            bursts = max(1, bursts)
            byte_count = int(pkt_count * avg_size)

            rows.append({
                "label": label,
                "packet_count": pkt_count,
                "byte_count": byte_count,
                "duration_seconds": round(duration, 3),
                "avg_packet_size": round(avg_size, 2),
                "packet_size_std": round(size_std, 2),
                "avg_interarrival_ms": round(avg_iat, 2),
                "interarrival_std_ms": round(iat_std, 2),
                "bytes_ratio_in_out": round(byte_ratio, 3),
                "burst_count": bursts,
            })

    df = pd.DataFrame(rows)
    return df
