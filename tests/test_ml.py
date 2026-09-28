"""
Tests for ML Traffic Classification Module
Verifies feature extraction, model predictions, probability summing, and explainability features.
"""

import pytest
from backend.models.schema import FlowMetadata
from backend.ml.traffic_classifier import TrafficClassifier
from backend.ml.dataset_generator import generate_synthetic_flow_dataset, CLASSES


def test_synthetic_dataset_generation():
    df = generate_synthetic_flow_dataset(samples_per_class=20)
    assert len(df) == 20 * len(CLASSES)
    assert "label" in df.columns
    assert set(df["label"].unique()) == set(CLASSES)


def test_traffic_classifier_prediction():
    clf = TrafficClassifier()
    
    # Create test VoIP flow
    voip_flow = FlowMetadata(
        flow_id="TEST-VOIP",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=4500,
        dst_port=4500,
        protocol="ESP",
        packet_count=500,
        byte_count=90000,
        duration_seconds=10.0,
        avg_packet_size=180.0,
        packet_size_std=15.0,
        avg_interarrival_ms=20.0,
        interarrival_std_ms=3.0,
        bytes_ratio_in_out=1.01,
        burst_count=2,
        first_seen="2026-09-28T00:00:00Z",
        last_seen="2026-09-28T00:00:10Z"
    )

    res = clf.classify_flow(voip_flow)
    assert res.predicted_class in CLASSES
    assert 0.0 <= res.confidence_score <= 1.0
    
    # Check probabilities sum to ~1.0
    prob_sum = sum(res.probabilities.values())
    assert 0.98 <= prob_sum <= 1.02, f"Probabilities should sum to ~1.0, got {prob_sum}"
    
    # Check top features are populated
    assert len(res.top_features) > 0
    assert res.disclaimer is not None
