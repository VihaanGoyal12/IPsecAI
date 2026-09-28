"""
IPsecAI Traffic Classification Module
Machine learning inference based on observable flow metadata (XGBoost / Scikit-Learn).
Does NOT perform payload decryption; relies strictly on statistical traffic flow features.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
try:
    import xgboost
    from xgboost import XGBClassifier
    HAS_XGB = True
except Exception:
    HAS_XGB = False

from backend.models.schema import FlowMetadata, ClassificationResult, FeatureContribution
from backend.ml.dataset_generator import generate_synthetic_flow_dataset, FEATURE_COLUMNS, CLASSES


class TrafficClassifier:
    def __init__(self):
        self.feature_columns = FEATURE_COLUMNS
        self.classes = CLASSES
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(self.classes)
        self.model = None
        self.feature_importances_ = {}
        self._train_prototype_model()

    def _train_prototype_model(self):
        df = generate_synthetic_flow_dataset(samples_per_class=200, seed=42)
        X = df[self.feature_columns]
        y = self.label_encoder.transform(df["label"])

        if HAS_XGB:
            self.model = XGBClassifier(
                n_estimators=60,
                max_depth=4,
                learning_rate=0.1,
                random_state=42,
                eval_metric="mlogloss"
            )
        else:
            self.model = RandomForestClassifier(
                n_estimators=60,
                max_depth=6,
                random_state=42
            )

        self.model.fit(X, y)
        importances = self.model.feature_importances_
        self.feature_importances_ = {
            col: round(float(imp), 4) for col, imp in zip(self.feature_columns, importances)
        }

    def classify_flow(self, flow: FlowMetadata) -> ClassificationResult:
        feat_df = pd.DataFrame([{
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
            "duration_seconds": flow.duration_seconds,
            "avg_packet_size": flow.avg_packet_size,
            "packet_size_std": flow.packet_size_std,
            "avg_interarrival_ms": flow.avg_interarrival_ms,
            "interarrival_std_ms": flow.interarrival_std_ms,
            "bytes_ratio_in_out": flow.bytes_ratio_in_out,
            "burst_count": flow.burst_count
        }])[self.feature_columns]

        probs = self.model.predict_proba(feat_df)[0]
        pred_idx = int(np.argmax(probs))
        predicted_class = self.label_encoder.inverse_transform([pred_idx])[0]
        confidence = float(probs[pred_idx])

        # Map probabilities dict
        prob_dict = {
            cls_name: round(float(probs[i]), 4)
            for i, cls_name in enumerate(self.label_encoder.classes_)
        }

        # Calculate top contributing features
        feature_descriptions = {
            "avg_packet_size": "Mean packet length (bytes)",
            "packet_size_std": "Standard deviation of packet lengths",
            "avg_interarrival_ms": "Mean inter-packet arrival time (ms)",
            "interarrival_std_ms": "Jitter / variance of arrival times (ms)",
            "bytes_ratio_in_out": "Directional byte ratio (inbound/outbound)",
            "packet_count": "Total packet count in flow",
            "byte_count": "Aggregate volume in bytes",
            "duration_seconds": "Total flow duration (seconds)",
            "burst_count": "Detected burst clusters"
        }

        # Top 4 features ranked by global importance and flow characteristics
        sorted_feats = sorted(
            self.feature_importances_.items(),
            key=lambda x: x[1],
            reverse=True
        )[:4]

        top_features: List[FeatureContribution] = []
        flow_dict = flow.model_dump()
        for feat_name, imp in sorted_feats:
            val = float(flow_dict.get(feat_name, 0.0))
            top_features.append(FeatureContribution(
                feature_name=feat_name,
                feature_value=round(val, 2),
                importance_score=imp,
                description=feature_descriptions.get(feat_name, feat_name)
            ))

        return ClassificationResult(
            flow_id=flow.flow_id,
            predicted_class=predicted_class,
            confidence_score=round(confidence, 3),
            probabilities=prob_dict,
            top_features=top_features,
            inference_method=f"{'XGBoost' if HAS_XGB else 'Random Forest'} Flow Metadata Classifier",
            disclaimer="Inferred from observable flow statistical characteristics; payloads remain encrypted."
        )

    def classify_all_flows(self, flows: List[FlowMetadata]) -> List[ClassificationResult]:
        return [self.classify_flow(f) for f in flows]
