"""
IPsecAI Database Storage Layer
Provides zero-friction local storage (in-memory + SQLite / JSON) with optional PostgreSQL support.
"""

import os
import json
import sqlite3
from typing import Dict, Any, Optional, List
from backend.models.schema import AnalysisResult


class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            db_dir = os.path.join(base_dir, "data")
            os.makedirs(db_dir, exist_ok=True)
            db_path = os.path.join(db_dir, "ipsecai.db")

        self.db_path = db_path
        self._memory_cache: Dict[str, AnalysisResult] = {}
        self._init_sqlite()

    def _init_sqlite(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_records (
                    analysis_id TEXT PRIMARY KEY,
                    filename TEXT,
                    overall_score INTEGER,
                    risk_level TEXT,
                    is_demo BOOLEAN,
                    payload_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            conn.close()
        except Exception:
            pass

    def save_analysis(self, analysis: AnalysisResult):
        self._memory_cache[analysis.analysis_id] = analysis
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO analysis_records 
                (analysis_id, filename, overall_score, risk_level, is_demo, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                analysis.analysis_id,
                analysis.capture_summary.filename,
                analysis.security_assessment.overall_score,
                analysis.security_assessment.risk_level,
                analysis.is_demo,
                analysis.model_dump_json()
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_analysis(self, analysis_id: str) -> Optional[AnalysisResult]:
        if analysis_id in self._memory_cache:
            return self._memory_cache[analysis_id]

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT payload_json FROM analysis_records WHERE analysis_id = ?", (analysis_id,))
            row = cursor.fetchone()
            conn.close()
            if row:
                data = json.loads(row[0])
                res = AnalysisResult.model_validate(data)
                self._memory_cache[analysis_id] = res
                return res
        except Exception:
            pass
        return None

    def list_analyses(self) -> List[Dict[str, Any]]:
        results = []
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT analysis_id, filename, overall_score, risk_level, is_demo, created_at FROM analysis_records ORDER BY created_at DESC")
            for row in cursor.fetchall():
                results.append({
                    "analysis_id": row[0],
                    "filename": row[1],
                    "overall_score": row[2],
                    "risk_level": row[3],
                    "is_demo": bool(row[4]),
                    "created_at": row[5]
                })
            conn.close()
        except Exception:
            pass
        return results
