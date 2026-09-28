"""
IPsecAI Rule Engine
Deterministic rule evaluator grounded in NIST SP 800-77 Rev. 1, RFC 7296, and RFC 4301.
Evaluates observed IPsec session and SA parameters against configured security rules.
"""

import os
import yaml
from typing import List, Dict, Any, Optional
from backend.models.schema import IPsecSession, Finding, SecurityAssociation


class RuleEngine:
    def __init__(self, rules_path: Optional[str] = None):
        if rules_path is None:
            # Default to config/security_rules.yaml relative to project root
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            rules_path = os.path.join(base_dir, "config", "security_rules.yaml")
        
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.rules_path):
            return []
        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data.get("rules", []) if isinstance(data, dict) else []
        except Exception:
            return []

    def evaluate_session(self, session: IPsecSession) -> List[Finding]:
        """
        Evaluates an IPsec session and returns detected findings with evidence.
        """
        findings: List[Finding] = []
        sa = session.security_association

        # Extract normalized attributes
        attr_map = {
            "encryption_algorithm": sa.encryption_algorithm,
            "integrity_algorithm": sa.integrity_algorithm,
            "dh_group": sa.dh_group,
            "pfs_enabled": sa.pfs_enabled,
            "replay_protection_enabled": sa.replay_protection_enabled,
            "sa_lifetime_seconds": sa.sa_lifetime_seconds,
            "sa_volume_limit_mb": sa.sa_volume_limit_mb,
            "vpn_mode": session.vpn_mode,
            "ike_version": session.ike_version,
            "metadata_padding_enabled": sa.metadata_padding_enabled,
        }

        finding_counter = 1
        for rule in self.rules:
            rule_id = rule.get("id", f"RULE-{finding_counter}")
            target_field = rule.get("target_field")
            operator = rule.get("operator", "eq")
            rule_values = rule.get("values", [])
            
            if target_field not in attr_map:
                continue

            field_val = attr_map[target_field]
            triggered = False
            evidence_str = ""

            if operator == "in":
                # Check if field_val is in rule_values (case-insensitive string comparison if string)
                if isinstance(field_val, str):
                    triggered = any(field_val.strip().lower() == str(v).strip().lower() for v in rule_values)
                else:
                    triggered = field_val in rule_values
                if triggered:
                    evidence_str = f"Observed {target_field} = '{field_val}', which matches restricted set {rule_values}."

            elif operator == "contains":
                if isinstance(field_val, str):
                    for v in rule_values:
                        if str(v).lower() in field_val.lower():
                            triggered = True
                            evidence_str = f"Observed {target_field} = '{field_val}', containing pattern '{v}'."
                            break

            elif operator == "eq":
                if len(rule_values) > 0:
                    target_v = rule_values[0]
                    if isinstance(field_val, bool):
                        triggered = (field_val == bool(target_v))
                    elif isinstance(field_val, str):
                        triggered = (field_val.strip().lower() == str(target_v).strip().lower())
                    else:
                        triggered = (field_val == target_v)
                    if triggered:
                        evidence_str = f"Observed {target_field} = '{field_val}' (criterion: {target_v})."

            elif operator == "gt":
                if len(rule_values) > 0 and isinstance(field_val, (int, float)):
                    threshold = rule_values[0]
                    triggered = (field_val > threshold)
                    if triggered:
                        evidence_str = f"Observed {target_field} = {field_val}, exceeding threshold of {threshold}."

            elif operator == "lt":
                if len(rule_values) > 0 and isinstance(field_val, (int, float)):
                    threshold = rule_values[0]
                    triggered = (field_val < threshold)
                    if triggered:
                        evidence_str = f"Observed {target_field} = {field_val}, below minimum threshold of {threshold}."

            if triggered:
                # Map likelihood and impact level for matrix
                sev = rule.get("severity", "Medium")
                if sev == "High":
                    likelihood = "High" if target_field in ["encryption_algorithm", "integrity_algorithm", "replay_protection_enabled"] else "Medium"
                    impact_level = "High"
                elif sev == "Medium":
                    likelihood = "Medium"
                    impact_level = "Medium"
                else:
                    likelihood = "Low"
                    impact_level = "Low"

                finding = Finding(
                    id=f"FND-{finding_counter:03d}",
                    rule_id=rule_id,
                    title=rule.get("title", "Configuration Finding"),
                    severity=sev,
                    category=rule.get("category", "Configuration"),
                    evidence=evidence_str,
                    impact=rule.get("impact", "Potential security deviation."),
                    recommendation=rule.get("recommendation", "Review profile configuration."),
                    reference=rule.get("reference", "NIST SP 800-77 Rev. 1"),
                    confidence=1.0,
                    status="Action Required" if sev in ["High", "Medium"] else "Acceptable Risk",
                    likelihood=likelihood,
                    impact_level=impact_level
                )
                findings.append(finding)
                finding_counter += 1

        return findings
