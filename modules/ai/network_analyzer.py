"""
AI Firewall and Outbound Network Connection Security Analyzer.
Evaluates threat level of connection events and suggests Defender Firewall blocking rules.
"""
import uuid
from typing import Optional
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from modules.ai.gemini_client import gemini_client
from config.constants import SEVERITY_WARNING, SEVERITY_CRITICAL, SEVERITY_INFO

def analyze_connection_security(event: dict) -> Optional[dict]:
    """
    Analyzes an outbound network event and queries Gemini for threat profiling and rule generation.
    Returns a standard SOC alert event if a threat is found, else None.
    """
    try:
        data = event.get("data", {})
        process_name = data.get("process_name", "Unknown")
        dst_ip = data.get("dst_ip", "")
        dst_port = data.get("dst_port", 0)
        domain = data.get("resolved_domain", "")
        
        # Get score from previous threat intelligence lookup or default to 0
        threat_score = data.get("threat_reputation", {}).get("reputation_score", 0.0)
        
        # Call Gemini AI
        result = gemini_client.analyze_connection(
            process_name=process_name,
            dst_ip=dst_ip,
            dst_port=dst_port,
            domain=domain,
            threat_score=threat_score
        )
        
        if result and result.get("is_threat"):
            risk = result.get("risk_level", "WARNING")
            severity = SEVERITY_CRITICAL if risk == "CRITICAL" else SEVERITY_WARNING
            
            alert = {
                "event_id": f"EVT-{uuid.uuid4()}",
                "timestamp": get_utc_timestamp(),
                "module": "ai_network_analyzer",
                "event_type": "ai_firewall_alert",
                "severity": severity,
                "status": "detected",
                "data": {
                    "triggering_event_id": event.get("event_id"),
                    "process_name": process_name,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "resolved_domain": domain,
                    "threat_category": result.get("threat_category", "Suspicious Process Activity"),
                    "risk_level": risk,
                    "explanation": result.get("explanation", "Suspicious network connection detected by AI."),
                    "suggested_firewall_rule": result.get("suggested_firewall_rule", "")
                }
            }
            logger.warning(
                f"AI Network Threat Detected [{result.get('threat_category')}]: "
                f"{process_name} -> {dst_ip}:{dst_port} - Risk: {risk}"
            )
            return alert
            
    except Exception as e:
        logger.error(f"Failed to analyze network connection with AI: {e}")
        
    return None
