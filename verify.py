"""
Verification script for SOC Platform.
Performs unit tests on utility validators, exceptions, Threat Intel mocks, and UEBA risk scores.
"""
import os
import sys
from utils.logger import logger
from utils.validators import is_valid_ip, is_valid_domain, is_valid_hash
from utils.error_handler import register_alert_callback, handle_exception
from modules.virustotal.virustotal import VirusTotalClient
from modules.threat_intel.threat_intel_aggregator import threat_intel_aggregator
from modules.ueba.ueba_baseline import ueba_engine
from modules.file_monitor.file_hashing import get_all_hashes
from modules.ai.gemini_client import gemini_client
from modules.ai.credential_scanner import scan_file_for_secrets
from modules.ai.network_analyzer import analyze_connection_security

def run_tests():
    print("\n" + "="*50)
    print("      [TEST] RUNNING AUTOMATED SOC PLATFORM VERIFICATION")
    print("="*50 + "\n")
    
    passed_tests = 0
    total_tests = 0

    # Test 1: Input Validators
    print("[*] Test 1: Input Validators...")
    total_tests += 1
    if is_valid_ip("192.168.1.1") and not is_valid_ip("999.999.999.999"):
        if is_valid_domain("google.com") and not is_valid_domain("invalid..domain"):
            if is_valid_hash("44d88612fea8a8f36de82e1278abb02f"):
                print("    [+] Passed input validation checks.")
                passed_tests += 1
            else:
                print("    [-] Failed hash check validation.")
        else:
            print("    [-] Failed domain check validation.")
    else:
        print("    [-] Failed IP check validation.")

    # Test 2: Error Handler Event Generation
    print("[*] Test 2: Central Exception Management...")
    total_tests += 1
    alert_triggered = False
    def mock_alert_callback(event):
        nonlocal alert_triggered
        if event.get("event_type") == "system_alert" and event.get("module") == "test_module":
            alert_triggered = True

    register_alert_callback(mock_alert_callback)
    try:
        raise ValueError("Simulated Platform Exception")
    except ValueError as e:
        handle_exception(e, "test_module", "Testing central logging pipeline")
        
    if alert_triggered:
        print("    [+] Passed exception tracking event loop.")
        passed_tests += 1
    else:
        print("    [-] Failed exception event integration.")

    # Test 3: Threat Intelligence Mock Outputs
    print("[*] Test 3: Threat Intelligence Aggregator (Mock Mode)...")
    total_tests += 1
    # Check regular IP vs malicious IP ends with .66
    clean_ip_report = threat_intel_aggregator.lookup("8.8.8.8", "ip")
    malicious_ip_report = threat_intel_aggregator.lookup("192.168.1.66", "ip")
    
    if not clean_ip_report["is_malicious"] and malicious_ip_report["is_malicious"]:
        if malicious_ip_report["reputation_score"] > 50:
            print(f"    [+] Passed parallel query aggregator checks. Malicious score: {malicious_ip_report['reputation_score']}")
            passed_tests += 1
        else:
            print(f"    [-] Composite risk calculation resolved low score: {malicious_ip_report['reputation_score']}")
    else:
        print("    [-] Threat Intel failed to discriminate clean vs malicious profiles.")

    # Test 4: UEBA Risk Score Calculations
    print("[*] Test 4: UEBA Behavioral baseline & risk score calculations...")
    total_tests += 1
    
    # Reset tester profile if it exists to ensure a clean baseline
    if "tester" in ueba_engine.profiles:
        del ueba_engine.profiles["tester"]
        ueba_engine.save_profiles()
        
    # Base profile initialization
    profile = ueba_engine.get_or_create_profile("tester")
    initial_score = profile["risk_score"]
    
    # Process Creation event for a normal file
    normal_process_event = {
        "event_id": "EVT-TEST-001",
        "event_type": "process_created",
        "module": "windows_process",
        "data": {
            "name": "chrome.exe",
            "username": "tester"
        }
    }
    ueba_engine.process_event(normal_process_event)
    score_after_normal = ueba_engine.get_or_create_profile("tester")["risk_score"]
    
    # Process Creation event for an unusual file
    malicious_process_event = {
        "event_id": "EVT-TEST-002",
        "event_type": "process_created",
        "module": "windows_process",
        "data": {
            "name": "unusual_shell.exe",
            "username": "tester"
        }
    }
    deviations = ueba_engine.process_event(malicious_process_event)
    profile_after_alert = ueba_engine.get_or_create_profile("tester")
    score_after_alert = profile_after_alert["risk_score"]
    
    if score_after_normal == 0.0 and score_after_alert > 0.0 and len(deviations) > 0:
        print(f"    [+] Passed UEBA profile baseline checks. Risk score spiked to: {score_after_alert}")
        passed_tests += 1
    else:
        print(f"    [-] UEBA profile failed to increment risk score. Final: {score_after_alert}")

    # Test 5: Gemini Client Initialization
    print("[*] Test 5: Gemini client initialization...")
    total_tests += 1
    if gemini_client is not None:
        print(f"    [+] Gemini client loaded successfully. Mock mode: {gemini_client.is_mock}")
        passed_tests += 1
    else:
        print("    [-] Gemini client failed to initialize.")

    # Test 6: AI Credential Scanner
    print("[*] Test 6: AI Credential & Password scanner...")
    total_tests += 1
    temp_secret_file = "temp_verification_secret.txt"
    try:
        with open(temp_secret_file, "w", encoding="utf-8") as f:
            f.write("database_password = \"supersecret_mock_password_123\"\n")
            
        alert = scan_file_for_secrets(temp_secret_file)
        if alert and alert.get("event_type") == "secret_leak_detected":
            print(f"    [+] Passed password scan. Detected type: {alert['data']['secret_type']}, Explanation: {alert['data']['explanation']}")
            passed_tests += 1
        else:
            print("    [-] Credential scanner failed to flag credentials in simulated file.")
    finally:
        if os.path.exists(temp_secret_file):
            os.remove(temp_secret_file)

    # Test 7: AI Firewall & Network Connection Analyzer
    print("[*] Test 7: AI Firewall & Network Connection Analyzer...")
    total_tests += 1
    mock_connection_event = {
        "event_id": "EVT-MOCK-CONN-01",
        "event_type": "network_connection",
        "module": "network_connection",
        "data": {
            "process_name": "malicious_script.exe",
            "dst_ip": "192.168.1.66",
            "dst_port": 6667,
            "resolved_domain": "attacker-c2.com",
            "threat_reputation": {
                "is_malicious": True,
                "reputation_score": 85.0
            }
        }
    }
    
    ai_alert = analyze_connection_security(mock_connection_event)
    if ai_alert and ai_alert.get("event_type") == "ai_firewall_alert":
        firewall_rule = ai_alert["data"].get("suggested_firewall_rule", "")
        if "New-NetFirewallRule" in firewall_rule:
            print(f"    [+] Passed Network/Firewall AI scanner. Generated block rule: {firewall_rule}")
            passed_tests += 1
        else:
            print(f"    [-] Failed to generate correct firewall rule. Got: {firewall_rule}")
    else:
        print("    [-] Network analyzer failed to flag high-risk connection event.")

    print("\n" + "="*50)
    print(f"      VERIFICATION RESULTS: {passed_tests}/{total_tests} PASSED")
    print("="*50 + "\n")
    
    if passed_tests == total_tests:
        print("All features verified successfully! The platform is production-ready.")
        return 0
    else:
        print("One or more tests failed. Inspect details.")
        return 1

if __name__ == "__main__":
    sys.exit(run_tests())
