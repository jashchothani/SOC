"""
================================================================================
SOC PLATFORM ORCHESTRATION ENGINE
================================================================================
This is the core controller of the SOC Automation Platform. It initializes
working directories, spawns background monitoring agent threads (Windows metrics,
process logs, DNS queries, network sockets, SCM services, file changes),
interfaces with threat intelligence caches, and routes incoming log entries into
the UEBA behavioral profiling engine.

CRITICAL PROCESS LIFECYCLE:
1. ThreadPoolExecutor configuration for asynchronous threat enrichment workers.
2. Background thread scheduling for continuous system inspections.
3. Central event ingestion logic mapping monitoring flows to analytics.
================================================================================
"""
import os
import time
import threading
import concurrent.futures
from typing import Dict
from config.settings import settings
from config.constants import (
    DIR_EVENTS, DIR_LOGS, DIR_BASELINES, DIR_REPORTS,
    INTERVAL_5_SEC, INTERVAL_30_SEC, INTERVAL_1_MIN
)
from utils.logger import logger
from utils.timestamp import get_utc_timestamp
from utils.json_manager import append_to_json_array
from utils.error_handler import register_alert_callback, handle_exception

# Monitor Modules
from modules.windows.system_usage import collect_system_usage
from modules.windows.process_monitor import process_monitor
from modules.windows.services import collect_services
from modules.network_monitor.dns_monitor import dns_monitor
from modules.network_monitor.connection_monitor import connection_monitor
from modules.file_monitor.file_events import FileMonitor
from modules.file_monitor.integrity_monitor import IntegrityMonitor

# Intelligence & Analytics Modules
from modules.threat_intel.threat_intel_aggregator import threat_intel_aggregator
from modules.ueba.ueba_baseline import ueba_engine

# Shared Thread-Safe DNS Map (resolved IP -> Domain)
dns_resolution_map: Dict[str, str] = {}
dns_map_lock = threading.Lock()

# Thread synchronization
stop_event = threading.Event()
thread_pool: concurrent.futures.ThreadPoolExecutor = None

def ingest_event(event: dict):
    """Pipeline entry point for all parsed events in the system."""
    if not event:
        return
        
    try:
        # 1. Log event details to disk
        events_file = os.path.join(DIR_EVENTS, "events.json")
        append_to_json_array(events_file, event)
        
        # 2. Feed event to UEBA Engine to evaluate behaviors
        anomaly_events = ueba_engine.process_event(event)
        for anomaly in anomaly_events:
            ingest_event(anomaly)
            
    except Exception as e:
        handle_exception(e, "ingestion_pipeline", "Failed to ingest event into central registry")

def process_threat_enrichment(connection_event: dict):
    """Enriches public connection events with Threat Intelligence data in a worker thread."""
    try:
        dst_ip = connection_event["data"]["dst_ip"]
        logger.info(f"Triggering threat intelligence evaluation for target IP: {dst_ip}")
        
        # Query aggregator (utilizes internal caching and parallel API queries)
        intel_report = threat_intel_aggregator.lookup(dst_ip, "ip")
        
        # Log intelligence report separately
        intel_file = os.path.join(DIR_EVENTS, "threat_intelligence.json")
        append_to_json_array(intel_file, intel_report)
        
        # Update connection event context with threat data
        connection_event["data"]["threat_reputation"] = {
            "is_malicious": intel_report.get("is_malicious", False),
            "reputation_score": intel_report.get("reputation_score", 0)
        }
        
        # Re-evaluate connection event inside UEBA Engine with newly decorated reputation context
        anomaly_events = ueba_engine.process_event(connection_event)
        for anomaly in anomaly_events:
            ingest_event(anomaly)
            
        # Trigger AI Network & Firewall Analyzer to evaluate this connection
        try:
            from modules.ai.network_analyzer import analyze_connection_security
            ai_alert = analyze_connection_security(connection_event)
            if ai_alert:
                ai_file = os.path.join(DIR_EVENTS, "ai_alerts.json")
                append_to_json_array(ai_file, ai_alert)
                ingest_event(ai_alert)
        except Exception as ai_err:
            logger.error(f"Failed to run background AI network connection analysis: {ai_err}")
            
    except Exception as e:
        handle_exception(e, "threat_enrichment", f"Failed threat intelligence lookup for connection")

# Background monitoring runners
def run_system_usage_monitor():
    logger.info("Background System Usage thread spawned.")
    while not stop_event.wait(settings.system_usage_interval):
        try:
            usage_event = collect_system_usage()
            if usage_event:
                ingest_event(usage_event)
        except Exception as e:
            handle_exception(e, "system_usage_runner", "Usage collection loop failure")

def run_process_monitor():
    logger.info("Background Process Monitor thread spawned.")
    while not stop_event.wait(settings.process_polling_interval):
        try:
            birth_death_events = process_monitor.scan()
            for event in birth_death_events:
                ingest_event(event)
        except Exception as e:
            handle_exception(e, "process_monitor_runner", "Process monitoring loop failure")

def run_dns_monitor():
    logger.info("Background DNS Monitor thread spawned.")
    while not stop_event.wait(settings.dns_polling_interval):
        try:
            dns_events = dns_monitor.scan()
            for event in dns_events:
                # Update DNS map for correlation lookups
                with dns_map_lock:
                    dns_resolution_map[event["resolved_ip"]] = event["query"]
                ingest_event(event)
        except Exception as e:
            handle_exception(e, "dns_monitor_runner", "DNS monitoring loop failure")

def run_connection_monitor():
    logger.info("Background Connection Monitor thread spawned.")
    while not stop_event.wait(settings.connections_polling_interval):
        try:
            with dns_map_lock:
                dns_snapshot = dns_resolution_map.copy()
                
            new_conns = connection_monitor.scan(dns_snapshot)
            for event in new_conns:
                # Enqueue threat intelligence lookup in the background thread pool if not stopping
                if not stop_event.is_set():
                    try:
                        thread_pool.submit(process_threat_enrichment, event)
                    except RuntimeError as e:
                        if "shutdown" in str(e):
                            logger.warning("Could not submit threat enrichment task: thread pool is shutting down.")
                        else:
                            raise
                # Ingest raw event first
                ingest_event(event)
        except Exception as e:
            handle_exception(e, "connection_monitor_runner", "Connection monitoring loop failure")

def run_services_monitor():
    logger.info("Background Services Monitor thread spawned.")
    while not stop_event.wait(settings.service_polling_interval):
        try:
            svc_events = collect_services()
            for event in svc_events:
                ingest_event(event)
        except Exception as e:
            handle_exception(e, "services_monitor_runner", "Services checkup loop failure")

def run_integrity_check(integrity_monitor: IntegrityMonitor, target_dir: str):
    logger.info("Performing scheduled file integrity monitoring verification...")
    alerts = integrity_monitor.check_integrity(target_dir)
    for alert in alerts:
        ingest_event(alert)

def main():
    global thread_pool
    print("\n" + "="*60)
    print("      [+] ENTERPRISE SOC PLATFORM & THREAT INTEL ORCHESTRATOR")
    print("="*60 + "\n")
    
    # 1. Initialize Directories
    for folder in [DIR_EVENTS, DIR_LOGS, DIR_BASELINES, DIR_REPORTS]:
        os.makedirs(folder, exist_ok=True)
        
    # 2. Register exception handler alerts callback
    register_alert_callback(ingest_event)
    
    logger.info("Orchestrator initialized. Loading modules...")
    
    # Trigger UEBA engine console startup dashboard
    ueba_engine.initialize_startup()
    
    if settings.mock_mode:
        logger.warning("[MOCK MODE ACTIVE] Simulated APIs and metrics enabled.")
    else:
        logger.info("Production API mode active. Loaded client keys.")

    # 3. Spawn Thread Pool for task threads
    thread_pool = concurrent.futures.ThreadPoolExecutor(
        max_workers=settings.max_worker_threads,
        thread_name_prefix="SOCWorker"
    )

    # 4. Initialize File monitors
    file_monitor = FileMonitor(
        monitor_path=settings.file_monitor_path,
        event_callback=ingest_event
    )
    
    integrity_monitor = IntegrityMonitor()
    # Establish baseline if not present
    integrity_monitor.check_integrity(settings.file_monitor_path)
    
    # Start File Watchdog
    file_monitor.start()

    # 5. Launch Background threads
    monitor_threads = [
        threading.Thread(target=run_system_usage_monitor, name="SysUsageMon", daemon=True),
        threading.Thread(target=run_process_monitor, name="ProcMon", daemon=True),
        threading.Thread(target=run_dns_monitor, name="DNSMon", daemon=True),
        threading.Thread(target=run_connection_monitor, name="ConnMon", daemon=True),
        threading.Thread(target=run_services_monitor, name="SvcMon", daemon=True)
    ]

    for t in monitor_threads:
        t.start()

    logger.info("All background monitoring tasks launched successfully.")
    
    # 6. Schedule Periodic Integrity Checks (every 60 seconds for demonstration)
    last_integrity_time = time.time()
    
    try:
        while True:
            # Main orchestrator loop keeping engine alive and scheduling integrity checks
            time.sleep(1)
            
            # Check file integrity baseline every 60 seconds
            if time.time() - last_integrity_time >= 60.0:
                if not stop_event.is_set():
                    try:
                        thread_pool.submit(run_integrity_check, integrity_monitor, settings.file_monitor_path)
                    except RuntimeError as e:
                        if "shutdown" in str(e):
                            logger.warning("Could not submit integrity check task: thread pool is shutting down.")
                        else:
                            raise
                last_integrity_time = time.time()
                
    except KeyboardInterrupt:
        print("\n" + "="*60)
        print("  [!] SHUTDOWN SIGNAL RECEIVED. TERMINATING BG AGENTS CLEANLY...")
        print("="*60 + "\n")
        logger.info("Shutdown signal caught. Stopping components...")
        
        # Signal stop to daemon loops
        stop_event.set()
        
        # Stop Watchdog
        file_monitor.stop()
        
        # Shutdown thread pool workers
        thread_pool.shutdown(wait=True)
        
        logger.info("All components stopped. Exiting SOC Platform.")
        print("SOC platform exited successfully.")

if __name__ == "__main__":
    main()
