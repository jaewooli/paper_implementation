import logging
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from pydantic import BaseModel, Field
import uuid
import datetime

# ==========================================
# 0. Logging Configuration
# ==========================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("AdaptiveSOC")

# ==========================================
# 1. Domain Enums and Data Models
# ==========================================
class Verdict(str, Enum):
    FALSE_POSITIVE = "False Positive"
    BENIGN = "Benign"
    MALICIOUS = "Malicious"
    INCONCLUSIVE = "Inconclusive"

class NormalizedIncident(BaseModel):
    incident_id: str
    raw_source: str
    timestamp: str
    target_host: str
    user_identity: str
    indicators: List[str]
    raw_payload: Dict[str, Any]

class GroundedContext(BaseModel):
    incident: NormalizedIncident
    asset_criticality: str  
    user_role: str          
    world_state: Dict[str, Any]

class InvestigationTrace(BaseModel):
    steps_executed: List[str]
    evidence_collected: List[Dict[str, Any]]
    proposed_verdict: Verdict
    reasoning_summary: str

# ==========================================
# 2. External Interfaces & Enhanced Mocking Layer
# ==========================================
class SecuritySiemClientInterface:
    def fetch_raw_alert(self, alert_id: str) -> Dict[str, Any]: raise NotImplementedError
    def execute_log_search(self, query: str) -> List[Dict[str, Any]]: raise NotImplementedError

class InfrastructureContextInterface:
    def fetch_asset_info(self, host_id: str) -> Dict[str, Any]: raise NotImplementedError
    def fetch_identity_info(self, user_id: str) -> Dict[str, Any]: raise NotImplementedError

class MockSiemClient(SecuritySiemClientInterface):
    def __init__(self):
        self.mock_alerts_db = {
            "alert_001": {
                "id": "alert_001",
                "vendor": "AzureSentinel",
                "timeGenerated": datetime.datetime.now().isoformat(),
                "entities": {"host": "server-prod-01", "account": "jsmith"},
                "description": "High CPU usage and unusual process executed."
            }
        }
        self.mock_logs_db = {
            "server-test-02": [{"EventID": "4624", "Message": "Successful Logon"}]
            # server-prod-01 has no logs deliberately to test the Null-Evidence Axiom
        }

    def fetch_raw_alert(self, alert_id: str) -> Dict[str, Any]:
        logger.info(f"Fetching raw alert from SIEM for ID: {alert_id}")
        if alert_id in self.mock_alerts_db:
            return self.mock_alerts_db[alert_id]
        
        # [Mocking Fallback] 실제 값이 없을 때 동적으로 더미 데이터 생성
        logger.warning(f"Alert ID '{alert_id}' not found. Generating mock fallback alert.")
        return {
            "id": alert_id,
            "vendor": "AzureSentinel",
            "timeGenerated": datetime.datetime.now().isoformat(),
            "entities": {"host": f"unknown-host-{str(uuid.uuid4())[:4]}", "account": "unknown-user"},
            "description": "Mocked fallback alert due to missing data."
        }
    
    def execute_log_search(self, query: str) -> List[Dict[str, Any]]:
        logger.debug(f"Executing SIEM query: {query}")
        for host, logs in self.mock_logs_db.items():
            if host in query:
                logger.info(f"Found {len(logs)} logs for query: {query}")
                return logs
        logger.info(f"No logs found for query: {query}")
        return []

class MockInfrastructureClient(InfrastructureContextInterface):
    def __init__(self):
        self.mock_cmdb_db = {
            "server-prod-01": {"criticality": "Production", "owner": "CoreBackend"},
        }
        self.mock_directory_db = {
            "jsmith": {"role": "System Administrator", "department": "IT Operations"},
        }

    def fetch_asset_info(self, host_id: str) -> Dict[str, Any]:
        if host_id in self.mock_cmdb_db:
            return self.mock_cmdb_db[host_id]
        
        # [Mocking Fallback]
        logger.warning(f"Host '{host_id}' not in CMDB. Returning default 'Unknown' state.")
        return {"criticality": "Unknown", "owner": "Unassigned"}
        
    def fetch_identity_info(self, user_id: str) -> Dict[str, Any]:
        if user_id in self.mock_directory_db:
            return self.mock_directory_db[user_id]
        
        # [Mocking Fallback]
        logger.warning(f"User '{user_id}' not in Directory. Returning default 'Guest' state.")
        return {"role": "Guest/Unknown", "department": "None"}

# ==========================================
# 3. Semantic Normalization Layer
# ==========================================
class SemanticNormalizationLayer:
    def normalize_azure_sentinel(self, json_payload: Dict[str, Any]) -> NormalizedIncident:
        logger.debug("Normalizing Azure Sentinel payload...")
        entities = json_payload.get("entities", {})
        return NormalizedIncident(
            incident_id=json_payload.get("id", str(uuid.uuid4())),
            raw_source="AzureSentinel",
            timestamp=json_payload.get("timeGenerated", datetime.datetime.now().isoformat()),
            target_host=entities.get("host", "unknown_host"),
            user_identity=entities.get("account", "unknown_user"),
            indicators=[json_payload.get("description", "No description provided")],
            raw_payload=json_payload
        )

# ==========================================
# 4. Dynamic State Injection Layer
# ==========================================
class DynamicStateInjection:
    def __init__(self, infra_client: InfrastructureContextInterface):
        self.infra_client = infra_client

    def enrich(self, incident: NormalizedIncident) -> GroundedContext:
        logger.info(f"Enriching context for Host: {incident.target_host}, User: {incident.user_identity}")
        asset_info = self.infra_client.fetch_asset_info(incident.target_host)
        identity_info = self.infra_client.fetch_identity_info(incident.user_identity)
        
        return GroundedContext(
            incident=incident,
            asset_criticality=asset_info.get("criticality", "Unknown"),
            user_role=identity_info.get("role", "Unknown"),
            world_state={"asset_details": asset_info, "identity_details": identity_info}
        )

# ==========================================
# 5. Cognitive Stack: Solver-Critic Loop
# ==========================================
class SolverAgent:
    def __init__(self, siem_client: SecuritySiemClientInterface):
        self.siem_client = siem_client

    def investigate(self, context: GroundedContext, feedback_history: List[str]) -> InvestigationTrace:
        target_host = context.incident.target_host
        user_role = context.user_role
        
        logger.info(f"[Solver] Starting investigation for {target_host}. Feedback history length: {len(feedback_history)}")
        
        query = f"search index=os host={target_host}"
        steps = [f"Executed query: {query}"]
        evidence = self.siem_client.execute_log_search(query)
        
        # ReAct Pivot & Hallucination Simulation
        if feedback_history:
            logger.info("[Solver] Adjusting hypothesis based on Critic's feedback.")
            steps.append(f"Adjusted based on feedback: {feedback_history[-1]}")
            proposed_verdict = Verdict.INCONCLUSIVE
            summary = "Cannot confirm benign intent due to lack of logs. Routing to human."
        else:
            if not evidence and "Administrator" in user_role:
                logger.debug("[Solver] Simulating hallucination: Assuming benign despite empty logs due to Admin role.")
                proposed_verdict = Verdict.BENIGN
                summary = f"Assumed benign maintenance as user is {user_role}, despite missing logs."
            elif evidence:
                proposed_verdict = Verdict.BENIGN
                summary = "Found valid logs proving authorized activity."
            else:
                proposed_verdict = Verdict.INCONCLUSIVE
                summary = "No evidence found, unable to determine intent."

        return InvestigationTrace(
            steps_executed=steps,
            evidence_collected=evidence,
            proposed_verdict=proposed_verdict,
            reasoning_summary=summary
        )

class CriticAgent:
    def verify(self, trace: InvestigationTrace) -> Tuple[bool, str]:
        logger.info(f"[Critic] Validating proposed verdict: {trace.proposed_verdict}")
        requires_evidence = [Verdict.BENIGN, Verdict.FALSE_POSITIVE]
        
        # Null-Evidence Axiom Enforcement
        if trace.proposed_verdict in requires_evidence and len(trace.evidence_collected) == 0:
            msg = "Violation: Empty logs cannot prove benign intent (Null-Evidence Axiom)."
            logger.warning(f"[Critic] REJECTED. {msg}")
            return False, msg
            
        logger.info("[Critic] APPROVED. Verdict is supported by evidence.")
        return True, "Approved: Verdict supported by evidence."

# ==========================================
# 6. Core Orchestrator Layout
# ==========================================
class AdaptiveSOCOrchestrator:
    def __init__(self, normalizer: SemanticNormalizationLayer, enricher: DynamicStateInjection, solver: SolverAgent, critic: CriticAgent):
        self.normalizer = normalizer
        self.enricher = enricher
        self.solver = solver
        self.critic = critic
        self.max_semantic_retries = 5

    def process_raw_alert(self, raw_alert_payload: Dict[str, Any], vendor_type: str) -> Tuple[Verdict, InvestigationTrace]:
        logger.info("=== STARTING NEW INCIDENT PIPELINE ===")
        incident = self.normalizer.normalize_azure_sentinel(raw_alert_payload)
        context = self.enricher.enrich(incident)
        
        feedback_history = []
        for attempt in range(1, self.max_semantic_retries + 1):
            logger.info(f"--- Semantic Cycle {attempt}/{self.max_semantic_retries} ---")
            trace = self.solver.investigate(context, feedback_history)
            is_approved, critique_msg = self.critic.verify(trace)
            
            if is_approved:
                logger.info(f"=== PIPELINE COMPLETE: {trace.proposed_verdict} ===")
                return trace.proposed_verdict, trace
                
            feedback_history.append(critique_msg)
            
        logger.error("Exceeded max semantic retries. Defaulting to Inconclusive.")
        trace.proposed_verdict = Verdict.INCONCLUSIVE
        trace.reasoning_summary = "Exceeded max semantic retries. Defaulting to Inconclusive."
        return Verdict.INCONCLUSIVE, trace

# ==========================================
# 7. Execution Sandbox (Test Runner)
# ==========================================
if __name__ == "__main__":
    siem = MockSiemClient()
    infra = MockInfrastructureClient()
    
    orchestrator = AdaptiveSOCOrchestrator(
        normalizer=SemanticNormalizationLayer(),
        enricher=DynamicStateInjection(infra),
        solver=SolverAgent(siem),
        critic=CriticAgent()
    )
    
    # 1. Normal Test (Existing alert simulating Hallucination -> Rejection -> Fix)
    logger.info("\n>>> RUNNING TEST CASE 1: Registered Alert (alert_001) <<<")
    raw_alert_1 = siem.fetch_raw_alert("alert_001")
    orchestrator.process_raw_alert(raw_alert_1, "AzureSentinel")
    
    # 2. Fallback Mock Test (Unregistered alert generating dynamic mock data)
    logger.info("\n>>> RUNNING TEST CASE 2: Unregistered Alert (alert_999) <<<")
    raw_alert_2 = siem.fetch_raw_alert("alert_999")
    orchestrator.process_raw_alert(raw_alert_2, "AzureSentinel")