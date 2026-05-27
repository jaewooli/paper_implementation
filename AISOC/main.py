import json
import os
import glob
import logging
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from pydantic import BaseModel
import uuid
import datetime
import re

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # openai 라이브러리가 없을 경우를 대비한 예외 처리

# ==========================================
# 0. Logging Configuration
# ==========================================
logging.basicConfig(
    level=logging.WARNING,  # 전체 시나리오 순회 시 화면 복잡도를 낮추기 위해 WARNING 유지
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
# 2. External Interfaces & Production-Ready Mocking Layer
# ==========================================
class SecuritySiemClientInterface:
    def fetch_raw_alert(self, alert_id: str) -> Dict[str, Any]: raise NotImplementedError
    def execute_log_search(self, query: str) -> List[Dict[str, Any]]: raise NotImplementedError

class InfrastructureContextInterface:
    def fetch_asset_info(self, host_id: str) -> Dict[str, Any]: raise NotImplementedError
    def fetch_identity_info(self, user_id: str) -> Dict[str, Any]: raise NotImplementedError

class RealDatasetSiemClient(SecuritySiemClientInterface):
    def __init__(self):
        self.mock_alerts_db: Dict[str, Dict[str, Any]] = {}
        self.mock_logs_db: Dict[str, List[Dict[str, Any]]] = {}

    def clear_database(self):
        self.mock_alerts_db.clear()
        self.mock_logs_db.clear()

    def fetch_raw_alert(self, alert_id: str) -> Dict[str, Any]:
        if alert_id in self.mock_alerts_db:
            return self.mock_alerts_db[alert_id]
        return {
            "id": alert_id,
            "vendor": "DatasetFallback",
            "timeGenerated": datetime.datetime.now().isoformat(),
            "entities": {"host": "unknown-host", "account": "unknown-user"},
            "description": "Fallback Dynamic Alert"
        }
    
    def execute_log_search(self, query: str) -> List[Dict[str, Any]]:
        for host, logs in self.mock_logs_db.items():
            if host.lower() in query.lower():
                return logs
        return []

class DynamicInfrastructureClient(InfrastructureContextInterface):
    def __init__(self):
        self.critical_keywords = ["prod", "dc", "sql", "db", "server"]

    def fetch_asset_info(self, host_id: str) -> Dict[str, Any]:
        host_lower = host_id.lower()
        if any(k in host_lower for k in self.critical_keywords):
            return {"criticality": "Production", "owner": "CoreInfrastructure"}
        if "test" in host_lower or "dev" in host_lower:
            return {"criticality": "Development", "owner": "DevTeam"}
        return {"criticality": "Workstation", "owner": "GeneralUser"}
        
    def fetch_identity_info(self, user_id: str) -> Dict[str, Any]:
        user_lower = user_id.lower()
        if "admin" in user_lower or "system" in user_lower or "root" in user_lower:
            return {"role": "System Administrator", "department": "IT Operations"}
        return {"role": "Standard User", "department": "Corporate"}

# ==========================================
# 3. Semantic Normalization Layer
# ==========================================
class SemanticNormalizationLayer:
    def normalize_splunk_dataset(self, json_payload: Dict[str, Any]) -> NormalizedIncident:
        target_host = json_payload.get("dest", json_payload.get("host", json_payload.get("dest_nt_host", "unknown_host")))
        user_identity = json_payload.get("user", json_payload.get("src_user", json_payload.get("user_name", "unknown_user")))
        
        return NormalizedIncident(
            incident_id=json_payload.get("event_id", str(uuid.uuid4())),
            raw_source="SplunkAttackData",
            timestamp=json_payload.get("_time", datetime.datetime.now().isoformat()),
            target_host=str(target_host),
            user_identity=str(user_identity),
            indicators=[json_payload.get("signature", json_payload.get("process_name", "Suspicious Activity Detected"))],
            raw_payload=json_payload
        )

# ==========================================
# 4. Dynamic State Injection Layer
# ==========================================
class DynamicStateInjection:
    def __init__(self, infra_client: InfrastructureContextInterface):
        self.infra_client = infra_client

    def enrich(self, incident: NormalizedIncident) -> GroundedContext:
        asset_info = self.infra_client.fetch_asset_info(incident.target_host)
        identity_info = self.infra_client.fetch_identity_info(incident.user_identity)
        
        return GroundedContext(
            incident=incident,
            asset_criticality=asset_info.get("criticality", "Unknown"),
            user_role=identity_info.get("role", "Unknown"),
            world_state={"asset_details": asset_info, "identity_details": identity_info}
        )

# ==========================================
# 5. Cognitive Stack: AI Reasoning Engines
# ==========================================
DEFAULT_HEURISTIC_PLAYBOOK = """
## Investigation Node: Identity Validation
- Check if the user is an active employee.
- Check if the user has administrative privileges required for the process.

## Investigation Node: Device Telemetry
- Query SIEM for related process execution logs.
- Identify if the binary path matches known system directories.

## Reasoning Rules
- Formulate a hypothesis based on Identity and Device nodes.
- Do NOT guess. Rely solely on explicit evidence logs.
"""

SOLVER_SYSTEM_PROMPT = """
You are an autonomous Tier 1 SOC Analyst (Solver Agent) using the ReAct (Reason, Act, Observe) framework.
Your task is to investigate the given normalized security incident, execute necessary search queries, and propose a verdict.
"""

class SimulatedLLM:
    """[개발용] API 호출 없이 LLM의 추론 동작을 로컬에서 모사하는 엔진"""
    def generate_solver_trace(self, prompt: str, user_role: str, siem_search_callback) -> Dict[str, Any]:
        
        # 프롬프트에서 타겟 호스트명을 추출하여 실제 쿼리에 매핑
        host_match = re.search(r"Target Host:\s*([^\n]+)", prompt)
        target_host = host_match.group(1).strip() if host_match else "unknown_host"
        
        # 하드코딩 대신 동적 호스트 쿼리 실행
        search_query = f"search host={target_host}"
        evidence = siem_search_callback(search_query)
        
        if not evidence and "Administrator" in user_role:
            return {
                "thought": "No logs found, but the user is an Administrator.",
                "verdict": Verdict.BENIGN, 
                "summary": "Assumed benign maintenance as user is Administrator, despite missing logs.",
                "evidence_collected": evidence,
                "steps_executed": [f"Action: {search_query} -> 빈 결과지만 유지보수로 가정"]
            }
        elif evidence:
            return {
                "thought": "Logs found matching the process execution.",
                "verdict": Verdict.MALICIOUS,
                "summary": "Confirmed malicious activity based on positive log evidence.",
                "evidence_collected": evidence,
                "steps_executed": [f"Action: {search_query} -> 로그 분석 결과 악성 행위 확인"]
            }
        else:
            return {
                "thought": "No logs found, and user is standard.",
                "verdict": Verdict.INCONCLUSIVE,
                "summary": "Insufficient telemetry to determine intent.",
                "evidence_collected": evidence,
                "steps_executed": [f"Action: {search_query} -> 증거 확보 실패"]
            }
            
class OpenAILiveEngine:
    """[실험용] OpenAI Function Calling을 활용한 진짜 ReAct 추론 엔진"""
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        if OpenAI is None:
            raise ImportError("openai 패키지가 설치되지 않았습니다. 'pip install openai'를 실행하세요.")
        self.client = OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))
        self.model = model

    def generate_solver_trace(self, prompt: str, user_role: str, siem_search_callback) -> Dict[str, Any]:
        tools = [{
            "type": "function",
            "function": {
                "name": "execute_siem_query",
                "description": "SIEM을 검색하여 특정 호스트나 계정의 위협 증거 로그를 수집합니다.",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string", "description": "SIEM 검색 쿼리 (예: 'target_host_name')"}},
                    "required": ["query"]
                }
            }
        }]

        messages = [
            {"role": "system", "content": SOLVER_SYSTEM_PROMPT},
            {"role": "user", "content": f"{prompt}\nUser Role: {user_role}"}
        ]

        steps_executed = []
        evidence_collected = []

        response = self.client.chat.completions.create(model=self.model, messages=messages, tools=tools, tool_choice="auto")
        response_msg = response.choices[0].message
        messages.append(response_msg)

        if response_msg.tool_calls:
            for tool in response_msg.tool_calls:
                if tool.function.name == "execute_siem_query":
                    args = json.loads(tool.function.arguments)
                    search_query = args.get("query", "")
                    steps_executed.append(f"Action: SIEM 쿼리 실행 -> {search_query}")

                    search_results = siem_search_callback(search_query)
                    evidence_collected.extend(search_results)
                    steps_executed.append(f"Observation: {len(search_results)}개의 관련 로그 발견.")

                    messages.append({
                        "tool_call_id": tool.id,
                        "role": "tool",
                        "name": "execute_siem_query",
                        "content": json.dumps(search_results)
                    })

            messages.append({
                "role": "system",
                "content": "수집된 증거를 바탕으로 최종 결론을 JSON 형식으로 출력하세요. 필수 Key: 'thought', 'verdict' (False Positive, Benign, Malicious, Inconclusive 중 하나), 'summary'"
            })
            
            final_response = self.client.chat.completions.create(model=self.model, messages=messages, response_format={"type": "json_object"})
            final_data = json.loads(final_response.choices[0].message.content)

            return {
                "thought": final_data.get("thought", ""),
                "verdict": Verdict(final_data.get("verdict", "Inconclusive")),
                "summary": final_data.get("summary", ""),
                "evidence_collected": evidence_collected,
                "steps_executed": steps_executed
            }
        else:
            return {
                "thought": "도구 사용 없이 즉시 판정합니다.",
                "verdict": Verdict.INCONCLUSIVE,
                "summary": "증거 수집을 수행하지 않아 판단을 보류합니다.",
                "evidence_collected": [],
                "steps_executed": ["Action: 도구 호출 생략"]
            }

class SolverAgent:
    def __init__(self, siem_client: SecuritySiemClientInterface, llm_engine: Any = None):
        self.siem_client = siem_client
        self.llm = llm_engine or SimulatedLLM()  # 기본값: 시뮬레이션 엔진
        self.heuristics = DEFAULT_HEURISTIC_PLAYBOOK

    def investigate(self, context: GroundedContext, feedback_history: List[str]) -> InvestigationTrace:
        target_host = context.incident.target_host
        llm_prompt = f"Target Host: {target_host}\nHeuristics:\n{self.heuristics}\nFeedback History:\n{feedback_history}"

        # 의존성 주입된 엔진(시뮬레이터 or OpenAI)을 통해 ReAct 프레임워크 가동
        response = self.llm.generate_solver_trace(
            prompt=llm_prompt,
            user_role=context.user_role,
            siem_search_callback=self.siem_client.execute_log_search
        )
        
        return InvestigationTrace(
            steps_executed=response["steps_executed"],
            evidence_collected=response["evidence_collected"],
            proposed_verdict=response["verdict"],
            reasoning_summary=response["summary"]
        )

class CriticAgent:
    def verify(self, trace: InvestigationTrace) -> Tuple[bool, str]:
        requires_evidence = [Verdict.BENIGN, Verdict.FALSE_POSITIVE]
        # 공백 증거 공리 (Null-Evidence Axiom) - 하드코드 강제 룰 검증
        if trace.proposed_verdict in requires_evidence and len(trace.evidence_collected) == 0:
            msg = "위반 기각: 공백 증거(Null-Evidence) 상태에서는 경보를 안전(Benign)으로 판단할 수 없습니다."
            return False, msg
        return True, "Approved"

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

    def process_raw_alert(self, raw_alert_payload: Dict[str, Any], dataset_type: str) -> Tuple[Verdict, InvestigationTrace]:
        incident = self.normalizer.normalize_splunk_dataset(raw_alert_payload)
        context = self.enricher.enrich(incident)
        
        feedback_history = []
        for attempt in range(1, self.max_semantic_retries + 1):
            trace = self.solver.investigate(context, feedback_history)
            is_approved, critique_msg = self.critic.verify(trace)
            
            if is_approved:
                return trace.proposed_verdict, trace
                
            feedback_history.append(critique_msg)
            
        trace.proposed_verdict = Verdict.INCONCLUSIVE
        trace.reasoning_summary = "최대 추론 횟수 초과로 인한 기본 폴백 이관."
        return Verdict.INCONCLUSIVE, trace

# ==========================================
# 7. 확장성 대응 구조 분할 레이어
# ==========================================
def scan_splunk_datasets(splunk_base_dir: str) -> List[str]:
    search_path = os.path.join(splunk_base_dir, "datasets", "attack_techniques", "**", "*.*")
    all_files = glob.glob(search_path, recursive=True)
    return [f for f in all_files if f.endswith(('.log', '.txt', '.json'))]

def test_single_scenario(file_path: str, orchestrator: AdaptiveSOCOrchestrator, siem_client: RealDatasetSiemClient) -> Tuple[Verdict, InvestigationTrace]:
    siem_client.clear_database()
    technique_group = os.path.basename(os.path.dirname(file_path)) 
    events = []
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, start=1):
            if not line.strip(): continue
            try:
                events.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                events.append({
                    "event_id": f"{technique_group}_{line_num}",
                    "_time": datetime.datetime.now().isoformat(),
                    "host": "splunk-attack-host",
                    "dest": "splunk-attack-host",
                    "user": "unknown-context",
                    "signature": line.strip()[:100]
                })
                
    if not events:
        raise ValueError(f"파일에 파싱 가능한 유효 로그 데이터가 없습니다: %s", file_path)
        
    for evt in events:
        host = evt.get("dest", evt.get("host", "unknown-host"))
        if host not in siem_client.mock_logs_db:
            siem_client.mock_logs_db[host] = []
        siem_client.mock_logs_db[host].append(evt)
        
    trigger_alert = events[0]
    alert_id = trigger_alert.get("event_id", f"alert_{str(uuid.uuid4())[:4]}")
    siem_client.mock_alerts_db[alert_id] = trigger_alert
    
    return orchestrator.process_raw_alert(trigger_alert, "splunk")

def run_all_splunk_scenarios(splunk_dir: str, llm_engine: Any = None):
    print("====================================================================")
    print("🚀 [전체 데이터셋 검증] Splunk Attack Data 모든 시나리오 분석 파이프라인 가동")
    print("====================================================================\n")
    
    siem_client = RealDatasetSiemClient()
    infra_client = DynamicInfrastructureClient()
    normalizer = SemanticNormalizationLayer()
    enricher = DynamicStateInjection(infra_client)
    
    # 전달받은 LLM 엔진을 SolverAgent에 주입
    solver = SolverAgent(siem_client, llm_engine=llm_engine)
    critic = CriticAgent()
    orchestrator = AdaptiveSOCOrchestrator(normalizer, enricher, solver, critic)

    target_files = scan_splunk_datasets(splunk_dir)
    total_scenarios = len(target_files)
    
    print(f"[*] 총 {total_scenarios}개의 위협 기술 시나리오 파일을 발견했습니다.\n")
    
    stats = {Verdict.BENIGN: 0, Verdict.FALSE_POSITIVE: 0, Verdict.MALICIOUS: 0, Verdict.INCONCLUSIVE: 0}
    
    for idx, file_path in enumerate(target_files, start=1):
        filename = os.path.basename(file_path)
        technique_group = os.path.basename(os.path.dirname(file_path))
        
        try:
            verdict, trace = test_single_scenario(file_path, orchestrator, siem_client)
            stats[verdict] += 1
            print(f"[{idx}/{total_scenarios}] 기술그룹: {technique_group} | 파일명: {filename[:30]}... -> 판정: {verdict.value}")
        except Exception as e:
            logger.error(f"[{filename}] 에러 발생으로 인해 Inconclusive 처리됨: {str(e)}")
            stats[Verdict.INCONCLUSIVE] += 1
            continue

    print("\n" + "="*50)
    print("📊 AI SOC AGENT BENCHMARK EVALUATION SCORECARD")
    print("="*50)
    print(f"• 총 테스트 시나리오 개수  : {total_scenarios}건")
    print(f"• 자율 차단/종결 (Malicious) : {stats[Verdict.MALICIOUS]}건")
    print(f"• 자율 정제 (Benign)        : {stats[Verdict.BENIGN]}건")
    print(f"• 자율 의심 (False Positive) : {stats[Verdict.FALSE_POSITIVE]}건")
    print(f"• 인간 분석가 이관 (Inconclusive) : {stats[Verdict.INCONCLUSIVE]}건")
    print("-"*50)
    
    autonomous_closed = stats[Verdict.MALICIOUS] + stats[Verdict.BENIGN] + stats[Verdict.FALSE_POSITIVE]
    autonomy_rate = (autonomous_closed / total_scenarios) * 100 if total_scenarios > 0 else 0
    print(f"🎯 에이전트 업무 자율 종결율 (Resolution Cap): {autonomy_rate:.1f}%")
    print(f"👥 인간 분석가 오프라인 이관율              : {(100 - autonomy_rate):.1f}%")
    print("="*50 + "\n")

if __name__ == "__main__":
    # ---------------------------------------------------------
    # [설정] 엔진 모드 선택 (개발/실험)
    # ---------------------------------------------------------
    
    # 모드 1: 비용이 발생하지 않는 로컬 시뮬레이션 (기본값)
    engine = SimulatedLLM()

    # 모드 2: 실제 OpenAI API를 활용한 라이브 동작 
    # engine = OpenAILiveEngine(api_key="sk-your-openai-api-key")

    run_all_splunk_scenarios(splunk_dir="../Splunk_data", llm_engine=engine)