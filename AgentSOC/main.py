import os
import re
import json
import logging
import networkx as nx
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Iterator
from abc import ABC, abstractmethod

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ==========================================
# 0. Data Structures
# ==========================================
@dataclass
class SplunkLog:
    raw_data: Dict[str, Any]
    source_file: str = "unknown"

@dataclass
class EnrichedIncident:
    incident_id: str
    user: str
    user_tier: int
    source_host: str
    target_host: str
    target_criticality: int
    event_type: str
    flags: List[str]

@dataclass
class Hypothesis:
    hypothesis_id: str
    description: str
    confidence: float
    mitre_attack_techniques: List[str]
    is_feasible: Optional[bool] = None
    feasibility_reason: Optional[str] = None

@dataclass
class ActionOption:
    action_id: str
    action_primitive: str
    target: str
    containment_score: float
    business_impact: float

@dataclass
class RankedAction:
    action: ActionOption
    composite_score: float
    rank: int = 0

# ==========================================
# [NEW] 1. Smart Field Extractor
# ==========================================
def parse_log_fields(raw_data: Dict[str, Any], file_name: str) -> Dict[str, str]:
    """Splunk, Sysmon, WinEvent 등 다양한 포맷과 깊이에서 src, dest, user를 기필코 찾아내는 헬퍼"""
    raw_str = raw_data.get("_raw", str(raw_data))
    
    # 1. Source 추출 (src, Computer, host, SourceIp 등)
    src = raw_data.get("src") or raw_data.get("SourceIp") or raw_data.get("Computer") or raw_data.get("host")
    if not src and isinstance(raw_data.get("result"), dict):
        src = raw_data["result"].get("src") or raw_data["result"].get("host")

    # 2. Destination 추출 (dest, TargetDomainName, DestinationIp 등)
    dest = raw_data.get("dest") or raw_data.get("DestinationIp") or raw_data.get("TargetDomainName")
    if not dest and isinstance(raw_data.get("result"), dict):
        dest = raw_data["result"].get("dest")

    # 3. 최후의 수단: Plain Text에서 정규식으로 IP 추출
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_str)
    if not src and ips: src = ips[0]
    if not dest and len(ips) > 1: dest = ips[1]

    # 4. User 및 Event Type 추출
    user = raw_data.get("user") or raw_data.get("UserName") or raw_data.get("TargetUserName")
    event_type = raw_data.get("sourcetype") or raw_data.get("EventID") or file_name.split(".")[0]

    return {
        "src": str(src).strip() if src else "unknown_src",
        "dest": str(dest).strip() if dest else "unknown_dest",
        "user": str(user).strip() if user else "unknown_user",
        "event_type": str(event_type).strip(),
        "timestamp": raw_data.get("_time", "unknown_time")
    }

# ==========================================
# 2. Data Ingestion
# ==========================================
class SplunkDataIngester:
    def __init__(self, base_directory: str):
        self.base_dir = Path(base_directory)
        
    def stream_logs(self, limit: Optional[int] = None) -> Iterator[SplunkLog]:
        if not self.base_dir.exists(): return
        
        files = list(self.base_dir.rglob("*.json")) + list(self.base_dir.rglob("*.log"))
        count = 0
        
        for file_path in files:
            if limit and count >= limit: break
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                try:
                    content = f.read()
                    f.seek(0)
                    data = json.loads(content)
                    if isinstance(data, list):
                        for item in data:
                            if limit and count >= limit: break
                            yield SplunkLog(raw_data=item, source_file=file_path.name)
                            count += 1
                        continue
                    elif isinstance(data, dict):
                        yield SplunkLog(raw_data=data, source_file=file_path.name)
                        count += 1
                        continue
                except json.JSONDecodeError:
                    pass

                f.seek(0)
                for line in f:
                    line = line.strip()
                    if not line: continue
                    if limit and count >= limit: break
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        item = {"_raw": line} # 순수 텍스트 로그
                    yield SplunkLog(raw_data=item, source_file=file_path.name)
                    count += 1

# ==========================================
# 3. Dynamic Topology Builder (Pass 1)
# ==========================================
class LogBasedTopologyBuilder:
    def __init__(self):
        self.graph = nx.DiGraph()

    def ingest_single_log(self, log: SplunkLog):
        fields = parse_log_fields(log.raw_data, log.source_file)
        src, dest = fields["src"], fields["dest"]
        
        # Source나 Dest 하나라도 존재하면 노드(자산)로 등록 (단일 호스트 이벤트 허용)
        if src != "unknown_src": self.graph.add_node(src)
        if dest != "unknown_dest": self.graph.add_node(dest)
        
        # 둘 다 존재하면 네트워크 간선(Edge) 추가
        if src != "unknown_src" and dest != "unknown_dest" and src != dest:
            if self.graph.has_edge(src, dest):
                self.graph[src][dest]['weight'] += 1
            else:
                self.graph.add_edge(src, dest, weight=1)

    def analyze_and_classify_nodes(self) -> nx.DiGraph:
        for node in self.graph.nodes():
            in_d, out_d = self.graph.in_degree(node), self.graph.out_degree(node)
            tier, crit, role = 2, 3, "Workstation"
            if in_d > 3 and out_d <= 2: role, tier, crit = "Server", 1, 7
            elif in_d > 5 and out_d > 5: role, tier, crit = "Core_Infra", 0, 10
            
            self.graph.nodes[node].update({'role': role, 'tier': tier, 'criticality': crit})
        return self.graph

# ==========================================
# 4. Core Engine (Layers & Modules)
# ==========================================
class SimulatedLLM:
    def generate_json(self, prompt: str) -> str:
        return json.dumps([{
            "hypothesis_id": "H-AUTO",
            "description": "Potential unauthorized access or local execution",
            "confidence": 0.65,
            "mitre_attack_techniques": ["T1059", "T1078"]
        }])

class InternalKnowledgeStore:
    def __init__(self): self.topology = nx.DiGraph()
    def load_topology(self, graph: nx.DiGraph): self.topology = graph
    def query_context(self, user: str, host: str) -> Dict:
        node_data = self.topology.nodes.get(host, {})
        return {
            "user_tier": 0 if "admin" in str(user).lower() else node_data.get('tier', 2),
            "target_criticality": node_data.get('criticality', 3)
        }

class PerceptionLayer:
    def __init__(self, knowledge_store: InternalKnowledgeStore):
        self.knowledge_store = knowledge_store
        
    def process_alert(self, log: SplunkLog) -> EnrichedIncident:
        fields = parse_log_fields(log.raw_data, log.source_file)
        
        # 목적지가 없으면(단일 호스트 이벤트) 타겟을 출발지와 동일하게 취급하여 문맥 획득
        target_for_ctx = fields["dest"] if fields["dest"] != "unknown_dest" else fields["src"]
        ctx = self.knowledge_store.query_context(fields["user"], target_for_ctx)
        
        import uuid
        return EnrichedIncident(
            incident_id=f"INC-{str(uuid.uuid4())[:8]}",
            user=fields["user"],
            user_tier=ctx["user_tier"],
            source_host=fields["src"],
            target_host=fields["dest"],
            target_criticality=ctx["target_criticality"],
            event_type=fields["event_type"],
            flags=["suspicious_activity"] if ctx["target_criticality"] > 5 else []
        )

class StructuralSimulationEngine:
    def __init__(self, knowledge_store: InternalKnowledgeStore):
        self.knowledge_store = knowledge_store
        
    def validate_feasibility(self, hypotheses: List[Hypothesis], incident: EnrichedIncident) -> List[Hypothesis]:
        valid_hypotheses = []
        topo = self.knowledge_store.topology
        
        for hyp in hypotheses:
            has_path = False
            if incident.target_host != "unknown_dest" and incident.source_host != "unknown_src":
                if topo.has_node(incident.source_host) and topo.has_node(incident.target_host):
                    try:
                        has_path = nx.has_path(topo, incident.source_host, incident.target_host)
                    except nx.NodeNotFound:
                        pass
        
            elif incident.source_host != "unknown_src":
                has_path = topo.has_node(incident.source_host)

            if has_path:
                hyp.is_feasible = True
                valid_hypotheses.append(hyp)
                
        return valid_hypotheses

class RiskScoringEvaluationModule:
    def __init__(self, alpha=0.7, beta=0.3):
        self.alpha, self.beta = alpha, beta
        
    def rank_actions(self, feasible_hypotheses: List[Hypothesis], incident: EnrichedIncident) -> List[RankedAction]:
        if not feasible_hypotheses: return []
        target_to_isolate = incident.source_host if incident.source_host != "unknown_src" else incident.target_host
        actions = [
            ActionOption("A1", "ISOLATE_HOST", target_to_isolate, 0.92, 0.15),
            ActionOption("A2", "MONITOR_ONLY", target_to_isolate, 0.15, 0.00)
        ]
        ranked = [RankedAction(act, round((self.alpha * act.containment_score) - (self.beta * act.business_impact), 3)) for act in actions]
        ranked.sort(key=lambda x: x.composite_score, reverse=True)
        return ranked

class ActionAndPlaybookLayer:
    def process_playbook(self, ranked_actions: List[RankedAction]) -> Dict[str, Any]:
        if not ranked_actions: return {"status": "Ignored", "action": None}
        top = ranked_actions[0].action
        return {"status": "Awaiting Approval" if top.business_impact >= 0.8 else "Auto-Executed", "action": top}

# ==========================================
# Main: Execution Flow
# ==========================================
if __name__ == "__main__":
    current_workspace = os.getcwd() 
    splunk_dataset_path = os.path.join(current_workspace,"..", "Splunk_data", "datasets")
    
    ingester = SplunkDataIngester(base_directory=splunk_dataset_path)

    logging.info("==================================================")
    logging.info("[PASS 1] 로그 스캔을 통한 네트워크 토폴로지 및 CMDB 구축 시작...")
    builder = LogBasedTopologyBuilder()
    
    log_count = 0
    # 전체 스캔
    for splunk_log in ingester.stream_logs(limit=None):
        builder.ingest_single_log(splunk_log)
        log_count += 1
        
    topology = builder.analyze_and_classify_nodes()
    logging.info(f"[PASS 1 완료] 식별된 자산(노드): {topology.number_of_nodes()}개 / 엣지(경로): {topology.number_of_edges()}개")
    
    # ---------------------------------------------------------
    k_store = InternalKnowledgeStore()
    k_store.load_topology(topology)
    
    perception = PerceptionLayer(k_store)
    nce = type('NarrativeCounterfactualEngine', (), {'generate_hypotheses': lambda s, i: [Hypothesis("H", "Threat", 0.7, ["T1059"])]})()
    sse = StructuralSimulationEngine(k_store)
    rsem = RiskScoringEvaluationModule()
    action_layer = ActionAndPlaybookLayer()

    logging.info("\n[PASS 2] 완성된 토폴로지를 기반으로 위협 탐지 파이프라인 가동 시작...")
    
    processed = executed_count = escalated_count = ignored_count = 0

    for splunk_log in ingester.stream_logs(limit=None):
        incident = perception.process_alert(splunk_log)
        
        if incident.source_host == "unknown_src" and incident.target_host == "unknown_dest":
            ignored_count += 1
            continue

        hypotheses = nce.generate_hypotheses(incident)
        feasible_hyps = sse.validate_feasibility(hypotheses, incident)
        
        if not feasible_hyps:
            ignored_count += 1
            continue
            
        ranked_actions = rsem.rank_actions(feasible_hyps, incident)
        outcome = action_layer.process_playbook(ranked_actions)
        
        processed += 1
        if "Executed" in outcome['status']: executed_count += 1
        elif "Awaiting" in outcome['status']: escalated_count += 1

    logging.info("==================================================")
    logging.info("[최종 결과 요약]")
    logging.info(f"총 스캔된 로그 수 : {log_count}건")
    logging.info(f"분석된 유효 위협  : {processed}건")
    logging.info(f"자동 조치 완료    : {executed_count}건")
    logging.info(f"정보 누락(무시됨) : {ignored_count}건")
    logging.info("==================================================")