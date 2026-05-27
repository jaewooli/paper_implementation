---

## 📊 실험 및 검증용 외부 데이터셋 설정

본 레포지토리의 일부 프로젝트는 실제 SOC 환경의 이기종 로그 및 위협 시나리오를 시뮬레이션하기 위해 오픈소스 표준 데이터셋을 활용함. 
대용량 로그 파일의 형상 관리 오버헤드를 방지하기 위해, 해당 데이터셋 폴더들은 `.gitignore`에 등록되어있음.

프로토타입을 로컬에서 정상적으로 실행하려면 아래 지침에 따라 외부 리포지토리를 이 프로젝트의 루트 폴더 내에 클론해야 함.

### 1. 데이터셋 클론 (Clone Datasets)

프로젝트 루트 디렉토리에서 아래 명령어를 실행하여 두 개의 데이터셋을 클론합니다.

```bash
# 1. Splunk Attack Range 데이터셋 클론
git clone [https://github.com/splunk/attack_data.git](https://github.com/splunk/attack_data.git) Splunk_data

# 2. MITRE ATT&CK 매핑 표준 데이터셋 (OTRF Security-Datasets) 클론
git clone [https://github.com/OTRF/Security-Datasets.git](https://github.com/OTRF/Security-Datasets.git) MITRE_ATT&CK_data