# ARP Controller

로컬 네트워크 기기 스캔 및 인터넷 차단/복구 도구

ARP 스푸핑을 이용하여 네트워크 내 기기의 인터넷 연결을 끊거나 복구할 수 있습니다.

## 주의사항

- **반드시 관리자 권한으로 실행**해야 합니다 (Windows: 관리자 CMD/PowerShell, Linux: sudo)
- **자신이 관리하는 네트워크에서만 사용**하세요. 타인의 네트워크에서 무단 사용은 불법입니다.
- 교육 및 네트워크 관리 목적으로만 사용하세요.

## 주요 기능

| 기능 | 설명 |
|------|------|
| 기기 스캔 | 네트워크 전체에 ARP 요청을 브로드캐스트하여 응답하는 기기 탐지 |
| 기기 정보 수집 | 스캔 시 호스트명, MAC 제조사, OS 추정(TTL 기반), 응답 시간 자동 수집 |
| 기기 상세 조회 | IP 주소 클릭 시 우측 패널에서 호스트명, 제조사, OS, TTL, RTT, 차단 상태 확인 |
| 내 컴퓨터 정보 | 상단에 자신의 IP/MAC 및 게이트웨이 IP/MAC 강조 표시 |
| 인터넷 차단 | ARP 스푸핑으로 타겟의 ARP 테이블 조작 + IP 포워딩 비활성화로 패킷 드롭 |
| 인터넷 복구 | 스푸핑 중지 후 올바른 ARP 응답 5회 전송하여 ARP 테이블 복구 |

## 작동 원리

| 기능 | 원리 |
|------|------|
| **기기 스캔** | ARP 요청 브로드캐스트 → 응답 기기 탐지 → ping으로 TTL/RTT 수집 → reverse DNS/NetBIOS로 호스트명 해석 → MAC OUI로 제조사 식별 |
| **인터넷 차단** | ARP 스푸핑으로 타겟의 ARP 테이블을 조작, 게이트웨이 대신 공격자 MAC으로 패킷이 오도록 속임. IP 포워딩 비활성화로 패킷 드롭 |
| **인터넷 복구** | 스푸핑 중지 후 올바른 ARP 응답을 5회 전송하여 타겟의 ARP 테이블 복구 |
| **OS 추정** | ping 응답 TTL 기반 (TTL<=64: Linux/macOS, TTL<=128: Windows, TTL<=255: 네트워크 장비/IoT) |
| **제조사 식별** | MAC 주소 OUI(앞 6자리)를 로컬 OUI 테이블에서 조회 (외부 네트워크 요청 없음) |

## 프로젝트 구조

```
arp-controller/
├── server.py                # Python Flask 백엔드 (ARP 스캔/스푸핑/API)
├── requirements.txt         # Python 의존성
├── package.json             # Node.js 설정 (TypeScript 빌드)
├── .gitignore               # Git 무시 파일
├── frontend/
│   ├── index.html           # 웹 UI (JetBrains Mono, 흑백 테마)
│   ├── app.js               # 컴파일된 TypeScript (실제 사용 파일)
│   ├── tsconfig.json        # TypeScript 컴파일러 설정
│   └── src/
│       └── app.ts           # TypeScript 소스
```

## 설치 방법

### 1. Python 의존성

```bash
pip install -r requirements.txt
```

필요 패키지:
- `flask` - 웹 서버
- `flask-cors` - CORS 허용
- `scapy` - ARP 패킷 생성/송수신

### 2. Npcap (Windows 필수)

scapy가 Windows에서 패킷을 송수신하려면 Npcap이 필요합니다.

1. https://npcap.com 에서 다운로드
2. 설치 시 **"Install Npcap in WinPcap API-compatible Mode"** 체크
3. 재부팅

Linux에서는 `libpcap-dev` 설치:
```bash
sudo apt install libpcap-dev    # Debian/Ubuntu
sudo dnf install libpcap-devel  # Fedora
```

### 3. TypeScript 빌드 (선택 - 소스 수정 시에만)

```bash
npm install
npm run build
```

> 이미 컴파일된 `frontend/app.js`가 포함되어 있어, 소스를 수정하지 않으면 빌드 불필요

## 실행 방법

### Windows

1. **관리자 권한**으로 명령 프롬프트 또는 PowerShell 실행
2. 프로젝트 디렉토리로 이동
3. 실행:
   ```
   python server.py
   ```
4. 브라우저에서 http://localhost:5000 접속

### Linux

```bash
sudo python3 server.py
```

## 사용법

1. **네트워크 스캔** 버튼 클릭 → 로컬 네트워크의 모든 기기 탐색
2. 상단 카드에서 **내 컴퓨터/게이트웨이 정보** 확인
3. 기기 목록에서 **IP, 호스트명, MAC 주소, 연결 상태** 확인
4. **IP 주소 클릭** → 우측 패널에서 기기 상세 정보 (호스트명, 제조사, OS 추정, TTL, RTT, 차단 상태) 확인
5. **인터넷 차단** 버튼으로 해당 기기 인터넷 연결 차단
6. **인터넷 허용** 버튼으로 해당 기기 인터넷 연결 복구

## API 엔드포인트

| Method | Endpoint | 설명 |
|--------|----------|------|
| GET | `/api/scan` | 네트워크 ARP 스캔 실행 (호스트명, 제조사, OS 추정, TTL, RTT 포함) |
| GET | `/api/devices` | 마지막 스캔 결과 조회 |
| GET | `/api/device?ip=x.x.x.x` | 특정 기기 상세 정보 조회 |
| GET | `/api/status` | 차단 상태 및 네트워크 정보 (로컬/게이트웨이 IP, MAC) 조회 |
| POST | `/api/block` | 기기 인터넷 차단 (`{"ip": "x.x.x.x"}`) |
| POST | `/api/unblock` | 기기 인터넷 복구 (`{"ip": "x.x.x.x"}`) |

## 문제 해결

| 문제 | 원인 | 해결 |
|------|------|------|
| "Not running with admin" 경고 | 관리자 권한 없음 | 관리자로 재실행 |
| 스캔 결과 0건 | Npcap 미설치 또는 방화벽 | Npcap 설치, 방화벽에서 Python 허용 |
| 차단해도 인터넷 됨 | IP 포워딩이 켜져있음 | 서버가 자동으로 비활성화하나, 수동 확인 필요 |
| 서버 종료 후 기기가 여전히 차단 | ARP 캐시 갱신 대기 | 기기에서 `arp -d *` 실행 또는 1~2분 대기 |
| 제조사가 표시되지 않음 | OUI 테이블에 없는 MAC | 주요 제조사만 등록되어 있어 일부 기기는 미표시 |

## 기술 스택

- **Backend**: Python 3, Flask, Scapy
- **Frontend**: HTML5, TypeScript, JetBrains Mono
- **Protocol**: ARP (Address Resolution Protocol)
- **Design**: 검정/회색 계열 다크 테마, 모노스페이스 폰트
