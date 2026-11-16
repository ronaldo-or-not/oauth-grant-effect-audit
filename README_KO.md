# OAuth Grant–Effect Audit

OAuth 클라이언트가 승인받은 자원 집합 `G`와 실제 서버 효과를 연결해 확인하는 증거 수집기와 판정기입니다. `B ∉ G`인 자원 B에서 효과가 관찰되었는지를, 정상 대조 요청과 서버 측 상태 측정까지 함께 읽어 판정합니다.

이 저장소에는 **특정 제품의 미공개 수정 누락, 그 제품의 작동하는 재현 코드, 실제 토큰이 없습니다.** 빠른 시작 JSON은 합성 데이터입니다. [AuthPlane 로컬 예제](examples/authplane_local/README.md)는 공식 인가 서버와 시험용 보호 경로를 실제 HTTP로 연결합니다. 공개 버전은 어댑터가 제공하는 승인·효과 증거를 수집하고 판정하며, 자동으로 임의의 대상을 탐색하거나 취약점을 발견한다고 주장하지 않습니다.

## 실행

```sh
python3 -m pip install -e .
grant-effect-audit examples/synthetic-finding.json --json
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

판정은 `out_of_grant_effect_observed`, `no_out_of_grant_effect_observed`, `within_grant`, `inconclusive` 중 하나입니다. HTTP 200이나 토큰 발급만으로 결함이라고 판단하지 않습니다. 승인 기록이 독립적이지 않거나, 익명·기존 토큰 대조군이 없거나, 실제 서버 효과를 확인하지 못하면 `inconclusive`로 처리합니다. 효과가 0인 경우에는 B가 별도 정상 승인으로 실행 가능하다는 양성 대조군도 요구합니다.

입력 형식과 한계는 [증거 형식 문서](docs/evidence-format.md), 영어 전체 설명은 [README.md](README.md)를 보세요. 기준이 되는 표준은 [RFC 8707](https://www.rfc-editor.org/info/rfc8707/)과 [MCP 인가 명세](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)입니다.

실제 서비스용 어댑터 작성 방법은 [어댑터 안내](docs/adapter-guide.md)를 보세요. `grant-effect-collect`는 기본적으로 로컬 주소만 허용하고, 토큰·비밀번호 등 알려진 비밀 필드를 거부하며, 출력 파일을 덮어쓰지 않습니다. 공개 전에는 출력에 다른 민감 정보가 없는지 직접 확인해야 합니다.
