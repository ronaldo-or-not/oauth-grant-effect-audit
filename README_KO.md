# OAuth Grant–Effect Audit

OAuth 클라이언트가 승인받은 자원 집합 `G`와 실제 서버 효과를 연결해 확인하는 오프라인 증거 판정기입니다. `B ∉ G`인 자원 B에서 효과가 관찰되었는지를, 정상 대조 요청과 서버 측 상태 측정까지 함께 읽어 판정합니다.

이 저장소에는 **특정 제품의 미공개 수정 누락, 작동하는 제품별 재현 코드, 실제 토큰이 없습니다.** 예제는 모두 합성 데이터입니다. 현재 공개 버전은 JSON 증거 파일을 읽는 도구이며, 자동으로 대상을 스캔하거나 취약점을 발견한다고 주장하지 않습니다.

## 실행

```sh
python3 -m pip install -e .
grant-effect-audit examples/synthetic-finding.json --json
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

판정은 `out_of_grant_effect_observed`, `no_out_of_grant_effect_observed`, `within_grant`, `inconclusive` 중 하나입니다. HTTP 200이나 토큰 발급만으로 결함이라고 판단하지 않습니다. 승인 기록이 독립적이지 않거나, 익명·기존 토큰 대조군이 없거나, 실제 서버 효과를 확인하지 못하면 `inconclusive`로 처리합니다. 효과가 0인 경우에는 B가 별도 정상 승인으로 실행 가능하다는 양성 대조군도 요구합니다.

입력 형식과 한계는 [증거 형식 문서](docs/evidence-format.md), 영어 전체 설명은 [README.md](README.md)를 보세요. 기준이 되는 표준은 [RFC 8707](https://www.rfc-editor.org/info/rfc8707/)과 [MCP 인가 명세](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)입니다.
