# 새 구현 세션용 `/goal` 프롬프트

TalkCut 프로젝트의 **Local 새 작업**에서 아래 블록 전체를 한 번에 붙여 넣는다. 목표를 현재 문서 작성 세션에서 실행하는 지시가 아니다. 새 task를 자동 생성하거나 구현을 시작한 상태도 아니다.

이 checkout의 계획 문서와 비공개 `projects/dgist-w02/goal-handoff.local.json`에 접근할 수 있어야 한다. 새 worktree에는 미커밋 문서와 gitignored 인계 파일이 자동 전달되지 않으므로 시작 전에 원래 checkout에서 확인한다. 이 문서의 프롬프트 본문은 공식 목표 길이 제한인 4,000자 이내로 유지한다. [공식 `/goal` 안내](https://learn.chatgpt.com/docs/developer-commands?surface=cli)

```text
/goal 이 TalkCut 저장소에서 첫 강의 편집 워크플로를 자율적으로 끝까지 구현하라. 실제 DGIST W02 원본으로 엄격한 자동·AI 검수를 통과한 최종 MP4를 READY_FOR_OWNER 상태로 준비하고, 검증된 OSS 코드를 push·PR 병합·alpha release까지 완료하라. 계획 제안으로 끝내지 말고 실제 구현·실행·검수·수정·공개를 수행하라.

먼저 README.md, docs/plans/0001-dgist-first-lecture.md, docs/plans/0002-autonomous-goal-contract.md, docs/validation/lecture-review-protocol.md와 적용되는 AGENTS.md를 읽어라. 실제 입력 위치와 위임 설정은 projects/dgist-w02/goal-handoff.local.json을 읽어라. 새 worktree를 쓰면 원래 checkout의 미커밋 계획과 비공개 인계 자료를 확인해 이어받고 기존 작업을 덮어쓰지 마라.

완료 조건은 RFC 0002의 AC01–AC13 전체 통과다. M1–M7 기능 구현·설치·회귀·복구 검증, 실제 DGIST 최종본의 G0–G5, 별도 검수자의 감사, 유효한 증거 묶음, 공개 코드의 CI·merge·release가 모두 필요하다. 사용자 최종 시청인 OWNER_ACCEPTED는 나중 단계이므로 기다리거나 대신 승인하지 마라.

Screen 전체 프레임·해상도·비율을 유지하고 작은 speaker 전체 프레임을 우측 상단에 겹쳐라. 검증한 단일 음원을 쓰고 실제 PTS·공통 시간축으로 모든 track에 동일한 컷을 적용하라. 원본과 성공한 산출물을 보존하라. 명확한 준비·무음만 정책으로 자동 적용하고, 말더듬·반복·재시작은 별도 AI 검수 후 적용하라. 무음 demo·질문 대기·의미 있는 정정은 보호하고 불확실한 삭제는 유지·복구하라. 자막·챕터·GUI·podcast 등으로 범위를 넓히지 마라.

중간 검수와 합의 범위의 판단은 네가 전담하라. 독립 가능한 구현·테스트·반대 검수를 subagent에 나누고 통합 책임은 유지하라. 모든 삭제 원본·모든 seam·최종 출력 전 범위를 실제 audio/video를 처리할 수 있는 도구로 검수하라. 제안과 검수 실행을 분리하고, source/output/clip hash와 modality·coverage를 기록하라. 기준이나 분모를 낮춰 완료를 만들지 마라. Mock, 짧은 sample, transcript-only 검수, 근거 없는 PASS, 분석 없는 keep-all은 완료가 아니다. 안전한 컷이 없는 경우도 계약의 별도 검증을 만족해야 한다.

첫 단계에서 원본 존재·영속 보존·전체 decode/PTS와 AI 검수 capability를 확인하라. 실제 합성본부터 만들고 한 컷의 적용·검수·복구를 증명한 뒤 자동 편집을 붙여라. 실제 실패 근거에 따라 구현 방식과 순서를 개선하되 요구·품질 기준은 유지하라. 각 체크포인트마다 미충족 AC, 실행 명령, 실제 결과, 다음 작업을 기록하고 context 압축·재개 후 이어가라. 의미 단위로 commit하고 마지막 변경 뒤 필요한 검증을 갱신하라.

기존 연결된 AI 도구로 필요한 DGIST 음성·영상 구간·frame·전사를 보내 분석·검수하는 것을 허용한다. 별도 유료 API 과금·가입은 먼저 질문하라. 코드·문서·공개 가능한 fixture의 push, PR 생성·병합, 버전 release는 자율 진행하라. 녹화 원본·편집본·개인 transcript·비공개 검수 자료·credentials는 공개하지 마라. 필수 CI나 repository 보호 규칙을 우회하지 마라. 별도 Codex token budget은 설정하지 말고 계정 한도와 앱 설정 안에서 진행하라.

기능이 어렵거나 테스트가 실패하거나 한 milestone이 끝났다는 이유로 멈추지 마라. 불명확한 optional 컷은 정해진 복구 정책으로 해결하고 계속 진행하라. 새로운 권한·유료 비용·필수 입력·품질 요구 변경이 실제로 필요할 때만 근거와 대안을 준비해 현재 세션에서 허용되는 질문 수단으로 질문하고 독립 작업은 계속하라. 한도 소진이나 외부 장애는 checkpoint를 남길 사유이며 목표 달성이 아니다. Goal 상태 변경은 현재 세션의 실제 도구 규칙을 따르고, 같은 goal을 반복 생성해 사용량을 초기화하지 마라.

완료 직전에 구현한 acceptance evaluate 명령으로 실제 최종 code·source·output·contract hash와 공개 release 증거를 평가하고 결과를 읽어라. 필수 FAIL·UNVERIFIED·stale 또는 미해결 P0/P1이 남으면 완료 처리하지 마라. AC01–AC13과 별도 감사가 모두 통과하면 goal을 완료하고, 최종 MP4의 절대 경로, 검수 보고서, 실제 측정·테스트 결과, 재실행·복구 명령, PR·release 링크, 확인 가능한 사용량·비용을 간결히 전달하라. 사용자 확인은 pending으로 남겨라.
```

## 운영 메모

- 완벽함을 추상적으로 반복 요구하는 대신 실제 산출물·반례 검사·평가기·별도 감사로 종료 조건을 고정했다.
- 일반 상태 업데이트는 새 goal을 만드는 명령이 아니다. 현재 goal과 체크포인트를 유지한다.
- 계정 한도·외부 권한·검수 도구의 실제 capability는 프롬프트로 우회할 수 없다. 부족한 경우에도 결과를 과장하지 않고 가능한 구현을 진행하도록 했다.
- 사용자 최종 확인을 구현 goal에서 분리했으므로, 사용자가 자리를 비운 동안 구현과 코드 release까지 완료할 수 있다.
