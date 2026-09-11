# RFC 0002 — 자율 구현 목표와 달성 평가 계약

| 항목 | 내용 |
| --- | --- |
| 상태 | 구현 세션에 전달할 목표 계약. 평가 명령과 기능은 아직 미구현 |
| 작성일 | 2026-09-07 |
| 상위 요구 | [구현 RFC](0001-dgist-first-lecture.md)의 R01–R14 및 이후 명시적 사용자 결정 |
| 세부 품질 규칙 | [검수 프로토콜](../validation/lecture-review-protocol.md) |
| 실행 진입점 | [새 세션용 `/goal` 프롬프트](../prompts/dgist-autonomous-goal.md) |

## 1. 하나의 목표와 유한한 종료 조건

> TalkCut의 첫 강의 편집 워크플로를 실제로 구현하고, 등록된 DGIST W02 원본으로 모든 필수 자동·AI 검수를 통과한 `READY_FOR_OWNER` 최종 MP4를 준비하며, 재현 가능한 OSS 코드를 검증·병합·alpha release까지 완료한다.

이 목표의 성공은 다음 조건의 **논리곱**이다.

```text
GOAL_ACHIEVED =
    implementation_acceptance == PASS
    AND real_dgist_acceptance == PASS
    AND reproducibility_and_recovery == PASS
    AND independent_review == PASS
    AND handoff_complete == PASS
    AND code_release_verified == PASS
```

각 항목은 아래 AC01–AC13의 실제 증거로 판정한다. 하나라도 FAIL, UNVERIFIED, stale이면 미완료다. 테스트 수, 작성한 코드량, PR 수, agent의 자신감, 백분율 평균으로 대신 판정하지 않는다.

- 범위는 RFC 0001의 M1–M7에 해당하는 구현·로컬 OSS 공개 준비와 DGIST G0–G5다.
- G6 `OWNER_ACCEPTED`는 사용자가 나중에 최종본을 확인하는 별도 단계다. Goal 완료를 위해 사용자에게 중간 시청이나 최종 확인을 재촉하지 않는다.
- G7의 코드·fixture·설치·문서·호환성 증거와 remote push, PR, merge, alpha release까지 포함한다. 2026-09-07 사용자가 이 범위를 명시적으로 위임했다. Code release와 DGIST 영상의 게시·사용자 최종 수락은 별개다.
- 다른 강사의 holdout 확보, 범용 VFR/HDR 지원, 자막·챕터, GUI, podcast, LMS 업로드는 이번 종료 조건에 넣지 않는다. 해당 후속 작업을 끝없이 수행하지 않는다.
- “완벽”은 계약상 필수 증거가 유효하고 관측된 미해결 P0/P1이 없다는 뜻이다. 알 수 없는 모든 오류가 0이라고 증명했다는 뜻이 아니다.

## 2. Goal 기능과 제품의 평가기를 구분

`/goal`은 작업을 여러 turn에 걸쳐 지속할 목표다. 제품의 테스트 실행기나 media 품질 검사 자체가 아니다. 저장된 목표에는 목표·종료 조건·문서 위치를 짧게 넣고, 상세 계약은 이 파일에 둔다. 공식 문서는 목표를 4,000자 이내로 제한하며 긴 지시는 파일을 가리키도록 안내한다. [Codex 명령 문서](https://learn.chatgpt.com/docs/developer-commands?surface=cli)

새 세션은 활성 goal이 있는지 확인하고 동일 목표를 매 turn 재생성하지 않는다. 목표를 새로 설정하면 사용량 집계가 달라질 수 있으므로 체크포인트를 goal 재설정으로 표현하지 않는다. [App Server goal 문서](https://learn.chatgpt.com/docs/app-server#manage-a-thread-goal)

Codex token budget, 외부 AI의 유료 API 비용, media 처리 시간·disk는 서로 다르다. 사용자가 명시하지 않은 token budget을 만들어 넣지 않는다. Goal이 있다고 권한·연결·사용량 제한이 확대되는 것도 아니다. [장기 실행 문서](https://learn.chatgpt.com/docs/long-running-work)

현재 이 문서를 만드는 세션은 구현 goal을 시작하지 않는다. 새 세션에서 사용자가 실행 프롬프트를 제출할 때 시작한다.

## 3. 새 세션의 시작 절차

1. 현재 checkout의 README, RFC 0001, 이 계약, 검수 프로토콜, 적용되는 AGENTS.md를 읽는다. 현재 구현 상태와 working tree를 확인한다. 과거 대화를 자동으로 기억한다고 가정하지 않는다.
2. 원래 checkout의 미커밋 계획 문서를 잃지 않는다. 새 worktree를 쓴다면 계획의 내용·hash를 확인해 포함시키고, 별도 작업자의 수정은 덮어쓰지 않는다. 오래된 default branch만 읽고 계획이 없다고 결론 내리지 않는다.
3. 비공개 `projects/dgist-w02/goal-handoff.local.json`에서 입력 위치·기존 확인 범위·위임 설정을 읽는다. 이 파일은 gitignored이며 worktree/clone에 자동 전달되지 않는다. 같은 host의 원래 checkout에서 찾아 비공개로 복사한다. 찾을 수 없다면 위치만 질문하고 독립적인 구현은 계속한다.
4. 등록한 완전한 screen/speaker와 비교용 mixed-retry를 확인한다. 불완전한 mixed는 제외한다. 임시 source는 영속 위치에 검증 복사하며 원본을 지우지 않는다. SHA-256과 전체 decode/PTS 증거는 새로 만든다.
5. M1에서 실제 reviewer의 audio·video modality와 시간 해상도를 시험한다. 1fps 요약 영상만으로 수십 ms의 입 모양 검증을 할 수 있다고 가정하지 않는다. 기존 연결된 도구와 로컬 분석을 조합하되 실제 관측 범위를 기록한다.
6. 아래 수용 조건을 실행 가능한 항목으로 옮기고 contract hash를 고정한다. 빈 상태 원장과 체크포인트를 만든 뒤 바로 가장 중요한 미검증 조건의 구현을 시작한다.

원본이 없거나 AI capability가 부족하면 이를 첫날 발견해야 한다. 그런 문제를 숨긴 채 긴 구현 후 합성 fixture만으로 실제 DGIST 완료를 선언하지 않는다.

## 4. 목표 달성 수용 조건

AC의 상태는 `PASS / FAIL / UNVERIFIED`다. 모든 AC는 필수이며 전체 AC를 `N/A`로 바꿀 수 없다. 특정 세부 검사가 적용되지 않으면 그 조건과 이유를 evaluator가 확인한다.

| ID | 통과에 필요한 결과 | 검증 증거·실패 예 |
| --- | --- | --- |
| AC01 실행 계약 | R01–R14, 위임 범위, protocol·계약 version, 실제 실행 code/toolchain/reviewer가 식별됨 | Contract/code/model/prompt hash; 기능이 없는 도구의 modality를 가정하면 실패 |
| AC02 실제 입력 | 등록한 DGIST source를 보존하고 정상 범위·시간축을 전체 검사 | Source hash/bytes/stream ID, full decode와 PTS coverage. Synthetic나 짧은 sample로 대체 불가 |
| AC03 기능 완주 | Inspect→sync→analysis→plan→review→render→QC→prepare-release의 실제 실행 경로 | 지원된 CLI의 E2E와 actual run manifest. Help, TODO, canned JSON, mock provider만 성공은 불가 |
| AC04 시간 정확성 | 단일 source/output mapping, audio 선택, offset/drift/lip sync, source coverage가 protocol 만족 | 실제 원본·출력의 holdout anchor 잔차/불확실성; 100-cut frame/sample fixture; unknown=UNVERIFIED |
| AC05 화면·음질 | 원본 screen/full-speaker 비율, 작은 우상단 PiP, 중요한 내용 가림 없음, 단일 audio | Full-res 실제 출력, geometry/occlusion/audio 검사. 새 crop/stretch/중복 mix/음절 손상은 실패 |
| AC06 편집 판단 | 전체 source를 분석해 근거 있는 후보·보호 구간·keep 이유를 생성하고 실제 적용을 검수 | 분석 coverage, positive/negative fixture, candidate ledger. 빈 후보를 하드코딩하거나 전부 keep으로 기능을 우회하면 실패 |
| AC07 수정·복구 | Cut→restore→reapply, project reopen, 변경 없는 재실행이 시간 관계와 결정 이력을 보존 | 합성 정답 fixture 및 실제 DGIST private project의 왕복 연습; 사용자 확인을 조작하지 않은 test-only 실험 |
| AC08 AI 검수 실체 | 제안과 별도 검수 실행, 모든 삭제 원본·seam·최종 출력 범위의 필요한 audio/video 관측 | 실제 입력 clip/hash·실행 ID·modality·유효 coverage. Transcript-only나 “보았다”는 자기 선언은 불가 |
| AC09 최종 master | 실제 강의 전체 retained intervals에 해당하는 파일이 완전 decode되고 모든 필수 gate 통과 | 최종 output hash, 실제 duration/frame/sample, G0–G5, P0/P1 미해결 0. Sample export나 미검수 baseline으로 대체 불가; 4.1절의 NO_SAFE_CUTS_VERIFIED만 조건부 예외 |
| AC10 실패·위조 방어 | 손상·중단·stale·source 교체·검수 누락을 실패로 처리하고 이전 성공본 보존 | 아래 negative 평가, cancel/disk/timeout·재개. `.partial` 승격과 임의 PASS 기록을 거절 |
| AC11 재현 가능한 OSS | 깨끗한 환경에서 설치·테스트·package build·합성 E2E와 지원 범위·복구 문서가 일치 | 최종 code revision의 실제 명령·exit·로그, 공개 가능한 fixture. 시험하지 않은 OS는 미검증으로 표시하고 지원 주장하지 않음 |
| AC12 독립 감사·전달 | 별도 검수자가 code·evaluator·고정 evidence snapshot을 감사하고 최종 파일·재현 명령을 포함한 전달 묶음을 준비 | 감사는 최종 집계 보고서 자신을 참조하지 않음. 미해결 P0/P1 없음; snapshot/audit/handoff hash, checkpoint, 최종 경로 |
| AC13 공개 코드 release | 허용된 repository에 구현을 push하고, review·필수 CI 통과 후 PR 병합과 첫 alpha release 완료 | PR·CI·merge commit·tag·release URL과 대상 code identity. 공개 assets/본문에 실제 녹화·개인 transcript·검수 자료 없음 |

`implementation_acceptance`는 AC01/03/06/11, `real_dgist_acceptance`는 AC02/04/05/08/09, `reproducibility_and_recovery`는 AC07/10/11, 감사·전달은 AC12의 서로 다른 증거, code release는 AC13을 사용한다. 일부 증거가 공유되어도 검증 범위를 합쳐 생략하지 않는다.

### 4.1 모든 구간을 남기는 경우

삭제율과 최소 컷 수를 목표로 삼지 않는다. 대신 결과를 구분한다.

- `EDITED`: 안전한 삭제를 실제 적용하고 검수를 통과했다.
- `NO_SAFE_CUTS_VERIFIED`: 전체 source의 분석·protection·후보 검수를 실제 수행했으나 안전한 삭제가 없다는 별도 감사 기록이 있다. 기능은 positive/negative fixture로 입증되어야 한다. 이 경우 보존한 합성본도 최종 후보가 될 수 있지만 “발화 편집으로 시간을 줄였다”고 주장하지 않는다.
- `COMPOSITION_ONLY` 또는 `ANALYSIS_UNAVAILABLE`: 분석·삭제 기능이나 근거가 없어서 합성만 했다. AC03/06/08이 미완료이므로 goal을 달성한 것이 아니다.

실제 DGIST에 안전한 컷이 없으면 AC07의 왕복 연습은 최종본과 분리한 `test_only` preview에서 수행한다. 시험용 삭제를 final plan에 넣어 수를 채우지 않는다.

### 4.2 안전성뿐 아니라 유효한 기능도 평가

초기 fixture에는 명확히 삭제 가능한 준비·정지 구간과 명확히 남겨야 하는 demo·질문 대기·부정·정정을 모두 둔다. Known-good expected action과 경계, 근거를 사람이 읽을 수 있게 작성하고 별도 검수자가 확인한다. AI가 만든 라벨을 사람 ground truth라 부르지 않는다.

최소 각 유형의 positive/negative 사례에서 정책의 기대 동작을 요구한다. 항상 keep, 항상 cut, 빈 결과 반환 구현은 서로 다른 fixture에서 실패해야 한다. 실제 자료는 불확실하면 keep하지만, 분석 실패로 후보를 만들지 못한 상태를 “안전한 컷 없음”으로 바꿀 수 없다.

## 5. 실행 가능한 평가기의 계약

M1에서 evidence schema와 작은 평가기의 골격을 만들고 M2–M6에서 실제 검사를 연결한다. M6의 필수 interface 제안은 다음과 같다. **현재 실행 가능한 명령이 아니다.**

```text
uv run --locked talkcut acceptance evaluate <private-project> \
  --render <render-id> --contract <frozen-contract.json> --json
```

위 contract는 이 문서·protocol의 AC와 수치 기준을 옮긴 versioned JSON이다. M1에 원문 hash와 변환된 조건을 비교해 고정한다. 숨은 설정으로 required 검사를 끌 수 없게 한다.

제안 exit contract는 `0=모든 필수 조건 PASS`, `1=FAIL 또는 UNVERIFIED/stale/누락`, `2=잘못된 인자·schema·실행 오류`다. Codex가 goal을 완료 처리하는 행위는 이 명령과 별개이며, 평가 통과 및 AC12 별도 감사를 확인한 뒤 수행한다.

공개 전에는 `release_ready = AC01–AC12 전체 PASS`를 별도 field로 계산한다. AC13은 아직 UNVERIFIED이므로 `goal_achieved=false`, 전체 평가 exit는 1이다. 실행자는 공개 전 gate에서 이 정상적인 대기 상태와 다른 FAIL/누락을 구분하고, `release_ready=true`일 때만 허용된 공개 절차를 진행한다. 공개 후 AC13 증거를 추가한 전체 평가에서만 `goal_achieved=true`와 exit 0을 허용한다. `prepare-release`의 media G0–G5 통과도 별도 상태다.

AC12 감사는 그 시점의 immutable code·media·검수 evidence snapshot과 준비된 전달 묶음을 대상으로 한다. Snapshot에 해당 감사 결과나 최종 집계 보고서 자신을 다시 넣어 hash 순환을 만들지 않는다. 공개 후 AC13은 새 증거로 더하며, code나 media가 변경되면 관련 감사도 다시 수행한다.

### 평가기가 직접 계산해야 하는 것

1. Source·code·contract·timeline·output·review input의 현재 hash를 대조한다. 실제 파일이 없거나 변경됐으면 evidence를 무효화한다.
2. 분모는 **원본의 검사 대상 구간, 실제 resolved timeline, 최종 master**로 재구성한다. 제안자가 보고한 후보 목록이나 검사 창 개수를 그대로 신뢰하지 않는다.
3. 삭제 interval의 합집합, 실제 seam 집합, output 유효 audio/video 범위와 검수 증거의 교집합을 계산한다. 중복·겹침·범위 밖 시간을 제거하고 누락 구간을 반환한다.
4. 검사에 필요한 modality·시간 해상도·최종 revision·검수 근거를 검증한다. Video 창 coverage와 실제 관측 frame 수는 별도 metric이다.
5. 위임 policy를 만족하는 actor의 decision인지 확인한다. Test-only, fixture, 다른 source/output의 결과는 실제 검수 근거에서 제외한다.
6. 모든 필수 검사가 PASS이며 미해결 P0/P1이 0인지 확인한다. 근거 없는 severity 하향·threshold 완화·required 해제를 탐지한다.
7. Output이 실제 retained intervals 전체인지 확인한다. 마지막 1분이나 잘된 30초만 제출한 결과는 누락된 강의 구간으로 실패해야 한다.

원본 domain도 보존식을 확인한다. 기준 screen의 전체 대상 시간은 유지 구간과 근거·결정이 있는 삭제 구간, 실제 측정된 source 결손 구간으로 빠짐없이 설명되어야 하며 겹쳐 계산하지 않는다. 앞뒤를 timeline에서 빠뜨리고 삭제 원장에도 넣지 않은 결과는 실패다. `source 결손`이라는 이름으로 정상적인 설명을 제외할 수 없고, 필수 구간의 미해결 결손은 여전히 blocker다.

평가기 자체도 agent가 구현하는 코드이므로 맹신하지 않는다. 독립 검수자가 평가기와 고정 fixture의 기대값을 확인하고 실제 로그·media를 재확인한다. 단순 hash는 내용 동일성을 확인할 뿐 검수의 진실성이나 의미 정확성을 보증하지 않는다.

### 최소 평가 보고서

```json
{
  "schema_version": "goal-acceptance/v1",
  "status": "UNVERIFIED",
  "release_ready": false,
  "goal_achieved": false,
  "goal_contract_hash": null,
  "code_revision": null,
  "code_tree_hash": null,
  "evaluator_version": null,
  "source_hashes": {},
  "output_hash": null,
  "edit_disposition": null,
  "criteria": [],
  "coverage": {},
  "uncovered_intervals": [],
  "open_findings": [],
  "independent_audit_ref": null,
  "code_release_evidence": null,
  "owner_acceptance": "pending"
}
```

이는 빈 형식 예시이며 합격 보고서가 아니다. `criteria`에는 AC01–AC13을 모두 넣고 각 측정값, 기대값, evidence refs, 판정, 유효성을 기록한다. Null이나 빈 배열은 해당 검사의 성공이 아니다.

Code hash에는 실행 source, lockfile, schema, evaluator, test configuration을 포함한다. 평가 보고서가 자신을 포함한 repository hash를 참조하는 순환은 피한다. 증거를 생성한 뒤 그 실행 코드가 바뀌면 필요한 평가를 다시 수행한다.

### 반드시 실패해야 하는 negative 평가

| 조작·결손 | 요구되는 결과 |
| --- | --- |
| Transcript만으로 audio/lip-sync PASS를 제출 | Modality 부족 → UNVERIFIED |
| 같은 30초 창을 여러 번 넣어 57분 coverage로 보고 | Union 재계산 → 실제 누락 구간 반환 |
| 모든 결과가 PASS지만 source/output hash가 다름 | Stale 또는 다른 입력 → 실패 |
| 미검수 삭제를 후보 목록에서 빼기 | 실제 timeline에서 삭제 재계산 → 실패 |
| 첫 source 1분만 렌더하고 전체 완료 주장 | Retained span와 전체 분석/제거 근거 불일치 → 실패 |
| Positive fixture에서 모든 후보 keep | 기능 수용 조건 실패 |
| 판정 원장에 임의로 PASS/human-approved 넣기 | Evidence/actor/provenance 불충족 → 실패 |
| Threshold/severity/required를 바꿔 기존 결함 통과 | Frozen contract 변경 탐지 → 재검토 전 실패 |
| Evaluator가 오류·skip를 0 exit로 반환 | Evaluator contract test 실패 |
| 취소된 render를 최종 MP4로 rename | 완료 manifest·decode·hash 부족 → 실패 |

## 6. 자율 실행과 체크포인트

매 반복은 다음 순서를 따른다.

```text
현재 goal + checkpoint 확인
→ 가장 중요한 미충족 AC와 원인 선택
→ 작고 검증 가능한 변경
→ 해당 test / 실제 media 실행
→ 별도 검수, 실패 수정 또는 안전한 restore
→ evidence + checkpoint 저장
→ 다음 미충족 조건으로 진행
```

독립 작업은 subagent에 나눈다. 예: timeline/renderer, fixture/evaluator, read-only code review. 같은 파일의 동시 편집 책임을 겹치지 않고 parent가 통합·최종 평가를 맡는다. 기능 제안자가 자신의 판정 하나만으로 AC12를 통과시키지 않는다.

`projects/dgist-w02/checkpoint.local.json` 또는 동등한 비공개 파일에 다음을 남긴다.

- Goal objective와 contract hash, 사용자가 확정한 권한·예산, code revision.
- AC별 현재 상태·근거, 마지막 성공 stage, 실패 원인과 시도 결과.
- 현재 계획·출력·review hash와 stale 관계, 살아 있는 process와 로그 위치.
- 다음 실행할 구체적 명령, 필요한 input, 예상 결과와 합격 기준.
- 결정한 사항과 미해결 질문, 외부 비용·Codex 사용량의 확인 가능 정보.

중요한 통합·실패·오랜 media 작업 전후에 저장한다. Context 압축·세션 재개 때 문서와 checkpoint를 읽고 유효한 작업을 이어간다. README를 매번 다시 계획하는 단계로 돌아가지 않는다.

실제 완료한 의미 단위로 local commit을 남긴다. 원본·개인 transcript·review clip·credentials·비공개 checkpoint는 commit하지 않는다. 외부 작업은 아래 위임 범위를 따른다.

### 6.1 확정된 자율 실행 권한

- **AI:** 기존 연결된 AI 도구로 분석·검수에 필요한 음성·영상 구간·frame·전사를 전송할 수 있다. 필요한 범위만 사용하고 새 유료 API 과금·가입은 사전 확인한다. 이 허용을 공개 업로드로 해석하지 않는다.
- **GitHub:** 코드·문서·공개 가능한 fixture의 push, PR 생성·병합, 버전 release까지 자율 진행한다. Repository protection·필수 CI를 우회하거나 강제 push로 다른 작업을 지우지 않는다.
- **Goal 예산:** 별도 Codex token budget을 지정하지 않는다. 계정 한도와 앱 설정을 따르고, 외부 API 비용과 별도로 기록한다. 무제한 과금 허용을 뜻하지 않는다.
- **로컬 작업:** 필요한 dependency 설치, source 검증 복사, 임시 분석·렌더, test·fixture·문서·code 수정, subagent 병렬 검수를 수행한다. 원본 보존과 다른 작업자의 변경 보존은 유지한다.

### 6.2 공개 release 순서

초기 버전은 alpha로 표시하고 현재 tags·package version을 확인해 충돌 없는 다음 버전을 선택한다. 실제 검증한 platform만 지원 주장에 포함한다. 필수 CI가 실패하거나 보호 규칙이 막으면 원인을 해결하며 임의 bypass하지 않는다.

새 repository의 branch protection에 required check가 없더라도 CI를 생략하지 않는다. 최소 schema/순수 logic 테스트, lint/type check, package build·clean install, 실제 FFmpeg 합성 fixture E2E의 CI를 정의하고 대상 code에서 성공시킨다. 여기에 repository가 요구하는 check도 모두 포함한다. CI 설정 파일만 추가한 것은 실행 성공이 아니다.

실제 DGIST G0–G5와 AC01–AC12가 유효한 code를 PR에서 검토하고 merge한다. Merge로 실행 코드가 달라지면 영향을 받는 테스트·검수를 갱신한다. 확정된 code tree를 tag/release하고 URL·commit을 다시 조회해 AC13 증거로 저장한다. Release note는 구현·검증 범위와 알려진 한계를 설명하고, 사용자가 DGIST를 이미 수락했다는 표현을 사용하지 않는다.

Public CI와 release에는 합성 또는 공개 허가된 자료만 사용한다. Private DGIST evidence는 local acceptance report에 연결하고 public 로그·issue·PR·release에 복사하지 않는다. 최종 종합 평가기는 local evidence와 read-only로 조회한 GitHub evidence를 함께 확인한다.

각 push·PR·release 전에 staged/공개 예정 파일, 공개 기록에 들어가는 새 commit, 본문·로그·첨부물·package 내용을 검사한다. Private 원본·편집본·transcript·검수 자료·credentials·private path가 섞였으면 그 공개를 막고 안전한 산출물로 수정한다. AC13의 게시 후 확인으로 사전 검사를 대체하지 않는다.

## 7. 계속 진행할 때와 실제 장애

| 상황 | 실행 방식 | Goal 판정 |
| --- | --- | --- |
| Test 실패, 느린 render, 어려운 구현 | 원인 조사·작은 수정·다른 유효 경로 | 계속 진행, 미완료 |
| 불명확한 optional cut | 정해진 횟수 내 보정 후 keep/restore | 다른 필수 작업 계속 |
| 기반 sync/원본/capability 실패 | 명확한 실패 범위 기록, 대체 근거·도구 검증 | 해결 전 성공 불가 |
| 새로운 유료 API·권한·입력 필요 | 필요한 정보와 대안을 구체화해 질문; 독립 작업 계속 | 의존 작업만 대기 |
| Token/계정 한도·외부 budget 소진 | Checkpoint와 남은 AC 보존, 현황 기록 | 예산 소진은 성공 아님 |
| 필수 AC 전체 PASS, 별도 감사·전달 완료 | 마지막 변경 뒤 평가 결과를 확인 | Goal complete |
| 사용자가 아직 최종본을 안 봄 | READY_FOR_OWNER 보관 | AC를 모두 만족했다면 goal 완료 가능; OWNER_ACCEPTED는 pending |

제품의 `BLOCKED`, 개별 command 실패, Codex goal의 blocked 상태를 구분한다. Codex goal 상태 변경은 해당 세션의 실제 tool 규칙을 따른다. 한 번의 오류나 재시도 횟수만으로 goal을 blocked로 종료하지 않는다. 현재 goal tool 계약처럼 동일 외부 장애가 연속 turn에 걸쳐 재발하고 유용한 독립 작업도 남지 않은 경우에만 허용된 blocked 전환을 사용한다.

권한·한도·네트워크 문제를 우회하거나 goal을 새로 만들어 사용량을 초기화하지 않는다. 단순히 실패 보고서를 잘 작성했다는 이유로 원래 구현 목표를 complete로 바꾸지 않는다.

## 8. 계획 변경 권한과 기준 유지

Agent는 구현 파일 배치, dependency 최소화, 알고리즘, PR 경계, 실행 순서와 측정 방법을 합리적으로 바꿀 수 있다. 이유와 전후 결과를 ADR에 남긴다. 특정 라이브러리를 사용했다는 것 자체는 성공 조건이 아니다.

다음은 사용자 재정렬 없이 바꿀 수 없다: 실제 DGIST 검증 생략, screen/frame 요구 완화, 의미 손상을 허용하는 편집, 필수 AI modality/coverage 제거, 최종 승인 역할 조작, 비용·게시 권한 확대. 이러한 변경은 구체적 근거와 대안을 준비한 뒤 질문한다.

검사기의 bug를 수정하거나 오탐을 해소할 수는 있다. 다만 실패를 지우기 위해 threshold·severity·expected label을 바꾸지 않는다. 계약에 영향을 주는 수정은 version과 이유·별도 검수·새 평가 결과를 남긴다. 품질 기준을 실질적으로 완화하는 변경은 사용자 판단 대상이다.

## 9. 최종 전달 형식

Goal 종료 전에 실제 파일을 열거나 probe하여 경로와 hash를 확인한다. 사용자에게 다음을 간결히 제공한다.

1. 최종 DGIST MP4의 절대 경로와 재생 가능한 링크.
2. `READY_FOR_OWNER` 평가 보고서 및 최종 source/plan/timeline/output hash.
3. 적용 컷·복원·유지한 불확실 구간, coverage, sync 측정, 미해결 사항의 실제 수치.
4. 설치·실행·재검수·restore·resume 명령과 code commit, 테스트 결과, 지원 제한.
5. Codex goal과 외부 AI 사용량·비용 중 실제 확인 가능한 값. 미확인 값은 추정과 분리.
6. 사용자 최종 확인은 pending이라는 표시. 사용자가 나중에 수정 요청하면 기존 project/revision으로 이어갈 수 있어야 한다.
7. 코드의 PR·merge commit·tag/release 링크와 공개 범위 확인 결과. Video 파일 자체의 공개 링크를 만들지 않는다.

목표 달성 후에도 가치가 있어 보인다는 이유로 자막·GUI·다른 강의·서비스 운영을 자동 확장하지 않는다. 완성한 목표와 후속 아이디어를 분리한다.
