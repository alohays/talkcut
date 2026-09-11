# DGIST 첫 강의 편집 검수·출하 프로토콜

| 항목 | 계약 |
| --- | --- |
| 상태 | 구현할 검증 계획. 검사기·AI 검수·품질 게이트는 아직 구현되지 않았다. |
| 작성일 | 2026-09-07 |
| 상위 계획 | [RFC 0001](../plans/0001-dgist-first-lecture.md) |
| 목표 평가 | [RFC 0002의 AC01–AC13](../plans/0002-autonomous-goal-contract.md) · G0–G5 외에 기능·복구·공개 코드 release까지 평가 |
| 대상 | 등록한 DGIST 원본, 특정 편집 revision, 특정 최종 출력 hash |
| 사용자 참여 | 중간 후보 승인 없이 진행. 사용자는 완성된 최종본만 나중에 확인한다. |
| 기본 원칙 | 엄격한 자동 검사와 AI 검수, 불확실한 삭제의 유지·복원, 역할별 판정 분리 |

## 1. 검수가 보장하는 범위

이 문서는 검증할 항목, 필요한 증거, 실패 처리와 완료 상태를 정의한다. 현재 기능이 동작하거나 DGIST 영상이 통과했다는 보고서가 아니다.
수치·창 길이·재시도 횟수는 초기 실험을 위한 제안값이다. 공인 방송 규격이나 검증된 지각 품질 임계치로 표현하지 않는다.
구현 중 관측한 변경 근거와 정책 revision을 남기고, 기준을 낮춰 기존 실패를 통과시키지 않는다.
삭제율, 빠른 렌더, 모델의 높은 자신감은 의미 보존과 정확한 동기화의 증거가 아니다.
모든 검사는 `PASS / FAIL / UNVERIFIED` 중 하나와 실제 검사 범위를 기록한다.
미실행, 지원되지 않는 modality, 측정 불확실성 과다, 오래된 artifact는 `UNVERIFIED`다.
필수 검사에 해당하지 않는 항목은 적용 제외 사유를 기록한다. 필수 증거 부재를 적용 제외로 우회하지 않는다.

## 2. 검수 역할과 최종 상태

| 역할 | 책임 | 기록할 수 없는 판정 |
| --- | --- | --- |
| 제안 agent | 보호 구간과 편집 후보, 근거, 원본 범위 제시 | 자신의 제안만으로 검수 완료 |
| 반대 검수 agent | 별도 실행에서 원본·편집본을 비교하고 삭제의 위험을 먼저 찾음 | 사용자가 보았거나 승인했다는 기록 |
| 기술 검사기 | 시간·스트림·기하·decode·artifact 의존성을 결정적으로 검사 | 의미 보존의 최종 ground truth |
| workflow 실행자 | 실패 복원, 재렌더, 증거 취합, 상태 전이 | 미관측 자료에 대한 검수 서명 |
| 사용자 | 구현 완료 후 최종본을 보고 수락하거나 수정 요청 | 사전에 생성된 AI 명의 서명으로 대체 불가 |

제안과 반대 검수는 다른 실행·검수 지침·원장을 사용한다. 같은 모델이어도 가능하나 통계적으로 독립된 판단이라고 주장하지 않는다.
반대 검수는 먼저 원본 증거와 출력 내용을 판정하고 제안 사유를 대조한다. 제안자의 자신감 수치는 통과 근거에서 제외한다.
두 AI의 동의는 오류가 없을 확률이나 사람의 편집 승인을 의미하지 않는다. 오류가 공유될 가능성을 한계로 기록한다.
모든 자동 검사·AI 검사와 복구를 완료한 동일 출력은 `READY_FOR_OWNER`가 된다.
`OWNER_ACCEPTED`는 사용자가 그 최종 출력 hash를 확인하고 수락한 뒤에만 기록한다.
사용자의 시청 범위·속도를 알 수 없으면 추정하지 않는다. 단순 수락과 전체 시청 확인은 별도 필드다.
사용자가 나중에 확인하는 동안에도 준비된 산출물은 유효하게 보관하며, 중간 후보 승인을 요청하지 않는다.
기술적 문제로 준비 게이트를 충족할 수 없으면 `BLOCKED`와 구체적 실패 보고서를 남긴다. 사용자 침묵은 승인이 아니다.

## 3. 출하 게이트와 우선순위

P0는 의미 유실, 잘못된 시간축, 원본 훼손, 추적 불가처럼 결과를 신뢰할 수 없게 하는 문제다.
P1은 가독성 가림, 잘린 음절, 새 클릭음, 미검증 구간 등 정상적인 강의 시청을 방해하는 문제다.
P2는 사용성을 해치지 않는 보고서·진단 개선 사항이며, 등급을 내리면 이유와 검수자를 기록한다.

| Gate | 필요한 증거 | 통과 조건 |
| --- | --- | --- |
| G0 입력 | source hash, 영속 참조, 실제 stream 선택, 전체 decode/PTS | 필요한 원본의 정상 범위 확인; 미확인 입력 0 |
| G1 기준 | 음원 선택, offset/drift/lip sync, 컷 없는 전체 합성본 | 필수 동기화·레이아웃 항목 PASS |
| G2 편집 | 보호 구간, 원본 삭제 구간 전체, 반대 검수, 복원 | 위험·분쟁 컷 유지 또는 복원; 적용된 모든 컷 검수 |
| G3 출력 | 실제 master 전체 decode, 시간·오디오·화면 검사 | 필수 기술 검사 PASS |
| G4 AI 검수 | 모든 삭제·seam·전체 출력 창의 시청 증거와 판정 | 필수 coverage 100%; 미검증 항목 0 |
| G5 최종 준비 | 같은 hash의 G0–G4, 유효 원장, 열린 이슈 | 미해결 P0/P1 0; `READY_FOR_OWNER` |
| G6 사용자 확인 | 사용자의 해당 최종본 수락 | `OWNER_ACCEPTED`; AI 판정으로 사용자 결정을 대체하지 않음 |
| G7 OSS alpha | 공개 fixture, clean install, CI·문서·지원표, 재현·복구 | 공개 준비 완료; 일반화 평가는 16절의 별도 holdout |

G5와 G6는 다른 완료 조건이다. 구현·자동 검수가 끝났다는 보고는 G5로 가능하며 사용자의 최종 수락을 선취하지 않는다.
어떤 필수 검사도 전체 평균 점수로 상쇄하지 않는다. 99% coverage와 알려진 한 구간의 미검증은 통과가 아니다.

## 4. 검사 순서와 기준 영상

1. 원본을 보존하고 hash를 고정한 뒤 전체 입력의 decode·PTS·stream coverage를 확인한다.
2. 선택한 단일 오디오와 화면·speaker의 시간 관계를 측정한다. 보정 전·후 증거를 모두 남긴다.
3. 컷 없는 전체 합성 baseline을 만든다. 먼저 합성과 동기화가 맞는지 자동 검사와 AI로 검수한다.
4. 명시적 시험 컷 하나에 적용→A/B→실제 출력→복원→재실행을 수행해 편집 기반을 확인한다.
5. 제안 agent가 근거 있는 후보와 보호 구간을 만들고, 반대 검수 agent가 후보별로 판정한다.
6. 허용된 컷으로 전체 후보를 렌더하고 모든 삭제·seam·출력 창을 검수한다.
7. 문제를 수정·복원하고 영향받은 증거를 무효화한 뒤 재검사한다. 최종 출력은 전체 범위를 다시 감사한다.
8. `READY_FOR_OWNER` 묶음을 생성한다. 사용자에게는 최종본·간결한 변경 요약·검수 결과를 제공한다.

기존 합성본은 비교 자료이며 자동 정답이 아니다. 원본→컷 없는 baseline은 합성, baseline→편집본은 편집 효과를 비교한다.
모든 review clip은 실제 적용 경계와 시간 매핑을 사용한다. 최종 seam 검수는 실제 master에서 추출한 클립을 사용한다.

## 5. 동기화의 측정 계약

초기 offset, 시간에 따른 drift, 선택 오디오와 입 모양의 관계를 별도로 검사한다.
소스의 PTS·time base·공유 origin을 보존하고 `lecture_time = rate × source_time + offset`의 부호를 명시한다.
duration 일치, 같은 nominal fps, audio 상관관계만으로 video나 lip sync가 맞다고 결론 내리지 않는다.
같은 실제 사건을 비교해야 한다. 슬라이드 변경과 그 내용을 말하는 시점의 자연스러운 차이는 offset 앵커가 아니다.
최소 시작·중간·끝과 10분 이하 간격에 앵커를 둔다. 불연속·녹화 재개·mapping 변경점은 앞뒤를 추가 검사한다.
맞춤에 사용한 앵커와 검증용 앵커를 구분한다. 불연속을 한 개 선형 drift 식으로 숨기지 않는다.

| 측정 | 잠정 목표 | 한계와 실패 처리 |
| --- | --- | --- |
| 같은 사건의 audio 정렬 잔차 | 각 검증 앵커에서 `abs(residual) + uncertainty <= 20 ms` | 같은 음향 사건을 확인할 수 없으면 해당 증거 UNVERIFIED |
| 선택 audio와 speaker 입 모양 | `abs(residual) + uncertainty <= 80 ms`, `uncertainty <= 40 ms` | 입이 작거나 가려져 측정 불가하면 확대 원본·대체 앵커로 재측정 |
| 보정 후 drift 변화량 | 앵커 간 시간차 변화의 상한이 1 local frame 이하, 최대 40 ms | 양 끝 앵커의 frame duration 중 작은 값 사용; 긴 gap은 별도 결함 |
| 영상 경계 적용 오차 | 실제 frame edge와 요청 경계의 차이 1 local frame 이내 | 발화·보호 구간을 침범하면 수치 이내여도 컷 복원 |
| 오디오 경계 양자화 | 기준 PCM의 누적 절대 경계에서 1 sample 이내 | codec priming/padding과 실제 유효 sample 구간을 분리 |

`uncertainty`는 분석기의 confidence 점수가 아니다. frame/sample 해상도, 이벤트 표시 오차, 측정 반복 차이를 근거로 한 시간 오차 상한이다.
오차 상한을 합리적으로 산정할 수 없으면 숫자만 채워 통과시키지 않는다. 허용치 변경은 실험과 정책 revision을 요구한다.
Drift는 위 게이트와 함께 ms/hour와 강의 전체 예상 시간차를 보고한다. 시작·끝만 맞아도 중간 잔차가 크면 실패다.
Speaker 원본 확대는 검사용이다. 최종 출력의 speaker를 임의 crop하거나 얼굴 위주로 바꾸지 않는다.
AI가 음성을 듣지 못하거나 시간별 입 모양을 볼 수 없는 환경이면 lip sync 검수를 완료할 수 없다.
출력에서도 검증 앵커와 모든 seam 주변을 재확인한다. 소스에서 맞았다는 이유로 출력 sync를 통과시키지 않는다.

## 6. 화면 구성과 오디오 품질

- Screen의 전체 프레임·원본 캔버스·표시 종횡비를 유지한다. crop, stretch, screen 축소, 장식 여백을 금지한다.
- Speaker 전체 프레임과 종횡비를 유지한 작은 우측 상단 overlay를 사용한다. 크기·여백은 검증 후 고정한다.
- 중요한 설명·코드·수식·자막·커서 동작 가림은 0건이어야 한다. 배경 일부를 덮는 것과 구분한다.
- 모든 슬라이드 상태, 앱 전환, 스크롤, 데모, 질문 장면을 검사한다. 대표 한 장의 프리뷰로 전체를 승인하지 않는다.
- OCR과 가림 영역 검출은 후보 탐지다. 글자를 찾지 못했다는 이유로 해당 영역이 비었다고 판단하지 않는다.
- 우측 상단 안에서 크기·여백을 조정해 해결하고, 해결할 수 없으면 layout conflict로 차단한다.
- Speaker가 먼저 끝나는 경우 명시한 screen-only 구간을 검수한다. 마지막 프레임 고정이나 강의 조기 종료로 숨기지 않는다.
- 검증한 오디오 소스 하나만 사용한다. 같은 프로그램 음원이 여러 파일에 있다고 중복 혼합하지 않는다.
- 원본에 없는 음성 누락·click·clipping·불연속을 허용하지 않는다. 원본 결함은 출처와 영향 범위를 분리해 기록한다.
- Denoise·compressor·normalization은 필요한 증거 없이 추가하지 않는다. 추가하면 처리 전후 전체 영향 범위를 검수한다.

## 7. 삭제 구간과 편집 경계의 전수 검수

모든 실제 삭제 구간을 100% 검사한다. 정책상 자동 적용된 강의 전 구간과 무음도 포함한다.
원본 A는 삭제 구간 전체와 앞뒤 최소 5초 및 완결된 앞뒤 문장을 포함한다. 문맥이 부족하면 범위를 늘린다.
긴 demo·질문·읽기 시간은 해당 활동이 끝날 때까지 확인한다. 삭제 구간의 처음과 끝만 본 것을 전체 검수로 기록하지 않는다.
편집본 B는 실제 master의 연결부와 앞뒤 문맥을 포함한다. 모든 seam에서 오디오와 frame 양쪽을 확인한다.
제안 agent와 반대 검수 agent의 실행 ID, 실제 입력 clip hash, 재생 범위와 판정을 각각 남긴다.
원본·편집본·transcript의 의미를 비교하되, transcript는 청취·시각 검토를 보조한다. ASR에 없는 음성도 삭제 보호 대상이다.

| 후보 | 필요한 긍정 근거 | 보존해야 하는 반례 |
| --- | --- | --- |
| 강의 전 준비 | 첫 실질 설명 이전임을 원본 문맥·음향·화면으로 확인 | 소개, 목표, 과제 안내, 첫 질문 |
| 긴 무음 | 비발화와 문맥 확인, 보호 구간 불교차, 학습 활동 아님 | 무음 demo, 실행 대기, 읽기, 학생 응답, 강조 |
| 말더듬·반복·재시작 | 삭제 전후 명제·대상·조건·강조가 유지되고 경계가 자연스러움 | 부정, 수치·단위 정정, 정의 갱신, 강조 반복 |

한국어 조사·어미, 연결 발음, 영어 기술어, code identifier와 숫자 발화를 별도 위험 항목으로 본다.
“A가 아니라 B”에서 A를 잘라 부정의 대상을 잃거나, 재시작을 잘라 주어·조건을 잃으면 실패다.
침묵의 길이, 움직이지 않는 slide, 빈 transcript, 높은 모델 confidence는 단독 삭제 근거가 아니다.
반대 검수가 의미 보존·호흡·경계에 이견을 내거나 자료가 부족하면 유지 또는 복원한다. 중간 사용자 결정을 기다리지 않는다.
검수 통과는 `ai_review_pass`이며 `human_approved`가 아니다. 허용된 정책에 따른 적용과 검수 결과를 별도 기록한다.

## 8. 전체 출력의 겹치는 창 기반 AI 감사

첫 기본값은 30초 창, 인접 창 5초 겹침이다. 시작·끝까지 빠짐없이 덮으며 실제 모델 입력 한도에 맞춰 더 작게 나눌 수 있다.
각 창은 실제 최종 출력의 연속 audio와 시간 정보가 있는 video를 포함한다. transcript만 입력하는 경로는 이 게이트를 충족하지 않는다.
도구가 해당 video·audio 입력을 실제 지원하고 분석에 사용했는지 capability와 실행 결과를 확인한다. 파일 첨부 성공만으로 시청 완료로 간주하지 않는다.
오디오와 정지 이미지밖에 못 보는 경로는 연속 동작·입 모양 검사에 필요한 증거를 추가해야 한다. 확보 불가하면 해당 검사는 UNVERIFIED다.
Provider의 내부 frame sampling이나 축약 때문에 관측 범위를 알 수 없으면 한계를 남긴다. 모든 frame을 보았다고 주장하지 않는다.
빠른 코드·커서·slide 전환, 모든 seam, 의심되는 freeze·lip sync 구간은 원본 해상도와 필요한 frame 밀도로 별도 재검사한다.
연속 창 감사는 구조적 누락을 막는 절차이며 AI가 모든 의미를 이해했다는 증명은 아니다. 컷별 원본 검수를 병행한다.
최종 수정 뒤의 최종 hash에 대해 전체 창 감사를 수행한다. 중간 반복에서는 영향받은 창을 우선 검사할 수 있다.

각 창의 필수 응답은 `확인한 범위`, `모달리티`, `문제 시각`, `원본 비교 필요 여부`, `판정`, `근거`다.
“문제 없음” 한 문장, 빈 응답, 잘못된 시각, 입력을 볼 수 없다는 응답은 PASS로 정규화하지 않는다.
이웃 창의 사건·발화 연속성과 시간 순서를 대조한다. 창 경계에서 발견된 의심은 두 창을 합쳐 재검사한다.
전체 감사를 비용상 완료하지 못하면 남은 범위와 비용을 보고하고 준비 상태를 차단한다. 조용히 샘플링 검수로 강등하지 않는다.

## 9. Coverage와 품질 보고

Coverage는 요청 수가 아닌, 검증 가능한 artifact를 실제 검사해 유효한 결과를 받은 범위로 계산한다.
겹치는 창의 초를 중복 합산하지 않는다. 각 지표의 분모·분자·제외 이유·미검증 구간을 함께 저장한다.

| 지표 | 분모·분자 | G5 기준 |
| --- | --- | --- |
| 삭제 구간 건수 | 실제 적용된 삭제 수 / 전체 검수 완료된 삭제 수를 별도 저장 | 검수 완료 건수 ÷ 적용 건수 = 100% |
| 삭제 원본 시간 | 삭제된 source interval union / 검수한 해당 union | 검수 시간 ÷ 삭제 시간 = 100% |
| Seam | 생성된 모든 경계 / audio+frame 검수 완료 경계 | 100% |
| 출력 audio coverage | 출력의 유효 audio 시간 / 실제 청취 분석 창 union | 100% |
| 출력 video 감사 coverage | 출력의 유효 video 시간 / 적합한 modality로 감사한 창 union | 100%; 실제 frame 관측량은 별도 보고 |
| 보호 구간 침범 | 실제 적용 경계와 보호 구간 교집합 | 0건 |
| 필수 sync 앵커 | 계획한 검증 앵커 / 유효하고 통과한 앵커 | 100% |
| 미해결 문제 | P0/P1의 FAIL·UNVERIFIED·stale·미완료 | 0건 |

삭제나 seam이 0개이면 분모 0과 “해당 없음”을 기록한다. 이를 100% 편집 검수 성공 사례로 과장하지 않는다.
실측 전에는 모든 값이 null/미측정이다. 목표값을 결과 칸에 미리 채우지 않는다.
False cut, 복원 수, 유지된 불확실 후보, 누락된 불필요 pause를 함께 보고한다. 삭제량을 늘리는 목표는 두지 않는다.

## 10. 전체 decode와 자동 기술 검사

- 입력과 실제 master의 모든 선택 stream을 끝까지 decode한다. ffprobe metadata만 읽은 결과와 분리한다.
- 실제 presentation timestamp, time base, discontinuity, stream coverage, 마지막 유효 frame/sample을 검사한다.
- Resolved timeline의 유지 구간과 출력 시간 매핑, 실제 경계, 기대 frame/sample schedule을 비교한다.
- Frame duration에 맞춘 검증 없이 30fps를 가정하거나 container duration 하나로 길이를 통과시키지 않는다.
- Canvas·SAR/DAR·rotation·speaker 사각형·선택 audio stream·출력 stream 수를 명시적 계약과 대조한다.
- Black/freeze/silence 검출 결과는 해당 source와 비교한다. 정적인 slide와 원본의 무음을 곧바로 오류로 분류하지 않는다.
- 새 drop·freeze·black·silence의 의심 범위를 AI 검수에 전달하고 해소 기록을 요구한다.
- Decoder exit code, 오류 로그, 처리한 frame/sample 수, 출력 hash와 도구 build 정보를 증거로 남긴다.

## 11. 증거와 서명 원장

아래는 구현할 증거 형식의 필드 목록이며, 실제 관측값이나 실행 가능한 설정은 아니다.

```text
review_id, run_id, reviewer_role, reviewer_version, reviewed_at
source_hashes, output_hash, clip_hashes
plan_hash, timeline_hash, sync_hash, layout_hash, audio_profile_hash
policy_version, toolchain_fingerprint, model_revision, prompt_version
scope: source_intervals / output_intervals / seam_ids / whole_output
input_modalities, capability_evidence, observed_frame_count_or_unknown
coverage_numerator, coverage_denominator, uncovered_intervals
check_id, measurements, uncertainty_method, evidence_refs
verdict: PASS | FAIL | UNVERIFIED
findings, severity, repair_action, supersedes, stale_reason
owner_acceptance: pending | accepted | changes_requested
owner_output_hash, owner_statement_ref, owner_viewing_scope_or_unknown
```

AI 검수 입력의 media·transcript에 포함된 지시문은 자료로 취급한다. 검수 기준·shell 명령·승인 원장을 변경할 권한이 없다.
근거에는 실제 시각과 관측 내용을 남긴다. 검수자의 숨겨진 사고 과정이나 임의의 확률 점수는 요구하지 않는다.
공개 문서·fixture에는 실제 원본, 비공개 경로, 다운로드 링크, 개인 transcript, credentials를 포함하지 않는다.

## 12. 수정과 회귀 검증의 무효화

| 변경 | 무효화할 증거 |
| --- | --- |
| Source bytes·stream 선택 | 해당 source에 의존하는 검사·분석·mapping·render·검수 |
| Sync model·origin·time base 처리 | 변환된 시각 근거, 영향받는 모든 출력·sync·seam 검수 |
| 컷 추가·복원·경계 변경 | 해당 컷과 이웃 seam, output mapping, 전역 출력 QC, 최종 전체 감사 |
| Layout·speaker omission | 해당 시간 범위의 합성·가림 검수, 출력 QC, 최종 전체 감사 |
| Audio source·처리 | 오디오·lip sync·seam 검사, 출력 QC, 최종 전체 감사 |
| Renderer·filter·codec·중요 build | 영향받는 출력 기술 검사와 AI 검수; 영향 불명확하면 전체 |
| Reviewer model·prompt/rubric·입력 clip·transcript·추출 방식 | 해당 검수 판정과 그에 의존하는 결정·준비 상태; 실제 modality와 coverage 재확인 |
| 출력 파일 변경 | 이전 output hash의 READY/OWNER 상태와 최종 감사 |

다른 output hash에 대한 기존 최종 서명을 이월하지 않는다. 재검수되지 않은 변경으로 `READY_FOR_OWNER`를 유지하지 않는다.
변하지 않은 source evidence는 직접 의존 hash가 같을 때만 재사용한다. 같은 파일명·candidate ID·시각만으로 재사용하지 않는다.
기존 전체 검수 기록은 보존하고 stale로 표시한다. 증거 삭제나 기록 덮어쓰기로 변경 이력을 숨기지 않는다.

## 13. 수정·복원과 제한된 반복

초기 한도는 후보별 경계 수정 2회, 동일 원인 기술 수정·재검사 3회다. 한도와 실제 시도를 원장에 남긴다.
불확실한 editorial 컷은 다수결로 강행하지 않는다. 유지 또는 복원한 뒤 새 seam과 전체 출력 검사를 수행한다.
반복해도 해결되지 않는 optional 편집은 포기하고 원본 구간을 남긴다. 결과가 덜 짧아져도 의미 보존을 우선한다.
동기화·decode·원본 부족·필수 modality 같은 기반 문제는 컷 복원으로 해결된 척할 수 없다. 한도 후 실패를 보고하고 BLOCKED로 둔다.
원인을 새로 확인해 다른 수정 경로를 시도하면 근거와 새 예산을 기록한다. 같은 실패를 무한 반복하거나 무제한 과금하지 않는다.
검사 실패 후에도 기존 성공 산출물과 원본을 유지한다. `.partial` 결과를 최종 파일로 승격하지 않는다.
최종 보고는 적용 컷 수·복원 수·남긴 불확실 구간·해결 못 한 문제를 실제 상태 그대로 제시한다.

## 14. 합성 fixture와 장애 주입

- 격자·모서리 표식·원·speaker 테두리·timecode·flash/beep로 기하와 동기화의 알려진 정답을 만든다.
- 33ms, 23.976/29.97fps, VFR, nonzero origin, 비정방형 픽셀, rotation, audio가 stream 0인 경우를 포함한다.
- Offset 부호, 선형 drift, 중간 불연속, speaker 조기 종료, 오디오 gap, AAC padding을 검증한다.
- 100개 이상 컷의 누적 경계, 인접·겹침·0길이·시작·끝·보호 구간 컷과 전체 복원을 property/integration test로 검사한다.
- 한국어·영어 혼용, 부정·수치·정정·강조·재시작·무음 demo·질문 대기의 허가된 발화 fixture를 둔다.
- SIGINT, subprocess 실패·timeout, disk-full 모사, corrupt JSON, source 교체, stale cache, 동시 revision 수정을 주입한다.
- Provider timeout, modality 미지원, 잘못된 시각·빈 응답·잘린 응답·예산 소진을 주입하고 UNVERIFIED 및 복구를 확인한다.
- 모든 실패에서 원본 불변, 이전 성공본 보존, partial 비승격, 명확한 재개 지점, 오래된 승인 거부를 확인한다.

짧은 fixture는 PR CI, 긴 drift·많은 컷·전체 파이프라인은 release 검사에 둔다. DGIST 비공개 자료를 public CI secret 의존성으로 만들지 않는다.
각 fixture는 “지원하여 올바른 출력” 또는 “지원하지 않아 명확히 거절” 중 기대 동작을 명시한다. 거절 테스트 통과를 해당 형식의 render 지원으로 보고하지 않는다.
DGIST 실제 검수에서 적어도 한 컷의 복원·재적용과 모든 관련 증거의 무효화·재생성을 확인한다.

## 15. 사람의 시간, 기계 시간과 비용

사람 시간은 설정·소스 확인·수동 작업·최종본 확인·수정 요청·복구에 실제로 쓴 시간을 기록한다. 중간 AI 실행 시간을 사람 검수 시간으로 합산하지 않는다.
사용자는 중간 검수 없이 최종본만 확인한다. 구현·자동 검수 완료와 사용자 최종 확인 시간은 별도 구간으로 보고한다.
AI 분석·반대 검수·전체 감사·재시도별 wall time, input/output 사용량, provider 비용, cache hit/miss를 기록한다.
Render/QC의 wall time, CPU/GPU 시간, peak memory, 임시 disk, output bytes를 따로 기록한다.
비용 한도는 실행 전 설정하고 실제 잔액을 검사한다. 한도 때문에 검사를 생략하면 READY 상태가 될 수 없다.
DGIST 새 구현 세션은 기존 연결된 AI 도구로 필요한 구간을 전송할 수 있다. 별도 유료 API는 사전 확인하며, Codex는 별도 token budget 없이 계정 한도·앱 설정을 따른다. 확인할 수 없는 잔액을 임의로 무한대나0으로 기록하지 않는다.
수작업 기준선이 없으면 절감률을 주장하지 않는다. 같은 기준·소스 범위의 수작업 실측이 있을 때만 비교한다.
부분 구간 기준선은 부분 구간 비교로 표시한다. AI 시청 시간을 사람의 전체시청 완료 시간으로 대신 쓰지 않는다.

## 16. DGIST 이후 OSS 품질 게이트

DGIST의 `READY_FOR_OWNER`와 사용자의 수락은 한 입력에 대한 결과다. 범용 강의 편집 정확도나 무오류를 보증하지 않는다.
일반화 시험 전 policy·threshold·코드를 고정하고 같은 강사의 미조정 강의 2편 이상과 다른 강사·녹화 조건의 허가된 holdout을 추가한다.
초기 목표는 최소 3편·총 3시간이며 실험 규모 제안이다. 짧은 영상만으로 숫자를 채우거나 통계적 일반화가 입증됐다고 쓰지 않는다.
Holdout도 모든 삭제·seam·전체 출력 AI 감사와 P0/P1 0건을 요구한다. 사람 정답 라벨이 있는 fixture와 사용자 확인 결과를 구분한다.
실패 영상을 조정에 사용하면 개발 자료로 재분류한다. 변경된 정책의 일반화는 새 holdout에서 다시 평가한다.
지원 OS·Python·FFmpeg 조합의 clean install, source→restore→master→QC 완주, 중단 복구와 문서 재현성을 확인한다.
자동 검사와 AI의 한계, 실제 coverage·오류·복원·시간·비용을 공개 가능한 집계로 보고한다. 미검증 성능을 홍보 문구로 바꾸지 않는다.

이 프로토콜의 작성 완료는 계획 산출물의 완료다. 실제 게이트 통과는 구현 후 특정 artifact의 증거와 역할별 기록으로만 성립한다.

## 17. Goal 평가기와의 연결

기능 구현 완료와 media 품질 통과는 [자율 목표 계약](../plans/0002-autonomous-goal-contract.md)에서 함께 평가한다. 실제 source 전체가 유지·삭제·명시한 결손 구간으로 빠짐없이 설명되는지 확인하고, 삭제·seam·출력 검수의 분모를 최종 artifact에서 계산한다. 입력창의 중복 합산, 누락한 후보, 다른 출력의 검수 재사용, 수기 PASS, 필수 검사 해제는 negative 평가에서 실패해야 한다.

G5는 최종 영상을 사용자에게 전달할 준비 상태다. 이 구현 goal은 여기에 기능·설치·복구·독립 감사와 코드 공개 release의 AC까지 추가해 판정한다. 사용자 최종 확인을 기다리며 goal을 무한히 유지하거나, 반대로 코드가 release됐다는 이유로 실제 DGIST 검수를 생략하지 않는다.
