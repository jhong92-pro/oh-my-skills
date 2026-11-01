---
name: source-to-docx
description: 폴더의 소스 파일을 내부망 반입용 docx 하나로 묶습니다. 슬래시 명령으로만 실행합니다.
disable-model-invocation: true
argument-hint: "[폴더 경로]"
allowed-tools: Bash(python3 "${CLAUDE_SKILL_DIR}/scripts/source_to_docx.py" *)
---

!`python3 "${CLAUDE_SKILL_DIR}/scripts/source_to_docx.py" --base "${CLAUDE_PROJECT_DIR}" $ARGUMENTS`

위 실행 결과만 사용자에게 그대로 전달합니다. 파일을 읽거나 수정하는 등 다른 작업은 하지 않습니다.
