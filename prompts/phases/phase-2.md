# Phase 2: Local LLM

## Implement

- LocalLLMProfile fixed to `chat_completions` wire API
- Model/tokenizer/chat-template/structured-output/profile digests
- Mission revision and capability-result binding
- Pydantic AI strict typed Planner/Analyzer outputs
- Canary capability check for nested models, enum, optional, list and discriminated union
- Native structured output and validated fallback mode
- Validation retry budget max 3, independent from HTTP/LangGraph retry
- Timeout, cancellation and fail-closed profile mismatch
- Prompt/data separation and raw-tool-output prompt injection defense

## Test

- Capability pass/fail and unsupported-mode behavior
- Unknown fields/coercion/duplicate keys/invalid output retry exhaustion
- Mid-mission model/wire/template/tokenizer/profile change rejection
- Mock profile cannot be used for real-LLM mission
- Only redacted, authorized context reaches LLM
- Prompt injection strings remain data and cannot change policy/tool/goal behavior

Local inference may be used only through the configured loopback/isolated endpoint. Do not make cloud LLM a runtime dependency of the product.
