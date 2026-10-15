# Multi-provider AI setup

**Deployed in r19.26 on 15 October 2026 (Asia/Hong_Kong)** after protected
database/configuration backups, migration and paired backend/GUI restart.
The Agent worker now advertises `openai_compatible,mcp,anthropic`. Existing
OpenRouter encrypted credentials, models and routes were verified unchanged.
No paid account inference was performed. See the
deployment record (private development evidence; not distributed).

## Guided configuration

Open **AI providers and routing → Guided AI provider setup** (`/settings/ai`).

| Provider | Fixed guided endpoint |
| --- | --- |
| OpenRouter | `https://openrouter.ai/api/v1` |
| OpenAI | `https://api.openai.com/v1` |
| Anthropic Claude | `https://api.anthropic.com/v1` |
| Google Gemini | `https://generativelanguage.googleapis.com/v1beta/openai` |
| DeepSeek | `https://api.deepseek.com` |
| Qwen — Beijing | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| Qwen — Singapore | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` |

1. Create a connection, select a provider, enter its API key and approve the
   displayed HTTPS endpoint. Protocol and authentication are filled by iCheck.
   Saving encrypts the key; it makes no inference or route changes. Switching
   providers clears the unsaved key and consent. Existing provider identity is
   immutable; use a separate connection for another provider/account.
2. **Verify key and discover models** reads the account catalog. OpenRouter
   retains its inference-key and advertised structured-output checks. Other
   catalogs are candidates, not a claim that every listed model works in iCheck.
3. Select a model and approve **Test model inference**: one fixed-input request,
   up to 512 output tokens, no inventory data or operational tools. Provider
   charges may apply. Valid Agent-schema output and usage metadata are required.
4. Select uses and save. Existing selected routes and their fallback lists are
   replaced only with explicit consent; other routes and old models remain.

Consumer subscriptions are not API credentials. Qwen keys must match the chosen
region. These presets use documented legacy regional endpoints; workspace-specific
Qwen URLs need Advanced configuration and administrator host allowlisting. Azure
resource endpoints, AWS Bedrock and Vertex AI are not guided integrations.
Self-hosted OpenAI-compatible servers such as Ollama/vLLM can use Advanced setup.
No current model names are guessed or hard-coded; test the chosen model first.

## The four Advanced sections

**Secret reference → Provider endpoint → Model profile → Purpose route.** Guided
setup creates these records automatically. Most users can leave Advanced closed.

| Section | Purpose and use |
| --- | --- |
| Token secret reference | A pointer, not the key. `env://ICHECK_AI_PROVIDER_TOKEN` names a server environment variable; `vault-kv2://kv/ai/primary#token` names a KV v2 field; `vault-dynamic://ai/creds/runtime` names a supported lease path. Administrators must provision the value and server access first. This form does not create variables or configure Vault. Automatically generated `managed-ai://` references are bound to one guided connection and must not be reused. |
| Provider endpoint | Where/how requests go: API protocol, base URL, authentication and external credential reference. Select OpenAI-compatible or native Anthropic. Custom hosts must be administrator-allowlisted. One provider can expose several models. |
| Model profile | Exact provider API model ID, local display name and capabilities. Registering capabilities is not a live test or quality score. Use guided discovery/testing for managed connections. |
| Agent-loop route | Which model handles a purpose: `investigation` serves AI Operator, alert investigations and dashboard AI; `capability.authoring` serves Studio. One primary and optional ordered fallbacks are tried on eligible failures, not in parallel. A new purpose name does not create a feature or workflow. |

Provider timeout limits one model request; route timeout limits the task.
Iteration, tool-call and token budgets bound execution, not an exact currency
bill. Cost class is a selection-policy label, not a price quotation. Privacy tier
and data residency are declared policy metadata, not proof of vendor location or
an automatic compliance guarantee. Remove/Restore retains history and does not
recover deleted external secrets or reapprove disabled outbound access.

## Runtime and migration

One shared transport adapter serves probes, Agent reasoning and Studio.
OpenRouter behavior is retained. Direct OpenAI uses `max_completion_tokens`;
Gemini uses its compatibility API. iCheck's open dictionaries are not falsely
advertised as strict-subset schemas. DeepSeek and direct Qwen use JSON mode,
the full schema in the prompt and local validation. Direct Qwen disables thinking
for this contract. Claude uses native Messages, `X-API-Key` and a version header;
one `icheck_structured_result` tool envelope carries JSON, not an executable IT
operation. Missing, unexpected, multiple or truncated results fail validation;
valid reported usage remains accounted on failure. IT/MCP calls still pass through
the existing authorization and tool-budget checks. A small probe does not prove
reasoning quality or every larger Studio artifact schema will succeed.
Native Claude custom parameters currently support temperature, top_p and top_k;
unsupported custom parameters fail locally instead of being silently ignored.

The new human-admin/CSRF-protected API is `/api/v1/ai/managed/*`. The old
OpenRouter API remains compatible. New guided configuration requires a successful
probe receipt and a current configuration hash. Direct presets cannot bypass
these checks through the old API. Fixed-origin approval does not enable global
egress, redirects or ambient proxies. No new provider SDK dependency is added.

Migration `a4g6i8k0m2p5`, after `z3f5h7j9l1n4`, extends only the managed preset
constraint. Ciphertext, AAD, revisions, approvals, models and routes are retained.
PostgreSQL RLS and immutable binding triggers remain active. Downgrade refuses
to discard non-OpenRouter key custody. Deploy frontend/backend together, migrate,
and add `anthropic` to existing explicit Agent worker capability lists. These
steps are complete on the preview server; new native installation defaults also
include it. Offline tests include provider contracts, SQLite and a temporary
PostgreSQL full-chain migration; paid-provider qualification remains opt-in.

Live checks cover seven preset endpoints, the four Advanced help sections,
authenticated API reads, preserved key custody and refreshed Worker capability.
The default guided page fits a 390px viewport. Expanding Advanced with the real
retained configuration causes horizontal overflow at that width; this is a
recorded layout limitation, not a failed provider connection or a completed fix.

Official references checked:
[OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create),
[Claude tool-use responses](https://platform.claude.com/docs/en/agents-and-tools/tool-use/parallel-tool-use),
[Gemini compatibility](https://ai.google.dev/gemini-api/docs/openai),
[DeepSeek JSON output](https://api-docs.deepseek.com/guides/json_mode/),
[Qwen structured output](https://www.alibabacloud.com/help/en/model-studio/qwen-structured-output),
[Qwen regional endpoints](https://www.alibabacloud.com/help/en/model-studio/compatibility-of-openai-with-dashscope).
