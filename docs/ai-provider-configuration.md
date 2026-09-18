# AI provider and model configuration

## Milestone boundary

This is the first M2 foundation slice while the project remains in the latter
part of M1 overall. It configures provider endpoints, credential references,
model identities, and bounded purpose routes. It does not execute prompts or
run a LangGraph investigation.

The administration UI is available at `/settings/ai`. The API surface is:

```text
POST /api/v1/credential-profiles
POST /api/v1/ai/providers
GET  /api/v1/ai/providers
PUT  /api/v1/ai/providers/{provider_id}
POST /api/v1/ai/providers/{provider_id}/health
POST /api/v1/ai/models
GET  /api/v1/ai/models
POST /api/v1/ai/routes
GET  /api/v1/ai/routes
```

## Secure configuration flow

1. Add the provider hostname to `ICHECK_AI_ALLOWED_HOSTS`. Exact hostnames and
   `*.example.internal` wildcards are supported.
2. Put the real provider token in the API service environment, for example
   `ICHECK_AI_PROVIDER_TOKEN`. Do not put its value in an API request.
3. Create an environment credential profile whose reference is
   `env://ICHECK_AI_PROVIDER_TOKEN` and whose allowed adapter is `ai_provider`.
4. Create an OpenAI-compatible provider with that credential profile name or ID.
5. Run the provider health check. It calls the bounded `/models` endpoint and
   persists only status, model count, a redacted error, and audit metadata.
6. Register model profiles and bind each task purpose to a primary model plus
   iteration, tool-call, timeout, and token budgets.

Supported authentication modes are `none`, `bearer`, and `api_key`. The latter
uses the fixed `X-API-Key` header. Provider requests reject credentials embedded
in URLs, query strings, fragments, redirects, unapproved hosts, oversized
responses, and invalid OpenAI-compatible model-list envelopes.

## Current limitations

- The environment resolver is the only active server-side secret provider.
  Vault, cloud KMS/secret managers, and rotation workflows remain open.
- Provider health checks validate `/models`; prompt/inference calls are not yet
  implemented.
- Routing budgets are persisted policy inputs. LangGraph does not consume them
  until the InvestigationState, Tool Registry, policy gate, and checkpoint
  runtime are implemented.
- User/RBAC enforcement is still an M1 production gate; the current UI uses the
  provisional audit actor `platform.admin`.
