# AI provider and model configuration

## Milestone boundary

This is the governed configuration boundary for the M2 runtime while production
M1 identity and credential-provider gates remain open. It configures provider
endpoints, credential references, model identities, ordered fallback, and
bounded purpose routes consumed by the LangGraph investigation worker.

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
6. Register model profiles with `chat` and `json_schema` capabilities.
7. Bind each task purpose to a primary model, zero or more ordered fallback
   models, and iteration, tool-call, timeout, and token budgets.

Supported authentication modes are `none`, `bearer`, and `api_key`. The latter
uses the fixed `X-API-Key` header. Provider requests reject credentials embedded
in URLs, query strings, fragments, redirects, unapproved hosts, oversized
responses, and invalid OpenAI-compatible model-list envelopes.

When an investigation is created, it snapshots the primary and fallback IDs as
well as every execution budget. Runtime fallback therefore cannot be changed by
later route edits. Retryable candidate failures are individually audited and
the successful decision is charged for the cumulative provider-reported tokens
across failed and successful candidates. Request-size and investigation-deadline
failures stop immediately rather than trying another provider.

## Current limitations

- The environment resolver is the only active server-side secret provider.
  Vault, cloud KMS/secret managers, and rotation workflows remain open.
- Provider health checks validate `/models`; the automated inference and
  fallback suites use controlled OpenAI-compatible gateways. Live-provider
  compatibility and fallback acceptance remain open.
- Persistent principals, roles, token authentication, and investigation
  permission snapshots are implemented. Browser OIDC/session integration and
  authorization on every AI-settings route remain M1 production gates; the
  development UI still submits the provisional audit actor `platform.admin`.
