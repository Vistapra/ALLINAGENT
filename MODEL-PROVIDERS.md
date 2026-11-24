# ALLINAGENT — LLM Model Providers Guide

**ALLINAGENT** uses an OpenAI-compatible unified model contract (`LLM_BASE_URL` + `CUSTOM_API_KEY` + `LLM_MODEL` / `DEFAULT_LLM_MODEL`) across **Hermes Agent (`v0.23.3`)**, **Paperclip (`v2026.1117.0`)**, **Unified Office Bridge**, and all **11 isolated corporate AI employee profiles (`pc*`)**.

---

## 1. Hardware Sizing Rule: Cloud API vs. Local Inference

> [!IMPORTANT]
> **2 vCPU / 8 GB RAM VPS Users — Always Use External API Inference:**
> On a **2 vCPU / 8 GB RAM** server (especially a multi-tenant VPS), ALLINAGENT's 6 containers operate inside a strict **`<= 1,536 MiB` (`1.50 GiB`)** physical RAM ceiling. Local LLM weights (`7B–14B` parameters via Ollama or vLLM) require **`6–16+ GB` of dedicated RAM/VRAM** and high memory bandwidth; running local LLM inference on a 2-vCPU / 8-GB CPU-only VPS will cause severe swap thrashing, 60–180s token latencies, and OOM kills.
>
> - **2 vCPU / 8 GB RAM VPS:** Use **OpenAI**, **OpenRouter**, **Google Gemini**, **Anthropic (via OpenRouter / OpenAI-compatible proxy)**, or a **remote GPU gateway**.
> - **Local Ollama / vLLM:** Use only on workstations or GPU servers with **`>= 16–32 GB RAM`** and/or a **discrete NVIDIA / Apple Silicon / AMD ROCm GPU (`>= 8–16 GB VRAM`)**, or run Ollama/vLLM on a separate GPU machine and point your 8 GB VPS's `LLM_BASE_URL` at it over HTTPS / Tailscale.

### Model Capability Requirements for Autonomous Engineering Agents

Because ALLINAGENT's 11 corporate roles perform multi-step tool execution (`file`, `terminal`, `skills`), structured JSON task updates, and code review:
- Choose models with reliable **OpenAI function / tool calling** support and at least a **`32k–128k` token context window**.
- Note: ALLINAGENT includes `patches/hermes-agent/0001-error-classifier-integrator.patch`, which teaches Hermes to classify upstream integrator routing errors (`"model_not_available_for_integrator"`, `"no endpoints found that support tool use"`) cleanly for graceful reporting and fallback handling.

---

## 2. Supported Provider Configurations (`.env` Examples)

Edit `<ALLINAGENT_ROOT>/.env` (or pass via environment variables to `./allinagent setup`), then synchronize worker secrets and restart:

```bash
./allinagent setup --yes --config-only
./allinagent up
```

---

### 2.1 OpenAI (Official API)

Direct first-party OpenAI inference with native tool calling and metered token pricing:

```dotenv
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
DEFAULT_LLM_MODEL=gpt-4o-mini
LLM_PROVIDER=openai
CUSTOM_API_KEY=<YOUR_OPENAI_API_KEY>
```

Recommended production models:
- **Fast / Cost-Efficient Default:** `gpt-4o-mini` or `gpt-4.1-mini`
- **Deep Architecture / Complex Engineering:** `gpt-4.1` or `gpt-4o`

---

### 2.2 OpenRouter (Multi-Vendor Unified Gateway)

OpenRouter provides a drop-in OpenAI-compatible endpoint giving ALLINAGENT access to OpenAI, Anthropic Claude, Google Gemini, DeepSeek, Qwen, and Llama tool-capable models behind a single key:

```dotenv
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_MODEL=anthropic/claude-3.7-sonnet
DEFAULT_LLM_MODEL=anthropic/claude-3.7-sonnet
LLM_PROVIDER=custom
CUSTOM_API_KEY=<YOUR_OPENROUTER_API_KEY>
```

Popular tool-calling models on OpenRouter:
- `anthropic/claude-3.7-sonnet` / `anthropic/claude-sonnet-4`
- `openai/gpt-4.1-mini` / `openai/gpt-4o-mini`
- `google/gemini-2.5-flash` / `google/gemini-2.5-pro`
- `deepseek/deepseek-chat`
- `qwen/qwen-2.5-coder-32b-instruct`

---

### 2.3 Anthropic Claude (via OpenRouter or OpenAI-Compatible Proxy)

Because ALLINAGENT standardizes worker profiles, Office Bridge chat turns, and Paperclip telemetry on the OpenAI `/v1/chat/completions` contract (`LLM_BASE_URL` + `CUSTOM_API_KEY`), connect **Anthropic Claude** models using either:

#### Option A — Via OpenRouter (Zero Extra Infrastructure)

```dotenv
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_MODEL=anthropic/claude-sonnet-4
DEFAULT_LLM_MODEL=anthropic/claude-sonnet-4
LLM_PROVIDER=custom
CUSTOM_API_KEY=<YOUR_OPENROUTER_API_KEY>
```

#### Option B — Via Anthropic's OpenAI-Compatible Endpoint or LiteLLM Proxy

Anthropic provides an OpenAI-compatible `/v1/` surface (or you can route via LiteLLM / Cloudflare AI Gateway):

```dotenv
LLM_BASE_URL=https://api.anthropic.com/v1
LLM_MODEL=claude-sonnet-4-20250514
DEFAULT_LLM_MODEL=claude-sonnet-4-20250514
LLM_PROVIDER=custom
CUSTOM_API_KEY=<YOUR_ANTHROPIC_API_KEY>
```

*(Note: For advanced direct Hermes CLI usage inside `allinagent-hermes`, Hermes `v0.23.3` also includes native `anthropic_adapter.py` support when `ANTHROPIC_API_KEY` is passed through.)*

---

### 2.4 Google Gemini (Official OpenAI-Compatible Endpoint)

Google AI Studio / Gemini API exposes an official OpenAI-compatible chat & tool-calling endpoint:

```dotenv
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
LLM_MODEL=gemini-2.5-flash
DEFAULT_LLM_MODEL=gemini-2.5-flash
LLM_PROVIDER=custom
CUSTOM_API_KEY=<YOUR_GEMINI_API_KEY>
```

Recommended Gemini models:
- **High-Throughput / Low-Cost:** `gemini-2.5-flash`
- **Heavy Codebase & Security Analysis:** `gemini-2.5-pro`

> [!NOTE]
> Keep `LLM_BASE_URL` without a trailing slash (`apps/office-bridge/contracts/paths.js` normalizes trailing slashes automatically).

---

### 2.5 Custom OpenAI-Compatible Endpoints (LiteLLM, vLLM Cloud, Azure/Enterprise Gateways)

Any self-hosted or enterprise gateway speaking `POST {LLM_BASE_URL}/chat/completions` with `Authorization: Bearer <CUSTOM_API_KEY>` works out of the box:

```dotenv
LLM_BASE_URL=https://llm-gateway.example.com/v1
LLM_MODEL=enterprise-coder-v1
DEFAULT_LLM_MODEL=enterprise-coder-v1
LLM_PROVIDER=custom
CUSTOM_API_KEY=<YOUR_API_KEY>
```

#### Cost & Telemetry Transparency for Unpriced Custom Models
When a custom gateway or model router does not return USD pricing metadata (`cost_usd: null`), ALLINAGENT's Analytics & Budget telemetry (`apps/office-bridge` & Virtual Office **Analytics** tab) honestly displays **`COST UNKNOWN` / `UNPRICED USAGE`** alongside exact prompt/completion token counts — never fabricating `$0.00` spend.

---

### 2.6 Optional Local Inference: Ollama & vLLM (GPU / High-RAM Hosts Only)

> [!WARNING]
> **Minimum Hardware for Local Inference:**
> - **`7B–8B` Q4_K_M tool-capable model (e.g. `qwen2.5-coder:7b`, `llama3.1:8b`):** `>= 16 GB` system RAM + `>= 8 GB` GPU VRAM (`32k` context).
> - **`14B–32B` coding/agentic model (recommended quality for 11-agent workflows):** `>= 32 GB` system RAM + `>= 16–24 GB` GPU VRAM.
> - **Do NOT run Ollama or vLLM on the same 2-vCPU / 8-GB VPS hosting ALLINAGENT.** Instead, run Ollama/vLLM on a dedicated GPU workstation/server and connect securely over HTTPS or Tailscale/WireGuard.

#### Connecting ALLINAGENT Containers to Ollama

1. Start Ollama on your GPU host and pull a tool-calling model:
   ```bash
   ollama pull qwen2.5-coder:14b
   ```
2. Configure `.env`:
   - **If Ollama runs on a separate GPU server on your Tailscale/private network:**
     ```dotenv
     LLM_BASE_URL=http://100.64.0.25:11434/v1
     LLM_MODEL=qwen2.5-coder:14b
     DEFAULT_LLM_MODEL=qwen2.5-coder:14b
     LLM_PROVIDER=custom
     CUSTOM_API_KEY=ollama-local
     ```
   - **If Ollama runs on the same `16+ GB RAM` workstation (Docker Desktop on Windows/macOS):**
     ```dotenv
     LLM_BASE_URL=http://host.docker.internal:11434/v1
     LLM_MODEL=qwen2.5-coder:14b
     DEFAULT_LLM_MODEL=qwen2.5-coder:14b
     LLM_PROVIDER=custom
     CUSTOM_API_KEY=ollama-local
     ```
     *(On native Linux Docker Engine, add `extra_hosts: ["host.docker.internal:host-gateway"]` to `hermes`, `paperclip`, and `office-bridge` in an untracked `compose.override.yaml` and ensure Ollama listens on the bridge/host interface.)*

> [!TIP]
> **Ollama Context Window (`num_ctx`):** Ollama defaults `num_ctx` to `2048` tokens unless overridden, which is too small for multi-agent engineering prompts. Hermes `v0.23.3` (`agent_init_ollama.py`) automatically probes Ollama's `/api/show` and clamps context compression to the effective window, or you can create an Ollama `Modelfile` with `PARAMETER num_ctx 32768`.

#### Connecting ALLINAGENT to vLLM (GPU Server)

Launch `vllm serve` with automatic tool-call parsing enabled on your GPU server:

```bash
vllm serve Qwen/Qwen2.5-Coder-14B-Instruct \
  --enable-auto-tool-choice \
  --tool-call-parser hermes \
  --max-model-len 32768 \
  --api-key "<YOUR_API_KEY>" \
  --port 8000
```

Then point ALLINAGENT at your vLLM endpoint:

```dotenv
LLM_BASE_URL=https://vllm.example.com/v1
LLM_MODEL=Qwen/Qwen2.5-Coder-14B-Instruct
DEFAULT_LLM_MODEL=Qwen/Qwen2.5-Coder-14B-Instruct
LLM_PROVIDER=custom
CUSTOM_API_KEY=<YOUR_API_KEY>
```

---

## 3. Applying Provider Changes & Rotating API Keys

Whenever you switch providers or rotate `CUSTOM_API_KEY`:

```bash
# 1. Update LLM_BASE_URL, LLM_MODEL, and CUSTOM_API_KEY in .env (or use masked prompt on Windows: .\deploy\windows\rotate-credentials.ps1 -Target provider)
# 2. Re-render data/secrets/worker-llm.env (0600) and VulnClaw config
./allinagent setup --yes --config-only

# 3. Recreate containers with updated environment and re-sync 11 worker profiles
./allinagent up
./allinagent health
```

---

## 4. Troubleshooting Model Provider Errors

| Error / Symptom | Likely Cause | Fix |
| :--- | :--- | :--- |
| `401 Unauthorized` / `Incorrect API key provided` | `CUSTOM_API_KEY` blank, expired, or mismatched with `LLM_BASE_URL` | Update `CUSTOM_API_KEY` in `.env`, run `./allinagent setup --yes --config-only && ./allinagent up` |
| `model_not_available_for_integrator` or `no endpoints found that support tool use` | Selected model on OpenRouter / custom gateway does not support function/tool calling | Switch `LLM_MODEL` to a tool-capable model (e.g. `gpt-4o-mini`, `anthropic/claude-3.7-sonnet`, `gemini-2.5-flash`) |
| `404 Not Found` on `/chat/completions` | Missing `/v1` or `/v1beta/openai` suffix on `LLM_BASE_URL` | Verify exact base URL (`https://api.openai.com/v1`, `https://openrouter.ai/api/v1`, `https://generativelanguage.googleapis.com/v1beta/openai`) |
| Prompt truncated or poor tool recall on local Ollama | Ollama running with default `2048` `num_ctx` | Set `PARAMETER num_ctx 32768` in an Ollama `Modelfile` (requires `>= 12–16 GB` VRAM/RAM) |
