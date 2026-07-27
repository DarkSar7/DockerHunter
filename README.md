# DockerHunter

DockerHunter is a fast, daemonless OCI container registry secret scanner coupled with a sandboxed AI validation pipeline.

It retrieves squashed container image filesystems directly from remote registries without requiring a Docker daemon (`dockerd`), Docker engine, or Docker CLI. It scans files line-by-line using a generic secret assignment regex, deduplicates findings, and verifies them in batches against the HuggingFace `bigcode/starpii` model to weed out placeholders and identify actual credentials.

---

## Key Features

- **Daemonless Operation**: No dependency on a local Docker Engine/daemon (`dockerd`). Runs cleanly in serverless, CI/CD, or headless environments.
- **Embedded Python Subprocess**: No FastAPI or Uvicorn server processes to manage. The Go CLI scanner automatically spawns and communicates with the Python model loop sequentially via stdin/stdout JSON channels.
- **One-Command Setup (`DockerHunter setup`)**: Verifies python3, initializes working directory (`~/.dockerhunter`), extracts python source scripts, builds a local virtual environment, installs PyTorch/transformers, and pre-caches the HuggingFace model. Requires access to the gated [bigcode/starpii](https://huggingface.co/bigcode/starpii) model repository.
- **Built-in Signatures Database**: Automatically packages and extracts the full signatures database (`regex_rules.yaml`) containing over 1100 validation patterns directly into `~/.dockerhunter/`.
- **Tag Filtering & Bounded Concurrency (for `--all-tags` scans)**:
  - `--semver "<constraint>"`: Filter tags locally using semantic version constraints (e.g. `^3.18`).
  - `--latest <N>`: Pull and scan only the `N` most recently updated tags.
  - `--since <date>`: Pull and scan tags created since a specific date (`YYYY-MM` or `YYYY-MM-DD`).
  - `--max-tags <N>`: Cap the tag scan list to a maximum of `N` tags.
  - **Worker Channel Pool**: Instead of spawning unstructured goroutines per tag, DockerHunter processes OCI queries through a dedicated worker pool (bounded to 8 concurrent channels) to prevent resource spikes and connection exhaustion.
- **Docker Hub API Optimization**: When sorting tags by timestamps, DockerHunter queries the Docker Hub API directly. This returns sorted tag timestamps for hundreds of tags in a single request (under 1 second), bypassing OCI metadata connection limits. It falls back to concurrent OCI manifest lookups with timeouts for other registries.
- **In-App Registry Account Scheduler**:
  - Store multiple credentials directly inside `~/.dockerhunter/config.yaml`.
  - Distributes traffic across accounts using a round-robin schedule.
  - Limits retry loops on HTTP 429 (Too Many Requests) to the count of configured accounts to prevent infinite loops.
  - Intercepts registry responses proactively using a custom `http.RoundTripper` wrapper to read rate-limit headers (`RateLimit-Remaining: 0`). Rotates accounts *before* hitting HTTP 429 failures.
  - Thread-safe (`sync.RWMutex`) statistics tracking and cooldown rotation.
- **Output Customization**:
  - `--output`, `-o`: Saves final scan results directly to a file (text report or JSON).
  - `--pre`: Saves candidates matching signature rules to `pre.json` *before* they are sent to the AI validator.

---

## Architecture Flow

```
User (CLI Command)
        │
        ├── DockerHunter setup  ──► Initialize ~/.dockerhunter, extract validator scripts,
        │                           build python venv, cache StarPII pipeline
        │
        └── DockerHunter scan   ──► Read configs, query registry tags, apply filters
                                    │
                                    ▼ (rotates accounts on HTTP 429 / remaining=0 headers)
                             Pull Squashed Layers
                                    │
                                    ▼
                             Walk Filesystem
                                    │
                                    ▼
                            Extract Candidates
                                    │
                                    ▼ (De-duplicate by variable, value, file, line)
                             Stream to Pipeline
                                    │
                                    ▼ (Batch Builder with 200ms timeout)
                             JSON Stdin/Stdout
                                    │
                                    ▼
                          StarPII Subprocess (main.py)
                                    │
                                    ▼
                             Formatted Report
```

---

## Installation & Setup

### 1. Installation
Install the DockerHunter binary globally via Go:
```bash
# Install latest executable to $GOPATH/bin/DockerHunter
go install github.com/DarkSar7/DockerHunter@latest
```
*(Ensure `~/go/bin` is in your terminal's `$PATH` or copy it to `/usr/local/bin/DockerHunter` for global access).*

---

### 2. Initialization (Setup)
Run the setup command to initialize DockerHunter:
```bash
DockerHunter setup
```
This automatically extracts the built-in configuration and signature database of 1100+ patterns to your home folder (`~/.dockerhunter/`) and sets up the Python virtual environment and AI model.

---

### 3. Adding Credentials & Configuration
Open the configuration file `~/.dockerhunter/config.yaml` to specify your HuggingFace Token, Registry Credentials, and fallback settings:

```bash
nano ~/.dockerhunter/config.yaml
```

> [!IMPORTANT]
> The AI Validator uses the gated model [bigcode/starpii](https://huggingface.co/bigcode/starpii).
> You must:
> 1. Create a Hugging Face account and accept the model's user agreement at [huggingface.co/bigcode/starpii](https://huggingface.co/bigcode/starpii).
> 2. Generate a **Read-only Access Token** from your Hugging Face account settings.
> 3. Paste the token into the `huggingface_token` field of `config.yaml`.

**Example Config Structure:**
```yaml
validator:
  model_name: "bigcode/starpii"
  cache_dir: "~/.dockerhunter/models"
  executable_path: "/usr/bin/python3"
  huggingface_token: "your_huggingface_auth_token_here"

pipeline:
  batch_size: 100
  batch_timeout_ms: 200
  worker_count: 8

scanner:
  regex_rules_path: "~/.dockerhunter/regex_rules.yaml"
  output_format: "text"

authentication:
  default_cooldown: 6h
  anonymous_fallback: true

registries:
  docker.io:
    accounts:
      - username: "dockerhub_user_1"
        token: "dckr_pat_your_first_token_here"
      - username: "dockerhub_user_2"
        token: "dckr_pat_your_second_token_here"
  ghcr.io:
    accounts:
      - username: "github_user"
        token: "ghp_your_personal_token_here"
```

---

## Usage Guide

### Commands and Flags

```bash
DockerHunter scan [image_reference] [flags]
```

- `--all-tags`: Scans all tags in the repository.
- `--format`: Output format, accepts `text` or `json` (default `text`).
- `--output`, `-o`: File path to save final scan results.
- `--pre`: Saves matching candidate credentials to `pre.json` before they are sent to the AI validator.
- `--semver "<constraint>"`: Scan only tags matching semantic version constraints (e.g. `^3.18`).
- `--latest <N>`: Scan only the `N` most recently updated tags.
- `--since <YYYY-MM or YYYY-MM-DD>`: Scan only tags created since the specified date.
- `--max-tags <N>`: Caps the tag scan list to a maximum of `N` tags.

---

## Examples

### 1. Scan a Single Image Tag
```bash
DockerHunter scan alpine:latest
```

### 2. Save Results (JSON Format) to a File
```bash
DockerHunter scan alpine:latest --format json --output results.json
```

### 3. Dump Pre-AI Candidates for Analysis
```bash
DockerHunter scan lyft/flyteadmin-stages:2 --pre
```
*(Creates `pre.json` containing candidates that matched your regex signatures before StarPII filtered out placeholders).*

### 4. Filter Registry Scans (Latest Tags & Limits)
Query the 5 most recently created tags of alpine:
```bash
DockerHunter scan alpine --all-tags --latest 5
```

### 5. Filter Registry Scans (Semantic Versions & Caps)
Scan alpine tags matching `^3.18` and cap the execution limit to the first 3 matches:
```bash
DockerHunter scan alpine --all-tags --semver "^3.18" --max-tags 3
```

---

## License
MIT
