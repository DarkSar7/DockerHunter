# DockerHunter

DockerHunter is a fast, daemonless OCI container registry secret scanner coupled with an AI validation service. 

It fetches squashed container image filesystems directly from remote registries without requiring Docker daemon (`dockerd`), Docker engine, or Docker CLI. It scans files line-by-line using a generic secret assignment regex, deduplicates findings, and verifies them in batches against the HuggingFace `bigcode/starpii` model to weed out placeholders and identify actual credentials.

---

## Architecture

DockerHunter consists of two independent components:
1. **Go CLI Scanner**: Handles registry image downloading, layer squashing, walking files, matching regex, deduplication, batch validation requests, and immediate cleanup.
2. **Python AI Validator**: A lightweight FastAPI wrapper around the `bigcode/starpii` model, validating candidate secrets in batches.

```
Repository/Image Reference
            │
            ▼ (remote.List tag enumeration if --all-tags)
     Download Image (OciRegistrySource)
            │
            ▼
   Reconstruct Filesystem (SquashedTree)
            │
            ▼
      Walk File Tree (filetree.Walker)
            │
            ▼
    Scan Lines (ExtractCandidates)
            │
            ▼
     Deduplicate candidates
            │
            ▼
Validate in batches (POST /validate) ──► StarPII NER Pipeline
            │
            ▼
  Consolidated Results
            │
            ▼
   Immediate Cleanup (img.Cleanup())
```

---

## Key Features

- **Daemonless Operation**: No dependency on local Docker Engine/daemon (`dockerd`). Runs cleanly in offline, CI/CD, or headless environments.
- **Repository-Wide Scanning**: Automatically lists and processes all available tags (`--all-tags`).
- **Immediate Workspace Cleanup**: Deletes temp layers and squashed directories immediately after processing each tag, preventing disk space accumulation.
- **Fault-Tolerant Scanning**: Skips failed or architecture-mismatched images and continues scanning remaining tags, displaying a complete errors list at the end.
- **AI Classification**: Batches HTTP validation requests to StarPII, reducing network and model evaluation time.
- **Attribution**: Annotates findings with the exact image and tag metadata.

---

## Installation & Setup

### 1. Python AI Validator Service
Ensure Python 3.11+ is installed.

```bash
cd validator
# Set up virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies (CPU-only Torch is recommended for faster setup)
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
```

#### Configuration
Set your configuration inside `validator/config/config.yaml`:
```yaml
server:
  host: "0.0.0.0"
  port: 9001

huggingface:
  token: "" # Gated model token (loaded from HUGGINGFACEHUB_API_TOKEN env var if empty)
  model:
    name: "bigcode/starpii"
    cache_dir: "/app/models"
    use_auth_token: true
```

#### Run Validator
```bash
python main.py
```

---

### 2. Go CLI Scanner
Ensure Go 1.24+ is installed.

```bash
# Build the binary
go build -o dockerhunter main.go

# Run unit tests
go test ./pkg/...
```

---

## Usage

### Commands and Flags

```bash
./dockerhunter scan [image_reference] [flags]
```

- `--all-tags`: Scans all tags in the repository (e.g. `dockerhunter scan alpine --all-tags`).
- `--json`: Outputs final results in JSON format.
- `--format`: Output format, accepts `text` or `json` (default `text`).
- `--validator-url`, `-u`: Specify validator service URL (default `http://localhost:9001`).
- `--batch-size`, `-b`: Invalidation request batch size (default `100`).

### Examples

#### Scan a Single Tag
```bash
./dockerhunter scan alpine:latest
```

#### Scan a Repository with All Tags
```bash
./dockerhunter scan hello-world --all-tags
```

#### JSON Output Format
```bash
./dockerhunter scan alpine:latest --json
```

```json
[
  {
    "image": "index.docker.io/library/alpine",
    "tag": "latest",
    "file": "/etc/shadow",
    "line": 15,
    "variable": "root",
    "value": "yoursecretpasshash",
    "context": "root:yoursecretpasshash:18776:0:99999:7:::"
  }
]
```

---

## License
MIT
