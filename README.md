# A2A-VEX

An Agent-to-Agent-based CVE reproduction and evidence-driven vulnerability assessment system built on CVE-Genie.

A2A-VEX extends the original CVE-Genie workflow with a browser-based FastAPI service and an HTTP-based agent orchestration layer. The system extracts CVE context, prepares vulnerable environments, generates and evaluates proof-of-concept exploits, verifies reproduction results, and exposes the resulting evidence through a web dashboard.

The implementation separates the workflow into three independently running agent services:

- **Environment Agent**: knowledge preparation, prerequisite analysis, repository construction, and environment review
- **Exploit Agent**: exploit generation, execution, and critic review
- **Verification Agent**: verifier generation, final validation, and consistency review

An **A2A Orchestrator** discovers these services through Agent Cards, assigns tasks, propagates a shared context, receives artifacts, and coordinates the end-to-end workflow. The original CVE-Genie execution mode remains available as a legacy fallback.

---

# 📜 Results

[RESULTS.md](results/RESULTS.md) provides details on accessing the results.

Depending on the execution method, reproduction artifacts may be stored in one of the following locations:

```text
/shared/<cve_id>/
results/reproduced_cves/<cve_id>/
web_jobs/results/<cve_id>/
```

The web service also stores job metadata and logs in:

```text
src/
├── cve_genie_jobs.db
└── web_jobs/
    └── <job_id>/
        ├── input/
        │   └── <cve_id>.json
        ├── logs/
        │   └── job.log
        └── results/
```

---

# 🏃‍♂️ How to Run

## A) Extract and Prepare Data

If you want to reproduce a CVE, follow the steps in **A-❶** to extract CVE data.

To reproduce a vulnerability that is not assigned a CVE identifier, follow **A-❷**.

---

## A-❶) CVE Data Extraction

> ‼️ CVE-Genie uses the `cvelistV5` repository to obtain CVE records.

### 1. Create and activate a Python virtual environment

From the repository root:

```bash
cd src

python3 -m venv env
source env/bin/activate
```

On Windows PowerShell without WSL:

```powershell
cd src

python -m venv env
.\env\Scripts\Activate.ps1
```

### 2. Install the required packages

```bash
pip install -r data/requirements.txt
playwright install
```

### 3. Clone the `cvelistV5` repository

```bash
cd src

git clone https://github.com/CVEProject/cvelistV5.git \
  data/cvelistV5/
```

The expected path is:

```text
src/data/cvelistV5/
```

### 4. Create the `.env` file

Create the following file:

```text
src/.env
```

Add the required credentials:

```dotenv
OPENAI_API_KEY=your_openai_api_key
GITHUB_TOKEN=your_github_token
```

Do not commit this file to a public repository.

### 5. Extract CVE data

Run:

```bash
python ./data/scripts/cve_data.py \
  --cve_id CVE-2024-4340 \
  --output_path ./data/example/test.json
```

If the script returns:

```text
✅ Ready to reproduce!!
```

the extracted data is ready for CVE-Genie.

If extraction is incomplete, refer to:

```text
src/data/PROCESSING.md
```

Manual context may be required when:

1. The CVE record does not include source-code information.
2. The affected software is a commercial or closed-source product.
3. The CVE record was modified.
4. The parser could not automatically identify the repository, version, build instructions, or vulnerable component.
5. Additional source-code URLs or version metadata must be supplied manually.

---

## A-❷) Extract Non-CVE Vulnerability Data

Automated extraction for non-CVE vulnerabilities is currently not supported.

Refer to:

```text
src/data/PROCESSING.md
```

and manually prepare the vulnerability context in the same format used by CVE-Genie.

---

# B) Run CVE-Genie on Extracted CVE Data

CVE-Genie can be executed in a Dev Container or in a virtual machine.

---

## B-❶) Run in a Dev Container

> ‼️ A Dev Container is easy to set up, but it may not be suitable for CVEs that require multiple services, privileged operations, kernel-level behavior, or stronger isolation. A failed exploit or unstable service may crash the Dev Container.

### 1. Open the repository in VS Code

Use:

```text
Dev Containers: Reopen in Container
```

### 2. Move to the `src` directory

```bash
cd /workspaces/A2A-VEX/src
```

### 3. Activate the virtual environment

```bash
source env/bin/activate
```

### 4. Verify the environment

```bash
python -c "from agentlib import Agent; print(Agent)"
```

Expected output:

```text
<class 'agentlib.lib.agents.agent.Agent'>
```

The following Pydantic warning is currently non-fatal:

```text
Valid config keys have changed in V2:
'underscore_attrs_are_private' has been removed
```

### 5. Run CVE-Genie

```bash
ENV_PATH=.env \
MODEL=example_run \
python main.py \
  --cve CVE-2024-4340 \
  --json data/example/test.json \
  --run-type build,exploit,verify
```

The `--run-type` option accepts one or more of:

```text
build
exploit
verify
```

Examples:

```bash
python main.py \
  --cve CVE-2024-4340 \
  --json data/example/test.json \
  --run-type build
```

```bash
python main.py \
  --cve CVE-2024-4340 \
  --json data/example/test.json \
  --run-type build,exploit
```

```bash
python main.py \
  --cve CVE-2024-4340 \
  --json data/example/test.json \
  --run-type build,exploit,verify
```

### 6. Review the results

The final artifacts are typically stored in:

```text
/shared/<cve_id>/
```

Depending on the repository version and execution configuration, results may also be stored in:

```text
results/reproduced_cves/<cve_id>/
```

---

## B-❷) Run in a Virtual Machine

For stronger isolation and better support for multi-service CVEs, use the VM-based execution mode.

Read:

```text
vm_library/README.md
```

The VM-based approach is recommended when the target CVE requires:

- Multiple services
- Privileged operations
- Kernel interaction
- Network services
- System-level package installation
- A disposable execution environment
- Stronger separation between CVE-Genie and the vulnerable target

---

# C) Run CVE-Genie as a Web Service

CVE-Genie can be operated through a FastAPI backend and a browser-based dashboard.

The current web service supports:

- Submission of any syntactically valid CVE ID
- Automatic CVE context extraction from the local `cvelistV5` data
- Defensive handling of incomplete CVE records
- Per-job input and log directories
- Validation of extracted reproduction context
- `needs_input` handling for incomplete records
- Browser-based JSON editing and job resumption
- Asynchronous execution of the existing CVE-Genie CLI
- Job status and live log monitoring
- Final reproduction verdict parsing
- Artifact and result-path discovery
- Swagger API documentation

The current architecture is:

```text
Browser
  ↓ HTTP/JSON
FastAPI Web Service
  ↓ Background Task
Web Worker
  ├── CVE data extraction
  ├── input validation
  └── A2A Orchestrator
        ├── Environment Agent :8101
        ├── Exploit Agent     :8102
        └── Verification Agent:8103
  ↓
SQLite Job Database
  ↓
Logs, A2A task records, artifacts, and reproduction results
```

The system supports two execution modes:

```text
a2a
→ Calls the A2A Orchestrator and independent agent services.

legacy
→ Calls the original CVE-Genie main.py workflow directly.
```

> ‼️ The current prototype runs the API server, CVE-Genie, the vulnerable target, exploit process, and verifier inside the same Dev Container. It is a functional prototype, not a security sandbox.

---

## C-❶) Web Service Directory Structure

```text
src/
├── cve_genie_web/
│   ├── __init__.py
│   ├── app.py
│   ├── config.py
│   ├── database.py
│   ├── models.py
│   ├── repository.py
│   ├── schemas.py
│   ├── routes/
│   │   ├── __init__.py
│   │   └── jobs.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── extraction_service.py
│   │   ├── input_service.py
│   │   ├── process_utils.py
│   │   ├── reproduction_result_service.py
│   │   ├── result_service.py
│   │   ├── runner_service.py
│   │   └── validation_service.py
│   ├── workers/
│   │   ├── __init__.py
│   │   └── job_worker.py
│   └── static/
│       ├── index.html
│       ├── style.css
│       └── app.js
├── cve_genie_a2a/
│   ├── models.py
│   ├── client.py
│   ├── common.py
│   ├── environment_server.py
│   ├── exploit_server.py
│   └── verification_server.py
├── data/
│   └── scripts/
│       └── cve_data.py
├── a2a_orchestrator.py
├── requirements-web.txt
├── requirements-a2a.txt
├── run_a2a_services.sh
├── stop_a2a_services.sh
├── run_web.sh
├── BACKFILL-EXISTING-RESULTS.py
├── cve_genie_jobs.db
└── web_jobs/
    └── <job_id>/
        ├── input/
        │   └── <cve_id>.json
        ├── logs/
        │   └── job.log
        └── results/
```

---

## C-❷) Install Web and A2A Dependencies

```bash
cd /workspaces/A2A-VEX/src
source env/bin/activate

pip install -r requirements-web.txt
pip install -r requirements-a2a.txt
pip install playwright
playwright install
```

Verify Playwright with the virtual-environment Python:

```bash
/workspaces/A2A-VEX/src/env/bin/python -c \
"from playwright.sync_api import sync_playwright; print('Playwright OK')"
```

---

## C-❸) Verify Required Files

```bash
test -x /workspaces/A2A-VEX/src/env/bin/python \
  && echo "Python OK"

test -f /workspaces/A2A-VEX/src/main.py \
  && echo "main.py OK"

test -f /workspaces/A2A-VEX/src/data/scripts/cve_data.py \
  && echo "cve_data.py OK"

test -f /workspaces/A2A-VEX/src/.env \
  && echo ".env OK"

test -d /workspaces/A2A-VEX/src/data/cvelistV5 \
  && echo "cvelistV5 OK"
```

Compile the web package and extraction script:

```bash
python -m py_compile data/scripts/cve_data.py
python -m compileall cve_genie_web
python -m compileall cve_genie_a2a
python -m py_compile a2a_orchestrator.py
python -m py_compile cve_genie_web/services/runner_service.py
```

---

## C-❹) Start the A2A Services and Web Server

After opening the project in the VS Code Dev Container:

```bash
cd /workspaces/A2A-VEX/src
source env/bin/activate
```

Start the three A2A agent services:

```bash
chmod +x run_a2a_services.sh stop_a2a_services.sh
./run_a2a_services.sh
```

Verify:

```bash
curl http://127.0.0.1:8101/health
curl http://127.0.0.1:8102/health
curl http://127.0.0.1:8103/health
```

Inspect an Agent Card:

```bash
curl http://127.0.0.1:8101/.well-known/agent-card.json | python -m json.tool
```

Start the web service in A2A mode:

```bash
CVE_GENIE_PYTHON=/workspaces/A2A-VEX/src/env/bin/python \
CVE_GENIE_EXECUTION_MODE=a2a \
./run_web.sh
```

Open:

```text
Dashboard: http://localhost:8000/
Swagger:   http://localhost:8000/docs
Health:    http://localhost:8000/health
```

Legacy mode:

```bash
CVE_GENIE_PYTHON=/workspaces/A2A-VEX/src/env/bin/python \
CVE_GENIE_EXECUTION_MODE=legacy \
./run_web.sh
```

---

## C-❺) Web Dashboard Workflow

```text
Enter CVE ID
  ↓
Create an isolated job
  ↓
Extract CVE context
  ↓
Validate repository, version, and vulnerability data
  ├── sufficient → run CVE-Genie
  ├── incomplete → needs_input
  └── unsupported → stop with an explanation
  ↓
Discover A2A agent services
  ↓
Environment Agent
  ↓
Exploit Agent
  ↓
Verification Agent
  ↓
Parse CVE-Genie's final Results output
  ↓
Display job completion and reproduction verdict separately
```

### Job status

Job status represents the execution state of the web-managed job:

```text
queued
extracting
validating
needs_input
ready
running
succeeded
failed
unsupported
cancelled
```

A `succeeded` job means that the CVE-Genie process completed without an execution error. It does not, by itself, mean the vulnerability was reproduced.

### Reproduction status

Reproduction status represents CVE-Genie's final exploit-verification result:

```text
confirmed
not_reproduced
inconclusive
unknown
```

The dashboard displays both values separately.

Example:

```text
Job Status: succeeded
Reproduction Verdict: confirmed
Exploitable: true
Verifier: passed
Final Reason: CTF Verifier done! CVE reproduced!
```

---

## C-❻) Incomplete CVE Records and `needs_input`

Not every CVE record contains enough information to automatically reconstruct a vulnerable environment.

The extraction and validation stages check for context such as:

- CVE identifier
- Vulnerability description
- Source repository or source archive
- Vulnerable version
- Git tag, commit, or checkout reference
- Patch-commit information

When required context is missing, the job enters:

```text
needs_input
```

The dashboard then displays:

- Missing field descriptions
- The generated input JSON
- A JSON editor
- A **Save and Resume** button

The user can supplement the JSON and resume the same job.

The updated extractor saves partial JSON instead of crashing when optional fields such as `patch_urls`, `version_data`, or advisory URLs are absent.

---

## C-❼) Web API Endpoints

### Create a job

```http
POST /api/jobs
```

```bash
curl -X POST http://localhost:8000/api/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-4340",
    "run_type": "build,exploit,verify"
  }'
```

### List jobs

```http
GET /api/jobs
```

```bash
curl http://localhost:8000/api/jobs
```

### Get job status and reproduction verdict

```http
GET /api/jobs/{job_id}
```

```bash
curl http://localhost:8000/api/jobs/JOB_ID
```

The response includes:

```text
status
stage
reproduction_status
exploitable
verifier_passed
final_reason
```

### Get execution log

```http
GET /api/jobs/{job_id}/log
```

```bash
curl http://localhost:8000/api/jobs/JOB_ID/log
```

### Read extracted or manually edited input JSON

```http
GET /api/jobs/{job_id}/input
```

```bash
curl http://localhost:8000/api/jobs/JOB_ID/input
```

### Update input JSON

```http
PUT /api/jobs/{job_id}/input
```

```bash
curl -X PUT http://localhost:8000/api/jobs/JOB_ID/input \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "CVE-2024-0000": {
        "description": "Example vulnerability context"
      }
    }
  }'
```

### Resume a paused or failed job

```http
POST /api/jobs/{job_id}/resume
```

```bash
curl -X POST http://localhost:8000/api/jobs/JOB_ID/resume
```

### Get result metadata and artifacts

```http
GET /api/jobs/{job_id}/result
```

```bash
curl http://localhost:8000/api/jobs/JOB_ID/result
```

The result response includes:

```text
job status
reproduction status
exploitable flag
verifier result
final reason
result path
artifact list
```

---

## C-❽) Job Execution Flow

When a job is submitted, the worker performs the following steps:

```text
1. Validate CVE ID syntax
2. Generate a UUID job ID
3. Create a per-job directory
4. Insert the job into SQLite
5. Run data/scripts/cve_data.py
6. Save complete or partial CVE JSON
7. Validate reproduction context
8. Pause with needs_input when required
9. Select `a2a` or `legacy` execution mode
10. Run `a2a_orchestrator.py` in A2A mode
11. Discover agent services through Agent Cards
12. Submit tasks with shared context and unique task IDs
13. Collect task states and returned artifacts
14. Store stdout, stderr, and A2A communication records
15. Locate the CVE-Genie result directory
16. Parse the final Results dictionary
17. Store the reproduction verdict
18. Expose status, verdict, logs, and artifacts through the API
```

Extraction command:

```bash
python ./data/scripts/cve_data.py \
  --cve_id CVE-2024-4340 \
  --output_path ./web_jobs/<job-id>/input/CVE-2024-4340.json
```

A2A execution command:

```bash
ENV_PATH=.env \
MODEL=example_run \
python a2a_orchestrator.py \
  --cve CVE-2024-4340 \
  --json ./web_jobs/<job-id>/input/CVE-2024-4340.json \
  --run-type build,exploit,verify \
  --log ./web_jobs/<job-id>/logs/job.log
```

Legacy execution command:

```bash
ENV_PATH=.env \
MODEL=example_run \
python main.py \
  --cve CVE-2024-4340 \
  --json ./web_jobs/<job-id>/input/CVE-2024-4340.json \
  --run-type build,exploit,verify
```

---

## C-❾) A2A Communication Model

Each agent exposes:

```text
GET  /health
GET  /.well-known/agent-card.json
POST /a2a/tasks
```

The Orchestrator:

```text
1. Discovers the agent through its Agent Card
2. Validates the advertised skill
3. Creates or propagates context_id
4. Creates a unique task_id
5. Sends a task message and input artifacts
6. Receives task state and output artifacts
7. Passes the result to the next agent
8. Records the exchange in an A2A JSONL log
```

Current skills:

```text
Environment Agent  → cve.environment.build
Exploit Agent      → cve.exploit.generate
Verification Agent → cve.verification.verify
```

CLI test:

```bash
ENV_PATH=.env \
MODEL=example_run \
python a2a_orchestrator.py \
  --cve CVE-2024-4340 \
  --json data/example/test.json \
  --run-type build,exploit,verify \
  --log /tmp/cve-2024-4340-a2a.log
```

Review logs:

```bash
tail -f /tmp/cve-2024-4340-a2a.log
tail -f /tmp/cve-2024-4340-a2a.log.a2a.jsonl
```

Typical A2A record fields:

```text
context_id
task_id
agent_name
skill_id
state
artifacts
```

> This is an application-oriented A2A service layer for CVE-Genie. It implements Agent Cards, task delegation, context propagation, task states, and artifacts, but does not claim support for every optional feature of the upstream A2A specification.

---

## C-❿) Reproduction Verdict Parsing

CVE-Genie prints a final result similar to:

```text
Results: {
  'success': 'True',
  'reason': 'CTF Verifier done! CVE reproduced!'
}
```

The web service parses this result and stores:

```text
reproduction_status
exploitable
verifier_passed
final_reason
```

Mapping:

```text
success=True
→ reproduction_status=confirmed
→ exploitable=true
→ verifier_passed=true

success=False
→ reproduction_status=not_reproduced
→ exploitable=false
→ verifier_passed=false

missing or ambiguous final result
→ reproduction_status=inconclusive or unknown
```

The parser also supports fallback log markers such as:

```text
CVE reproduced
Critic accepted the verifier
Verifier passed
CVE not reproduced
Verifier failed
```

---

## C-⓫) SQLite Job Model

The SQLite database stores:

```text
job_id
cve_id
status
stage
message
input_json_path
log_path
result_path
exit_code
run_type
missing_fields_json
reproduction_status
exploitable
verifier_passed
final_reason
created_at
updated_at
started_at
finished_at
```

Existing databases are migrated automatically when the FastAPI application starts.

To parse old job logs and populate the newly added reproduction fields:

```bash
cd /workspaces/A2A-VEX/src
source env/bin/activate

python BACKFILL-EXISTING-RESULTS.py
```

---

## C-⓬) Runtime Files

```text
src/
├── cve_genie_jobs.db
└── web_jobs/
    └── <job_id>/
        ├── input/
        │   └── <cve_id>.json
        ├── logs/
        │   └── job.log
        └── results/
```

CVE-Genie result discovery checks paths such as:

```text
/shared/<cve_id>/
results/reproduced_cves/<cve_id>/
web_jobs/results/<cve_id>/
```

---

## C-⓭) Troubleshooting

### Port 8000 is already in use

```bash
ss -ltnp | grep :8000
```

Terminate the existing process:

```bash
fuser -k 8000/tcp
```

Restart:

```bash
cd /workspaces/A2A-VEX/src
source env/bin/activate
./run_web.sh
```

### CSS or JavaScript is not applied

```bash
curl -I http://localhost:8000/static/style.css
```

Expected:

```text
HTTP/1.1 200 OK
```

Verify references:

```bash
grep -nE "stylesheet|app.js" \
  cve_genie_web/static/index.html
```

Use a hard refresh:

```text
Ctrl + Shift + R
```

### Job remains in `extracting`

```bash
ps aux | grep cve_data.py
```

Find job logs:

```bash
find web_jobs -path "*/logs/job.log" -type f -print
```

Read a specific log:

```bash
tail -f web_jobs/<job-id>/logs/job.log
```

### Job enters `needs_input`

This means extraction completed, but source repository or vulnerable-version context is incomplete.

Select the job in the dashboard, edit the generated JSON, and click:

```text
Save and Resume
```

### Old successful job shows `unknown`

Run:

```bash
python BACKFILL-EXISTING-RESULTS.py
```

### Static resources are cached

Open:

```text
http://localhost:8000/?v=5
```

---

### Playwright is installed but extraction still reports `ModuleNotFoundError`

Check the Python path:

```bash
python -c "
from cve_genie_web.config import settings
print(settings.python_executable)
"
```

Expected:

```text
/workspaces/A2A-VEX/src/env/bin/python
```

Do not call `.resolve()` on the virtual-environment Python path in `cve_genie_web/config.py`. Resolving the symbolic link may turn it into `/usr/bin/python3.10` and bypass packages installed in the virtual environment.

Correct configuration:

```python
python_executable=Path(
    os.getenv(
        "CVE_GENIE_PYTHON",
        str(project_root / "env" / "bin" / "python"),
    )
),
```

Restart:

```bash
pkill -f "uvicorn cve_genie_web.app:app" 2>/dev/null || true
sleep 2

CVE_GENIE_PYTHON=/workspaces/A2A-VEX/src/env/bin/python \
CVE_GENIE_EXECUTION_MODE=a2a \
./run_web.sh
```

### Port 8000 is in use and `fuser` is unavailable

```bash
pkill -f "uvicorn cve_genie_web.app:app" 2>/dev/null || true
sleep 2
```

Do not use `pkill -f python`; it may terminate the A2A agent servers.

### Clear web job history

```bash
pkill -f "uvicorn cve_genie_web.app:app" 2>/dev/null || true

cd /workspaces/A2A-VEX/src
rm -f cve_genie_jobs.db
rm -rf web_jobs
mkdir -p web_jobs
```

This does not remove CVE-Genie artifacts under `/shared` or `results`.

---

## C-⓮) Security Limitations

The implementation includes:

- CVE ID format validation
- `shell=False`
- Argument-array subprocess execution
- Per-job input and log paths
- Configurable timeout
- Environment-based configuration
- Basic secret masking in logs
- JSON validation before CVE-Genie execution

The current prototype does not provide strong exploit isolation.

```text
Dev Container
├── FastAPI server
├── CVE-Genie
├── LLM agents
├── vulnerable source code
├── build process
├── exploit process
└── verifier
```

A Python virtual environment isolates Python dependencies only. It does not isolate malicious or vulnerable processes.

The recommended production architecture is:

```text
Frontend
  ↓
FastAPI API
  ↓
Redis
  ↓
Celery or RQ Worker
  ↓
Disposable Container or VM
  ↓
PostgreSQL
  ↓
Artifact Storage
```

Production hardening should include:

- Authentication and authorization
- Per-job disposable containers or VMs
- CPU, memory, PID, time, and storage limits
- Network restrictions
- Read-only mounts where possible
- Persistent task queues
- Worker restart recovery
- Artifact retention policies
- Audit logs
- Secret redaction
- Job cancellation
- Resource monitoring

The web request-handling process should not directly execute untrusted PoCs.

---

# D) Visualize Existing CVE Reproduction Runs

CVE-Genie also includes a visualizer for inspecting completed reproduction runs.

### 1. Verify the result path

Make sure the CVE reproduction run is located under:

```text
results/reproduced_cves/
```

Some repository versions may use:

```text
results/reproduced_cve/
```

Verify the actual directory name in your checkout.

### 2. Run the visualizer

```bash
cd visualizer/
python3 serve.py
```

### 3. Open the generated URL

The script prints a local URL for the visualizer.

### 4. Load a CVE

Enter a CVE ID and click:

```text
Load CVE
```

The visualizer allows users to inspect:

- Agent conversations
- Tool calls
- Intermediate artifacts
- Build activity
- Exploit activity
- Verification output
- Reproduction evidence

---

# E) A2A-VEX Workflow

```text
CVE ID
  ↓
CVE Data Extraction
  ↓
Input Validation
  ├── incomplete → needs_input
  └── sufficient → A2A Orchestrator
                      ↓
                Environment Agent
                ├── KnowledgeBuilder
                ├── PreReqBuilder
                ├── RepoBuilder
                └── RepoCritic
                      ↓
                  Exploit Agent
                ├── Exploiter
                └── ExploitCritic
                      ↓
               Verification Agent
                ├── CTFVerifier
                └── SanityGuy
                      ↓
             Reproduction Verdict
                      ↓
          Logs, Artifacts, and Evidence
```

The A2A Orchestrator does not replace the original CVE-Genie logic. It adds service boundaries and a task-oriented communication layer around the existing capabilities.

- **A2A Orchestrator**: discovers agents, assigns tasks, propagates context, and collects artifacts.
- **Environment Agent**: prepares knowledge, prerequisites, repository state, and the vulnerable environment.
- **Exploit Agent**: generates and evaluates the exploit.
- **Verification Agent**: creates the verifier and performs the final consistency check.
- **Web Service**: manages jobs, logs, manual input, persistence, and verdict presentation.

---

# F) Environment Variables

The main environment variables are:

```dotenv
OPENAI_API_KEY=...
GITHUB_TOKEN=...
ENV_PATH=.env
MODEL=example_run
```

Optional web configuration variables include:

```dotenv
CVE_GENIE_ROOT=/workspaces/A2A-VEX/src
CVE_GENIE_PYTHON=/workspaces/A2A-VEX/src/env/bin/python
CVE_GENIE_ENV_FILE=/workspaces/A2A-VEX/src/.env
CVE_GENIE_DATA_SCRIPT=/workspaces/A2A-VEX/src/data/scripts/cve_data.py
CVE_GENIE_MAIN_SCRIPT=/workspaces/A2A-VEX/src/main.py
CVE_GENIE_JOB_ROOT=/workspaces/A2A-VEX/src/web_jobs
CVE_GENIE_DATABASE=/workspaces/A2A-VEX/src/cve_genie_jobs.db
CVE_GENIE_PROCESS_TIMEOUT=7200
CVE_GENIE_EXECUTION_MODE=a2a
CVE_GENIE_ENVIRONMENT_AGENT_URL=http://127.0.0.1:8101
CVE_GENIE_EXPLOIT_AGENT_URL=http://127.0.0.1:8102
CVE_GENIE_VERIFICATION_AGENT_URL=http://127.0.0.1:8103
```

---

# G) Recommended Development Roadmap

The current A2A-VEX implementation is a functional research prototype.

1. Replace the application-oriented message model with the official upstream A2A SDK where strict interoperability is required.
2. Add durable task persistence, polling, cancellation, and failure recovery.
3. Display active agent, context ID, task ID, skill ID, and returned artifacts in the dashboard.
4. Add Server-Sent Events or WebSocket-based live updates.
5. Replace FastAPI `BackgroundTasks` with Redis and Celery or RQ.
6. Run each task in a disposable container or VM.
7. Add evidence provenance linking input records, messages, artifacts, critic decisions, and the final verdict.
8. Generate VEX documents using `affected`, `not_affected`, `fixed`, and `under_investigation`.
9. Add authentication and per-user job history.
10. Replace SQLite with PostgreSQL.
11. Add resource quotas, retention rules, and automatic cleanup.
12. Add automated tests for discovery, task transitions, failure propagation, and legacy fallback.

---

# H) Quick Start

```bash
cd /workspaces/A2A-VEX/src
source env/bin/activate

pip install -r requirements-web.txt
pip install -r requirements-a2a.txt
pip install playwright
playwright install
```

Start A2A services:

```bash
chmod +x run_a2a_services.sh stop_a2a_services.sh
./run_a2a_services.sh
```

Verify:

```bash
curl http://127.0.0.1:8101/health
curl http://127.0.0.1:8102/health
curl http://127.0.0.1:8103/health
```

Start the web dashboard:

```bash
CVE_GENIE_PYTHON=/workspaces/A2A-VEX/src/env/bin/python \
CVE_GENIE_EXECUTION_MODE=a2a \
./run_web.sh
```

Open:

```text
http://localhost:8000/
```

Submit:

```text
CVE-2024-4340
```

Stop the A2A services:

```bash
./stop_a2a_services.sh
```
