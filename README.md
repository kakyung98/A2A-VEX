# A2A-VEX

An Agent-to-Agent-based CVE reproduction, semantic evidence exchange, and asset-context likelihood assessment system built on CVE-Genie.

A2A-VEX extends the original CVE-Genie workflow with a browser-based FastAPI service, an HTTP-based agent orchestration layer, and an asset-context assessment path for CVEs that cannot be reproduced from source code.

The system first extracts CVE context and evaluates whether usable source code can be obtained. When source code and reproduction metadata are available, A2A-VEX follows the original CVE-Genie workflow to prepare the vulnerable environment, generate and evaluate a proof-of-concept exploit, and verify the reproduction result.

When usable source code cannot be obtained, the job is not treated as reproduced or not affected. Instead, it enters an `under_investigation`-oriented asset-context workflow. The user provides operational information about the deployed asset, while Data Processor and Builder outputs are converted into structured semantic evidence. A likelihood assessment layer then compares CVE exploitation prerequisites with the supplied asset context and estimates one of:

```text
likely_affected
likely_not_affected
under_investigation
```

These likelihood labels are advisory estimates. They do not replace a confirmed reproduction result or a final machine-readable VEX statement.

The implementation separates the workflow into three independently running agent services:

- **Environment Agent**: knowledge preparation, prerequisite analysis, repository construction, and environment review
- **Exploit Agent**: exploit generation, execution, and critic review
- **Verification Agent**: verifier generation, final validation, and consistency review

An **A2A Orchestrator** discovers these services through Agent Cards, assigns tasks, propagates a shared context, receives artifacts, and coordinates the end-to-end workflow. The original CVE-Genie execution mode remains available as a legacy fallback.

## Dual Analysis Paths

A2A-VEX supports two analysis paths:

```text
1. Source Reproduction Path
   CVE input
     → source availability check
     → CVE-Genie environment build
     → exploit generation
     → verifier execution
     → reproduction verdict

2. Asset-Context Likelihood Path
   CVE input
     → source unavailable or unusable
     → base state: under_investigation
     → collect asset operational information
     → fuse Data Processor and Builder semantic evidence
     → compare exploitation prerequisites with asset conditions
     → likelihood estimate
```

The asset-context path is intended for commercial, proprietary, closed-source, inaccessible, or otherwise non-reproducible products.

### Semantic evidence used in the asset-context path

A2A-VEX is designed to combine evidence extracted by CVE-Genie components such as:

- CVE Data Processor outputs
- `KnowledgeBuilder` vulnerability context
- `PreReqBuilder` exploitation prerequisites
- advisory and CWE-derived attack semantics
- protocol, service, feature, authentication, privilege, and interaction requirements
- A2A task artifacts and structured claims
- user-provided asset operational context

The resulting semantic profile may include:

```text
attack vector
required protocol
required service
required port
authentication requirement
required privilege
user interaction requirement
required feature
remote reachability requirement
runtime prerequisite
deployment assumption
impact type
```

The asset input is normalized into the same condition vocabulary so that CVE requirements and asset conditions can be compared explicitly.

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
- `needs_input` handling when source code exists but reproduction metadata is incomplete
- `needs_asset_input` handling when usable source code cannot be obtained
- Browser-based JSON editing and job resumption
- Browser-based asset operational context entry
- Semantic likelihood assessment for source-unavailable CVEs
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
  ├── source availability assessment
  ├── reproduction input validation
  ├── asset-context collection when source is unavailable
  ├── semantic profile generation
  ├── semantic evidence fusion
  ├── likelihood assessment worker
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

## C-0) Functional Capabilities

The semantic asset-assessment backend, persistence layer, background evaluation worker, REST endpoints, and likelihood dashboard card are implemented in the current branch.

A2A-VEX provides the following system-level functions.

### CVE intake and context preparation

- Accepts a syntactically valid CVE identifier from the web dashboard or API
- Loads the corresponding CVE List V5 record from the local `cvelistV5` repository
- Extracts descriptions, CWE information, references, patch commits, and affected-version information
- Preserves partial extraction results when some reproduction metadata is unavailable
- Creates an isolated working directory for each submitted analysis

### Source availability and reproduction readiness assessment

- Checks whether a usable source repository or source archive can be identified
- Optionally probes remote repositories before starting reproduction
- Evaluates the availability of a vulnerable version, tag, commit, checkout reference, and patch evidence
- Separates source-reproducible jobs from source-unavailable jobs
- Sends incomplete but source-reproducible jobs to `needs_input`
- Sends source-unavailable jobs to `needs_asset_input`
- Preserves `reproduction_status=not_attempted` when source-based execution is not performed
- Reports missing reproduction or asset-context fields through the dashboard

### Manual context completion

- Displays the generated CVE input JSON in the browser
- Allows analysts to add or correct repository, version, build, and vulnerability context
- Validates edited JSON before accepting it
- Resumes the same job without creating a new analysis record
- Retains the original job ID, log path, and analysis history

### Asset-context likelihood assessment

When source-based reproduction cannot be performed, A2A-VEX keeps the case in an investigation-oriented state and requests operational context from the user.

The current asset form collects information such as:

```text
product and vendor
installed version
operating system and architecture
deployment type
service and process state
vulnerable feature state
component reachability
internet exposure
listening ports and reachable networks
authentication requirements
patch state
firewall, segmentation, and IDS/IPS controls
supporting evidence notes
```

This information is not interpreted in isolation. The implemented decision layer builds a normalized semantic prerequisite profile from the extracted CVE data and any structured A2A claims already stored for the job. It then fuses those claims with user-provided asset context before running the likelihood assessment.

Automatic structured Claim emission from every CVE-Genie Data Processor and Builder is not yet complete. The current implementation therefore uses the claims that have already been persisted for the job and augments them with normalized asset-context claims.

Example comparison:

```text
CVE semantic prerequisite:
- remote management HTTP service required
- unauthenticated access required
- file-upload feature required
- attacker reachability required

Asset context:
- management service running
- authentication enforced
- file upload disabled
- service reachable only from isolated management network

Likelihood result:
- likely_not_affected
- unmet prerequisites: unauthenticated access, file upload, relevant reachability
- base investigation state remains under_investigation until stronger evidence is available
```

The implemented likelihood assessment preserves:

- matched prerequisites
- unmatched prerequisites
- unknown prerequisites
- supporting A2A claim IDs
- contradicting claim IDs
- confidence score
- explanation
- provenance references

The likelihood layer must not infer `not_affected` merely because a firewall, IDS/IPS, authentication mechanism, or network segmentation exists. Those controls affect exposure and confidence but do not remove the vulnerability.

### A2A semantic evidence exchange

The A2A layer is used not only to separate services but also to exchange structured semantic evidence.

The evidence-fusion service normalizes claims into fields such as:

```text
claim_id
context_id
task_id
agent_name
skill_id
subject
predicate
value
confidence
evidence_type
artifact_id
source_reference
supports
contradicts
```

Example predicates include:

```text
requires_remote_reachability
requires_authentication
requires_service
requires_protocol
requires_feature
requires_user_interaction
requires_privilege
service_running
authentication_enforced
feature_enabled
component_reachable
```

A semantic decision service maps CVE requirements to asset facts and evaluates condition compatibility.

### A2A orchestration

- Discovers the Environment, Exploit, and Verification agents through Agent Cards
- Verifies that each agent advertises the expected skill
- Creates a shared `context_id` for the end-to-end analysis
- Assigns a unique `task_id` to each delegated stage
- Transfers input artifacts and stage outputs between agents
- Records task states, messages, and returned artifacts
- Propagates agent failures to the web-managed job state

### Environment preparation

- Organizes CVE knowledge and affected-version evidence
- Determines build tools, packages, services, and runtime prerequisites
- Obtains and checks out the target repository
- Builds or prepares the vulnerable software environment
- Reviews the environment before exploit execution

### Exploit generation and evaluation

- Generates or adapts a proof-of-concept for the selected CVE
- Executes the exploit against the prepared target
- Collects runtime output and intermediate artifacts
- Uses critic review to assess whether the observed behavior is relevant to the target vulnerability

### Verification and final assessment

- Generates or runs an automated verifier
- Evaluates whether the exploit result satisfies the reproduction condition
- Performs a final consistency review
- Separates workflow completion from vulnerability reproduction
- Produces one of the following reproduction states:

```text
confirmed
not_reproduced
inconclusive
unknown
not_attempted
```

`not_attempted` means source-based reproduction was not performed. It must not be interpreted as `not_reproduced` or `not_affected`.

### Job and evidence management

- Stores job metadata in SQLite
- Stores per-job inputs, logs, and result references
- Exposes live execution logs through the dashboard and API
- Discovers generated result directories and artifacts
- Preserves A2A communication records for later inspection
- Supports historical result backfilling for existing jobs

### Dashboard presentation

The dashboard provides:

- Total-job, running-job, reproduced-job, and review-required summaries
- A recent-job queue showing the 10 most recent analyses with CVE ID, job ID, and current status
- A stage indicator for queueing, extraction, validation, assessment, and completion
- Separate job-status and reproduction-verdict panels
- Exploitability, verifier result, and final-reason fields
- An asset operational-context form for source-unavailable jobs
- A likelihood result card showing `likely_affected`, `likely_not_affected`, or `under_investigation`
- Assessment confidence and the base VEX state
- Matched, unmatched, and unknown prerequisite counts
- Per-condition expected and observed values
- Assessment reasons
- Live execution logs
- Missing-field guidance
- A browser-based JSON editor
- Save-and-resume controls for incomplete jobs

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
│   │   ├── validation_service.py
│   │   ├── semantic_profile_service.py
│   │   ├── evidence_fusion_service.py
│   │   └── likelihood_assessment_service.py
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
Extract CVE context and semantic evidence
  ↓
Check source-code availability
  ├── source available
  │     ↓
  │   validate reproduction metadata
  │     ├── sufficient → run CVE-Genie
  │     └── incomplete → needs_input
  │
  └── source unavailable or unusable
        ↓
      needs_asset_input
        ↓
      base investigation state: under_investigation
        ↓
      collect asset operational context
        ↓
      fuse Data Processor and Builder evidence
        ↓
      compare semantic prerequisites
        ↓
      likely_affected / likely_not_affected /
      under_investigation

Source reproduction path:
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
needs_asset_input
ready
running
assessing_asset
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
not_attempted
```

The dashboard displays both values separately.

For asset-context jobs, the dashboard also displays:

```text
base_vex_status
likelihood_status
asset_assessment_status
asset_assessment_confidence
matched_conditions
unmatched_conditions
unknown_conditions
assessment reasons
```

The base VEX state remains `under_investigation` even when the advisory likelihood is `likely_affected` or `likely_not_affected`.

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

The reproduction and asset-context endpoints described below are implemented in the current web-service branch.



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

### Read asset operational input

```http
GET /api/jobs/{job_id}/asset-input
```

### Save asset operational input

```http
PUT /api/jobs/{job_id}/asset-input
```

Example request body:

```json
{
  "asset": {
    "product_name": "Example Server",
    "vendor": "Example Corporation",
    "installed_version": "4.2.1",
    "deployment_type": "server",
    "runtime": {
      "service_running": true,
      "vulnerable_feature_enabled": false,
      "component_loaded": true,
      "component_reachable": false
    },
    "exposure": {
      "internet_exposed": false,
      "reachable_networks": ["management"],
      "listening_ports": [443],
      "authentication_required": true
    },
    "security_controls": {
      "firewall_enabled": true,
      "network_segmentation": true,
      "ids_ips_enabled": true,
      "compensating_controls": []
    },
    "patch_status": "unknown",
    "evidence": [],
    "evidence_notes": "Operational context supplied by the asset operator."
  }
}
```

### Start semantic asset assessment

```http
POST /api/jobs/{job_id}/assess-asset
```

The endpoint queues the background asset-assessment worker and returns the queued job state. The completed likelihood result is available through:

```http
GET /api/jobs/{job_id}
GET /api/jobs/{job_id}/asset-input
```

The stored assessment data includes:

```text
base_vex_status
likelihood_status
asset_assessment_status
confidence
matched_conditions
unmatched_conditions
unknown_conditions
supporting_claim_ids
contradicting_claim_ids
reasons
semantic_profile
evidence_claims
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
7. Check source repository or source archive availability
8. If source is available, validate reproduction context
9. Pause with `needs_input` when source exists but reproduction metadata is incomplete
10. Pause with `needs_asset_input` when usable source cannot be obtained
11. Preserve `reproduction_status=not_attempted` for the asset-context path
12. Collect user-supplied asset operational context
13. Fuse CVE Data Processor and Builder semantic evidence
14. Estimate `likely_affected`, `likely_not_affected`, or `under_investigation`
15. For source-reproducible jobs, select `a2a` or `legacy` execution mode
16. Run `a2a_orchestrator.py` in A2A mode
17. Discover agent services through Agent Cards
18. Submit tasks with shared context and unique task IDs
19. Collect task states and returned artifacts
20. Store stdout, stderr, and A2A communication records
21. Locate the CVE-Genie result directory
22. Parse the final Results dictionary
23. Store the reproduction verdict or likelihood assessment
24. Expose status, verdict, likelihood, logs, and artifacts through the API
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
→ verifier_passed=false
→ exploitability was not demonstrated

A failed reproduction must not automatically be treated as proof that exploitation is impossible. The preferred long-term model keeps reproduction outcome and exploitability assessment separate.

missing or ambiguous final result
→ reproduction_status=inconclusive or unknown

source-based reproduction not performed
→ reproduction_status=not_attempted
→ exploitable=null
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
analysis_mode
source_availability
asset_input_json
asset_assessment_status
asset_impact_status
asset_assessment_confidence
asset_assessment_reasons_json
semantic_profile_json
evidence_claims_json
matched_conditions_json
unmatched_conditions_json
unknown_conditions_json
supporting_claim_ids_json
contradicting_claim_ids_json
base_vex_status
likelihood_status
exploitable
verifier_passed
final_reason
created_at
updated_at
started_at
finished_at
```

Current asset-assessment workflow states are:

```text
pending
sufficient
insufficient
assessing
assessed
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

### `/api/jobs` returns a Pydantic validation error for `asset_assessment_status`

Allowed values are:

```text
pending
sufficient
insufficient
assessing
assessed
```

Normalize older prototype values in SQLite:

```bash
python - <<'PY'
from cve_genie_web.database import db_session, initialize_database

initialize_database()

mapping = {
    "waiting_for_input": "pending",
    "queued": "pending",
    "completed": "assessed",
    "failed": "insufficient",
}

with db_session() as connection:
    for old_value, new_value in mapping.items():
        connection.execute(
            '''
            UPDATE jobs
            SET asset_assessment_status = ?
            WHERE asset_assessment_status = ?
            ''',
            (new_value, old_value),
        )

print("Asset assessment statuses normalized.")
PY
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
Semantic Evidence Preparation
  ├── CVE Data Processor
  ├── KnowledgeBuilder
  └── PreReqBuilder
  ↓
Source Availability Assessment
  ├── Source available
  │     ↓
  │   Reproduction Input Validation
  │     ├── incomplete → needs_input
  │     └── sufficient → A2A Orchestrator
  │                         ↓
  │                   Environment Agent
  │                   ├── KnowledgeBuilder
  │                   ├── PreReqBuilder
  │                   ├── RepoBuilder
  │                   └── RepoCritic
  │                         ↓
  │                     Exploit Agent
  │                   ├── Exploiter
  │                   └── ExploitCritic
  │                         ↓
  │                  Verification Agent
  │                   ├── CTFVerifier
  │                   └── SanityGuy
  │                         ↓
  │                Reproduction Verdict
  │
  └── Source unavailable
        ↓
      needs_asset_input
        ↓
      Base status: under_investigation
        ↓
      Asset Operational Context
        ↓
      A2A Semantic Evidence Fusion
        ↓
      Prerequisite Compatibility Assessment
        ↓
      likely_affected /
      likely_not_affected /
      under_investigation
        ↓
      Logs, Claims, Artifacts, and Provenance
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


# G) Current Functional Scope

The current implementation is a functional research prototype for evidence-driven CVE reproduction and source-unavailable asset-context likelihood assessment.

It currently supports:

- Local CVE List V5-based context extraction
- Web-managed CVE analysis jobs
- Partial-input preservation and analyst-assisted completion
- Source availability assessment and dual-path routing
- `needs_input` handling for incomplete source-reproduction jobs
- `needs_asset_input` handling for source-unavailable jobs
- Browser-based asset operational-context collection
- SQLite persistence for asset input, semantic profiles, normalized claims, condition evaluations, and likelihood results
- Automatic SQLite column migration for existing databases
- Semantic CVE prerequisite profile generation
- A2A evidence claim normalization and confidence-weighted fusion
- Contradiction detection for competing evidence
- Background asset likelihood assessment through `assess_asset_job()`
- Advisory `likely_affected`, `likely_not_affected`, and `under_investigation` results
- Preservation of `base_vex_status=under_investigation` for likelihood-only cases
- Preservation of `reproduction_status=not_attempted` when source execution is not performed
- Likelihood confidence, reasons, and condition-level results in the dashboard
- HTTP-based A2A discovery and task delegation
- Environment, exploit, and verification stage separation
- Legacy CVE-Genie execution as a fallback mode
- Job, log, artifact, verdict, and likelihood persistence
- Browser-based monitoring and result review

The current implementation does not yet provide:

- Automatic normalized Claim emission from every Data Processor, `KnowledgeBuilder`, `PreReqBuilder`, and related Builder component
- Direct collection of live asset evidence through SSH, EDR, CMDB, SBOM platforms, configuration managers, or network scanners
- Final VEX assertions derived automatically from likelihood estimates
- Official machine-readable VEX document generation
- Strong per-job exploit isolation
- Multi-user authentication and authorization
- Distributed worker recovery
- Durable message queues
- Full interoperability with every optional feature of the upstream A2A specification

A firewall, IDS/IPS, authentication control, or network segmentation may reduce exposure, but it does not by itself prove that a vulnerable component is absent, fixed, or not affected. Likelihood results must remain separate from final VEX assertions.

# H) Recommended Development Roadmap

The next development priorities are:

1. Add automatic normalized Claim emission to the CVE Data Processor, `KnowledgeBuilder`, `PreReqBuilder`, `RepoBuilder`, and critic components.
2. Attach stronger provenance links between raw CVE records, A2A messages, generated artifacts, normalized claims, condition evaluations, and final outcomes.
3. Add direct evidence adapters for SBOM inventories, service managers, process lists, firewall rules, configuration files, EDR, CMDB, and network scanners.
4. Display active agent, context ID, task ID, skill ID, claim provenance, and returned artifacts in the dashboard.
5. Add Server-Sent Events or WebSocket-based live updates.
6. Replace FastAPI `BackgroundTasks` with Redis and Celery or RQ.
7. Add durable task persistence, retry policies, cancellation, polling, and worker failure recovery.
8. Run each reproduction task in a disposable container or VM with strict resource and network controls.
9. Define evidentiary thresholds for promoting an investigation result to `affected`, `not_affected`, or `fixed`.
10. Generate machine-readable VEX documents only when those evidentiary requirements are satisfied.
11. Add authentication, authorization, and per-user job history.
12. Replace SQLite with PostgreSQL for multi-worker deployments.
13. Add resource quotas, retention rules, and automatic cleanup.
14. Add automated tests for source routing, semantic profile generation, evidence fusion, contradiction handling, likelihood thresholds, task transitions, failure propagation, and legacy fallback.

---

# I) Quick Start

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
