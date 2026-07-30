const form = document.getElementById("job-form");
const jobsElement = document.getElementById("jobs");
const detailElement = document.getElementById("job-detail");
const logElement = document.getElementById("job-log");
const messageElement = document.getElementById("form-message");
const refreshButton = document.getElementById("refresh-button");

const totalCount = document.getElementById("total-count");
const runningCount = document.getElementById("running-count");
const successCount = document.getElementById("success-count");
const failedCount = document.getElementById("failed-count");

const selectedStatus = document.getElementById("selected-status");
const detailCve = document.getElementById("detail-cve");
const detailJobStatus = document.getElementById("detail-job-status");
const detailJob = document.getElementById("detail-job");
const detailStage = document.getElementById("detail-stage");

const verdictTitle = document.getElementById("verdict-title");
const verdictBadge = document.getElementById("verdict-badge");
const verdictExploitable = document.getElementById("verdict-exploitable");
const verdictVerifier = document.getElementById("verdict-verifier");
const verdictReason = document.getElementById("verdict-reason");

const inputEditor = document.getElementById("input-editor");
const inputJsonEditor = document.getElementById("input-json-editor");
const missingFieldsElement = document.getElementById("missing-fields");
const resumeButton = document.getElementById("resume-button");
const editorMessage = document.getElementById("editor-message");

let selectedJobId = null;
let pollTimer = null;
let loadedInputForJobId = null;

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.json();

  if (!response.ok) {
    throw new Error(body.detail || `Request failed: ${response.status}`);
  }
  return body;
}

function statusClass(status) {
  if (status === "succeeded") return "success";
  if (["failed", "cancelled", "unsupported"].includes(status)) return "failed";
  if (status === "needs_input") return "needs-input";
  if (["queued", "extracting", "validating", "ready", "running"].includes(status)) {
    return "running";
  }
  return "neutral";
}

function verdictClass(status) {
  if (status === "confirmed") return "confirmed";
  if (status === "not_reproduced") return "not-reproduced";
  if (status === "inconclusive") return "inconclusive";
  return "unknown";
}

function verdictLabel(status) {
  const labels = {
    confirmed: "CONFIRMED",
    not_reproduced: "NOT REPRODUCED",
    inconclusive: "INCONCLUSIVE",
    unknown: "UNKNOWN",
  };
  return labels[status] || "UNKNOWN";
}

function updateStats(jobs) {
  totalCount.textContent = jobs.length;
  runningCount.textContent = jobs.filter((job) =>
    ["queued", "extracting", "validating", "ready", "running"].includes(job.status)
  ).length;
  successCount.textContent = jobs.filter((job) =>
    job.reproduction_status === "confirmed"
  ).length;
  failedCount.textContent = jobs.filter((job) =>
    ["needs_input", "failed", "unsupported", "cancelled"].includes(job.status)
    || ["not_reproduced", "inconclusive"].includes(job.reproduction_status)
  ).length;
}

function renderJobs(jobs) {
  updateStats(jobs);

  if (!jobs.length) {
    jobsElement.innerHTML = '<div class="empty-state">No jobs yet.</div>';
    return;
  }

  jobsElement.innerHTML = jobs.map((job) => {
    const secondary = job.reproduction_status !== "unknown"
      ? verdictLabel(job.reproduction_status)
      : job.status;

    const secondaryClass = job.reproduction_status !== "unknown"
      ? verdictClass(job.reproduction_status)
      : statusClass(job.status);

    return `
      <button
        class="job-card ${selectedJobId === job.job_id ? "active" : ""}"
        data-job-id="${job.job_id}"
      >
        <strong>${job.cve_id}</strong>
        <span class="job-status ${secondaryClass}">${secondary}</span>
        <small>${job.job_id}</small>
      </button>
    `;
  }).join("");

  document.querySelectorAll(".job-card").forEach((button) => {
    button.addEventListener("click", () => selectJob(button.dataset.jobId));
  });
}

function updateProgress(status) {
  const order = ["queued", "extracting", "validating", "running", "succeeded"];
  let activeIndex = order.indexOf(status);

  if (status === "ready") activeIndex = 3;
  if (["needs_input", "unsupported"].includes(status)) activeIndex = 2;
  if (["failed", "cancelled"].includes(status)) activeIndex = 3;

  document.querySelectorAll(".step").forEach((step, index) => {
    step.classList.remove("active", "done");
    if (index < activeIndex) step.classList.add("done");
    else if (index === activeIndex) step.classList.add("active");
  });
}

function renderVerdict(job) {
  const status = job.reproduction_status || "unknown";
  const label = verdictLabel(status);

  verdictBadge.textContent = label;
  verdictBadge.className = `verdict-badge ${verdictClass(status)}`;

  const titles = {
    confirmed: "CVE reproduction confirmed",
    not_reproduced: "CVE was not reproduced",
    inconclusive: "Reproduction result is inconclusive",
    unknown: "Reproduction not evaluated",
  };

  verdictTitle.textContent = titles[status] || titles.unknown;
  verdictExploitable.textContent =
    job.exploitable === true ? "TRUE"
    : job.exploitable === false ? "FALSE"
    : "-";
  verdictVerifier.textContent =
    job.verifier_passed === true ? "PASSED"
    : job.verifier_passed === false ? "FAILED"
    : "-";
  verdictReason.textContent = job.final_reason || "No final result yet.";
}

async function loadInputEditor(job) {
  const editableStatuses = ["needs_input", "failed", "unsupported"];

  if (!editableStatuses.includes(job.status)) {
    inputEditor.classList.add("hidden");
    loadedInputForJobId = null;
    return;
  }

  inputEditor.classList.remove("hidden");

  const missing = job.missing_fields || [];
  missingFieldsElement.textContent = missing.length
    ? `Missing: ${missing.join(", ")}`
    : "Review or supplement the extracted JSON before resuming.";

  if (loadedInputForJobId === job.job_id) return;

  try {
    const input = await requestJson(`/api/jobs/${job.job_id}/input`);
    inputJsonEditor.value = JSON.stringify(input.data, null, 2);
    loadedInputForJobId = job.job_id;
    editorMessage.textContent = "";
  } catch (error) {
    inputJsonEditor.value = "";
    editorMessage.textContent = error.message;
  }
}

async function renderSelectedJob(job) {
  selectedStatus.textContent = job.status;
  selectedStatus.className = `status-badge ${statusClass(job.status)}`;

  detailCve.textContent = job.cve_id || "-";
  detailJobStatus.textContent = job.status || "-";
  detailJob.textContent = job.job_id || "-";
  detailStage.textContent = job.stage || "-";

  detailElement.textContent = JSON.stringify(job, null, 2);
  updateProgress(job.status);
  renderVerdict(job);
  await loadInputEditor(job);
}

async function loadJobs() {
  try {
    renderJobs(await requestJson("/api/jobs"));
  } catch (error) {
    jobsElement.innerHTML = `<div class="empty-state">${error.message}</div>`;
  }
}

async function selectJob(jobId) {
  selectedJobId = jobId;
  loadedInputForJobId = null;
  await refreshSelectedJob();
  await loadJobs();

  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(refreshSelectedJob, 2000);
}

async function refreshSelectedJob() {
  if (!selectedJobId) return;

  try {
    const [job, log] = await Promise.all([
      requestJson(`/api/jobs/${selectedJobId}`),
      requestJson(`/api/jobs/${selectedJobId}/log`),
    ]);

    await renderSelectedJob(job);
    logElement.textContent = log.content || "Log is empty.";
    logElement.scrollTop = logElement.scrollHeight;

    if (["succeeded", "needs_input", "failed", "unsupported", "cancelled"].includes(job.status)) {
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = null;
      await loadJobs();
    }
  } catch (error) {
    detailElement.textContent = error.message;
  }
}

resumeButton.addEventListener("click", async () => {
  if (!selectedJobId) return;

  editorMessage.textContent = "Validating JSON...";

  try {
    const data = JSON.parse(inputJsonEditor.value);

    await requestJson(`/api/jobs/${selectedJobId}/input`, {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({data}),
    });

    await requestJson(`/api/jobs/${selectedJobId}/resume`, {
      method: "POST",
    });

    editorMessage.textContent = "Saved. Job resumed.";
    loadedInputForJobId = null;
    await selectJob(selectedJobId);
  } catch (error) {
    editorMessage.textContent = error.message;
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  messageElement.textContent = "Submitting job...";

  try {
    const cveId = document.getElementById("cve-id").value.trim().toUpperCase();
    const job = await requestJson("/api/jobs", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        cve_id: cveId,
        run_type: "build,exploit,verify",
      }),
    });

    messageElement.textContent = `Created job ${job.job_id}`;
    form.reset();
    await loadJobs();
    await selectJob(job.job_id);
  } catch (error) {
    messageElement.textContent = error.message;
  }
});

refreshButton.addEventListener("click", loadJobs);
loadJobs();
