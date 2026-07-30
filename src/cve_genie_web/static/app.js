"use strict";


/*
 * ==========================================================================
 * DOM elements
 * ==========================================================================
 */

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

const selectedStatus = document.getElementById(
  "selected-status"
);

const detailCve = document.getElementById(
  "detail-cve"
);

const detailJobStatus = document.getElementById(
  "detail-job-status"
);

const detailJob = document.getElementById(
  "detail-job"
);

const detailStage = document.getElementById(
  "detail-stage"
);

const verdictTitle = document.getElementById(
  "verdict-title"
);

const verdictBadge = document.getElementById(
  "verdict-badge"
);

const verdictExploitable = document.getElementById(
  "verdict-exploitable"
);

const verdictVerifier = document.getElementById(
  "verdict-verifier"
);

const verdictReason = document.getElementById(
  "verdict-reason"
);


/*
 * Existing manual CVE reproduction JSON editor.
 */

const inputEditor = document.getElementById(
  "input-editor"
);

const inputJsonEditor = document.getElementById(
  "input-json-editor"
);

const missingFieldsElement = document.getElementById(
  "missing-fields"
);

const resumeButton = document.getElementById(
  "resume-button"
);

const editorMessage = document.getElementById(
  "editor-message"
);


/*
 * Asset operational context editor.
 */

const assetInputPanel = document.getElementById(
  "asset-input-panel"
);

const assetInputForm = document.getElementById(
  "asset-input-form"
);

const assetJobId = document.getElementById(
  "asset-job-id"
);

const assetCveId = document.getElementById(
  "asset-cve-id"
);

const assetSubmitButton = document.getElementById(
  "asset-submit-button"
);

const assetFormMessage = document.getElementById(
  "asset-form-message"
);


const likelihoodCard = document.getElementById(
  "likelihood-card"
);

const likelihoodTitle = document.getElementById(
  "likelihood-title"
);

const likelihoodBadge = document.getElementById(
  "likelihood-badge"
);

const likelihoodConfidence = document.getElementById(
  "likelihood-confidence"
);

const assetAssessmentStatus = document.getElementById(
  "asset-assessment-status"
);

const baseVexStatus = document.getElementById(
  "base-vex-status"
);

const matchedCount = document.getElementById(
  "matched-count"
);

const unmatchedCount = document.getElementById(
  "unmatched-count"
);

const unknownCount = document.getElementById(
  "unknown-count"
);

const matchedConditions = document.getElementById(
  "matched-conditions"
);

const unmatchedConditions = document.getElementById(
  "unmatched-conditions"
);

const unknownConditions = document.getElementById(
  "unknown-conditions"
);

const likelihoodReasons = document.getElementById(
  "likelihood-reasons"
);



/*
 * ==========================================================================
 * Client state
 * ==========================================================================
 */

let selectedJobId = null;
let pollTimer = null;
let loadedInputForJobId = null;
let loadedAssetForJobId = null;


/*
 * ==========================================================================
 * HTTP helpers
 * ==========================================================================
 */

async function requestJson(
  url,
  options = {},
) {
  const response = await fetch(
    url,
    options,
  );

  let body = null;

  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (!response.ok) {
    let detail = (
      `Request failed: ${response.status}`
    );

    if (
      body
      && typeof body.detail === "string"
    ) {
      detail = body.detail;
    } else if (
      body
      && Array.isArray(body.detail)
    ) {
      detail = body.detail
        .map((item) => {
          if (
            item
            && typeof item.msg === "string"
          ) {
            return item.msg;
          }

          return JSON.stringify(item);
        })
        .join("; ");
    } else if (
      body
      && typeof body.message === "string"
    ) {
      detail = body.message;
    }

    throw new Error(detail);
  }

  return body;
}


/*
 * ==========================================================================
 * Generic UI helpers
 * ==========================================================================
 */

function setText(
  element,
  value,
) {
  if (!element) {
    return;
  }

  element.textContent = (
    value === null
    || value === undefined
      ? ""
      : String(value)
  );
}


function showElement(element) {
  if (!element) {
    return;
  }

  element.classList.remove("hidden");
}


function hideElement(element) {
  if (!element) {
    return;
  }

  element.classList.add("hidden");
}


function stopPolling() {
  if (!pollTimer) {
    return;
  }

  clearInterval(pollTimer);
  pollTimer = null;
}


function startPolling() {
  stopPolling();

  pollTimer = setInterval(
    refreshSelectedJob,
    2000,
  );
}


function normalizeStatusLabel(status) {
  const labels = {
    queued: "QUEUED",
    extracting: "EXTRACTING",
    validating: "VALIDATING",
    needs_input: "NEEDS INPUT",
    needs_asset_input: "NEEDS ASSET INPUT",
    ready: "READY",
    running: "RUNNING",
    assessing_asset: "ASSESSING ASSET",
    succeeded: "SUCCEEDED",
    failed: "FAILED",
    unsupported: "UNSUPPORTED",
    cancelled: "CANCELLED",
  };

  if (labels[status]) {
    return labels[status];
  }

  return String(status || "unknown")
    .replaceAll("_", " ")
    .toUpperCase();
}


function statusClass(status) {
  if (status === "succeeded") {
    return "success";
  }

  if (
    [
      "failed",
      "cancelled",
      "unsupported",
    ].includes(status)
  ) {
    return "failed";
  }

  if (status === "needs_input") {
    return "needs-input";
  }

  if (status === "needs_asset_input") {
    return "needs-asset-input";
  }

  if (
    [
      "queued",
      "extracting",
      "validating",
      "ready",
      "running",
      "assessing_asset",
    ].includes(status)
  ) {
    return "running";
  }

  return "neutral";
}


function verdictClass(status) {
  if (status === "confirmed") {
    return "confirmed";
  }

  if (status === "not_reproduced") {
    return "not-reproduced";
  }

  if (status === "inconclusive") {
    return "inconclusive";
  }

  if (status === "not_attempted") {
    return "not-attempted";
  }

  return "unknown";
}


function verdictLabel(status) {
  const labels = {
    confirmed: "CONFIRMED",
    not_reproduced: "NOT REPRODUCED",
    inconclusive: "INCONCLUSIVE",
    unknown: "UNKNOWN",
    not_attempted: "NOT ATTEMPTED",
  };

  return labels[status] || "UNKNOWN";
}


function isActiveStatus(status) {
  return [
    "queued",
    "extracting",
    "validating",
    "ready",
    "running",
    "assessing_asset",
  ].includes(status);
}


function isPausedOrTerminalStatus(status) {
  return [
    "succeeded",
    "needs_input",
    "needs_asset_input",
    "failed",
    "unsupported",
    "cancelled",
  ].includes(status);
}


function getJobCreatedTime(job) {
  const timestamp = Date.parse(
    job.created_at || "",
  );

  if (Number.isNaN(timestamp)) {
    return 0;
  }

  return timestamp;
}


/*
 * ==========================================================================
 * Input conversion helpers
 * ==========================================================================
 */

function parseNullableBoolean(value) {
  if (
    value === true
    || value === "true"
  ) {
    return true;
  }

  if (
    value === false
    || value === "false"
  ) {
    return false;
  }

  return null;
}


function nullableBooleanToFormValue(value) {
  if (value === true) {
    return "true";
  }

  if (value === false) {
    return "false";
  }

  return "";
}


function parseCommaSeparatedStrings(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}


function parsePorts(value) {
  const rawItems = (
    parseCommaSeparatedStrings(value)
  );

  const ports = [];
  const invalidPorts = [];

  for (const rawItem of rawItems) {
    const port = Number(rawItem);

    if (
      !Number.isInteger(port)
      || port < 1
      || port > 65535
    ) {
      invalidPorts.push(rawItem);
      continue;
    }

    if (!ports.includes(port)) {
      ports.push(port);
    }
  }

  if (invalidPorts.length) {
    throw new Error(
      "Invalid port values: "
      + invalidPorts.join(", "),
    );
  }

  return ports;
}


function getInputValue(elementId) {
  const element = document.getElementById(
    elementId,
  );

  if (!element) {
    return "";
  }

  return element.value;
}


function setInputValue(
  elementId,
  value,
) {
  const element = document.getElementById(
    elementId,
  );

  if (!element) {
    return;
  }

  element.value = value ?? "";
}


/*
 * ==========================================================================
 * Dashboard statistics
 * ==========================================================================
 */

function updateStats(jobs) {
  /*
   * Statistics are calculated from all jobs returned
   * by the API, not only the 10 recent jobs displayed.
   */

  setText(
    totalCount,
    jobs.length,
  );

  setText(
    runningCount,
    jobs.filter((job) =>
      isActiveStatus(job.status)
    ).length,
  );

  setText(
    successCount,
    jobs.filter((job) =>
      job.reproduction_status === "confirmed"
    ).length,
  );

  setText(
    failedCount,
    jobs.filter((job) =>
      [
        "needs_input",
        "needs_asset_input",
        "failed",
        "unsupported",
        "cancelled",
      ].includes(job.status)
      || [
        "not_reproduced",
        "inconclusive",
      ].includes(job.reproduction_status)
    ).length,
  );
}


/*
 * ==========================================================================
 * Recent jobs list
 * ==========================================================================
 */

function renderJobs(jobs) {
  const normalizedJobs = Array.isArray(jobs)
    ? jobs
    : [];

  /*
   * Dashboard totals use all jobs.
   */
  updateStats(normalizedJobs);

  /*
   * Recent jobs displays only the latest 10 records.
   * A copied array is sorted so the original API result
   * remains unchanged.
   */
  const recentJobs = [...normalizedJobs]
    .sort((left, right) =>
      getJobCreatedTime(right)
      - getJobCreatedTime(left)
    )
    .slice(0, 10);

  if (!jobsElement) {
    return;
  }

  if (!recentJobs.length) {
    jobsElement.innerHTML = (
      '<div class="empty-state">'
      + "No jobs yet."
      + "</div>"
    );

    return;
  }

  jobsElement.innerHTML = recentJobs
    .map((job) => {
      /*
       * confirmed, not_reproduced and inconclusive
       * are final reproduction results.
       *
       * not_attempted does not override the job status
       * when asset input is required. In that state,
       * NEEDS ASSET INPUT is more useful to the user.
       */
      const hasFinalReproductionVerdict = [
        "confirmed",
        "not_reproduced",
        "inconclusive",
      ].includes(job.reproduction_status);

      let secondary = normalizeStatusLabel(
        job.status,
      );

      let secondaryClass = statusClass(
        job.status,
      );

      if (hasFinalReproductionVerdict) {
        secondary = verdictLabel(
          job.reproduction_status,
        );

        secondaryClass = verdictClass(
          job.reproduction_status,
        );
      } else if (
        job.reproduction_status === "not_attempted"
        && job.status !== "needs_asset_input"
      ) {
        secondary = verdictLabel(
          "not_attempted",
        );

        secondaryClass = verdictClass(
          "not_attempted",
        );
      }

      const activeClass = (
        selectedJobId === job.job_id
          ? "active"
          : ""
      );

      return `
        <button
          class="job-card ${activeClass}"
          data-job-id="${job.job_id}"
          type="button"
        >
          <strong>${job.cve_id}</strong>

          <span
            class="job-status ${secondaryClass}"
          >
            ${secondary}
          </span>

          <small>${job.job_id}</small>
        </button>
      `;
    })
    .join("");

  document
    .querySelectorAll(".job-card")
    .forEach((button) => {
      button.addEventListener(
        "click",
        () => {
          selectJob(
            button.dataset.jobId,
          );
        },
      );
    });
}


/*
 * ==========================================================================
 * Progress indicator
 * ==========================================================================
 */

function updateProgress(status) {
  const statusToIndex = {
    queued: 0,
    extracting: 1,
    validating: 2,
    needs_input: 2,
    needs_asset_input: 2,
    ready: 3,
    running: 3,
    assessing_asset: 3,
    succeeded: 4,
    failed: 3,
    unsupported: 2,
    cancelled: 3,
  };

  const activeIndex = (
    Object.hasOwn(statusToIndex, status)
      ? statusToIndex[status]
      : 0
  );

  document
    .querySelectorAll(".step")
    .forEach((step, index) => {
      step.classList.remove(
        "active",
        "done",
      );

      if (index < activeIndex) {
        step.classList.add("done");
      } else if (index === activeIndex) {
        step.classList.add("active");
      }
    });
}


/*
 * ==========================================================================
 * Reproduction verdict
 * ==========================================================================
 */

function renderVerdict(job) {
  const status = (
    job.reproduction_status
    || "unknown"
  );

  const label = verdictLabel(status);

  if (verdictBadge) {
    verdictBadge.textContent = label;
    verdictBadge.className = (
      `verdict-badge ${verdictClass(status)}`
    );
  }

  const titles = {
    confirmed: "CVE reproduction confirmed",
    not_reproduced: "CVE was not reproduced",
    inconclusive: (
      "Reproduction result is inconclusive"
    ),
    unknown: "Reproduction not evaluated",
    not_attempted: (
      "Source-based reproduction was not attempted"
    ),
  };

  setText(
    verdictTitle,
    titles[status] || titles.unknown,
  );

  setText(
    verdictExploitable,
    job.exploitable === true
      ? "TRUE"
      : job.exploitable === false
        ? "FALSE"
        : "-",
  );

  setText(
    verdictVerifier,
    job.verifier_passed === true
      ? "PASSED"
      : job.verifier_passed === false
        ? "FAILED"
        : "-",
  );

  let reason = job.final_reason;

  if (!reason && status === "not_attempted") {
    reason = (
      "Source code was unavailable. "
      + "Asset operational information is required."
    );
  }

  setText(
    verdictReason,
    reason || "No final result yet.",
  );
}



function likelihoodLabel(status) {
  const labels = {
    likely_affected: "LIKELY AFFECTED",
    likely_not_affected: "LIKELY NOT AFFECTED",
    under_investigation: "UNDER INVESTIGATION",
  };

  return labels[status] || "UNDER INVESTIGATION";
}


function likelihoodClass(status) {
  if (status === "likely_affected") {
    return "likely-affected";
  }

  if (status === "likely_not_affected") {
    return "likely-not-affected";
  }

  return "under-investigation";
}


function conditionDisplayValue(value) {
  if (value === null || value === undefined) {
    return "unknown";
  }

  if (typeof value === "object") {
    return JSON.stringify(value);
  }

  return String(value);
}


function renderConditionList(
  element,
  conditions,
  emptyText,
) {
  if (!element) {
    return;
  }

  const normalized = Array.isArray(conditions)
    ? conditions
    : [];

  if (!normalized.length) {
    element.innerHTML = (
      `<p class="condition-empty">${emptyText}</p>`
    );
    return;
  }

  element.innerHTML = normalized
    .map((condition) => {
      const predicate = (
        condition.predicate
        || condition.condition_id
        || "condition"
      );

      const expected = conditionDisplayValue(
        condition.expected_value,
      );

      const observed = conditionDisplayValue(
        condition.observed_value,
      );

      return `
        <article class="condition-item">
          <strong>${predicate}</strong>
          <span>
            Expected: ${expected}
          </span>
          <span>
            Observed: ${observed}
          </span>
        </article>
      `;
    })
    .join("");
}


function hideLikelihoodCard() {
  hideElement(likelihoodCard);
}


function renderLikelihoodAssessment(
  assessment,
) {
  if (
    !assessment
    || assessment.analysis_mode
      !== "asset_context_assessment"
  ) {
    hideLikelihoodCard();
    return;
  }

  showElement(likelihoodCard);

  const status = (
    assessment.likelihood_status
    || "under_investigation"
  );

  if (likelihoodBadge) {
    likelihoodBadge.textContent = (
      likelihoodLabel(status)
    );

    likelihoodBadge.className = (
      `likelihood-badge ${likelihoodClass(status)}`
    );
  }

  const titles = {
    likely_affected: (
      "Asset conditions likely support exploitation"
    ),
    likely_not_affected: (
      "Asset conditions likely do not support exploitation"
    ),
    under_investigation: (
      "More operational evidence is required"
    ),
  };

  setText(
    likelihoodTitle,
    titles[status] || titles.under_investigation,
  );

  const confidence = assessment.confidence;

  setText(
    likelihoodConfidence,
    typeof confidence === "number"
      ? `${Math.round(confidence * 100)}%`
      : "-",
  );

  setText(
    assetAssessmentStatus,
    assessment.asset_assessment_status || "-",
  );

  setText(
    baseVexStatus,
    assessment.base_vex_status
      || "under_investigation",
  );

  const matched = (
    Array.isArray(assessment.matched_conditions)
      ? assessment.matched_conditions
      : []
  );

  const unmatched = (
    Array.isArray(assessment.unmatched_conditions)
      ? assessment.unmatched_conditions
      : []
  );

  const unknown = (
    Array.isArray(assessment.unknown_conditions)
      ? assessment.unknown_conditions
      : []
  );

  setText(matchedCount, matched.length);
  setText(unmatchedCount, unmatched.length);
  setText(unknownCount, unknown.length);

  renderConditionList(
    matchedConditions,
    matched,
    "No matched conditions.",
  );

  renderConditionList(
    unmatchedConditions,
    unmatched,
    "No unmatched conditions.",
  );

  renderConditionList(
    unknownConditions,
    unknown,
    "No unknown conditions.",
  );

  if (likelihoodReasons) {
    const reasons = (
      Array.isArray(assessment.reasons)
        ? assessment.reasons
        : []
    );

    likelihoodReasons.innerHTML = (
      reasons.length
        ? reasons
          .map((reason) => `<li>${reason}</li>`)
          .join("")
        : "<li>No assessment reason available.</li>"
    );
  }
}


async function loadLikelihoodAssessment(job) {
  const isAssetJob = (
    job.analysis_mode === "asset_context_assessment"
    || job.reproduction_status === "not_attempted"
    || [
      "needs_asset_input",
      "assessing_asset",
    ].includes(job.status)
  );

  if (!isAssetJob) {
    hideLikelihoodCard();
    return;
  }

  try {
    const assessment = await requestJson(
      `/api/jobs/${job.job_id}/asset-input`,
    );

    renderLikelihoodAssessment(assessment);
  } catch (error) {
    showElement(likelihoodCard);

    renderLikelihoodAssessment({
      analysis_mode: "asset_context_assessment",
      likelihood_status: "under_investigation",
      base_vex_status: "under_investigation",
      asset_assessment_status: "unavailable",
      confidence: null,
      matched_conditions: [],
      unmatched_conditions: [],
      unknown_conditions: [],
      reasons: [error.message],
    });
  }
}


/*
 * ==========================================================================
 * Existing reproduction JSON editor
 * ==========================================================================
 */

async function loadInputEditor(job) {
  const editableStatuses = [
    "needs_input",
    "failed",
    "unsupported",
  ];

  if (!inputEditor) {
    return;
  }

  if (!editableStatuses.includes(job.status)) {
    hideElement(inputEditor);
    loadedInputForJobId = null;
    return;
  }

  showElement(inputEditor);
  hideAssetInputPanel();

  const missing = (
    Array.isArray(job.missing_fields)
      ? job.missing_fields
      : []
  );

  setText(
    missingFieldsElement,
    missing.length
      ? `Missing: ${missing.join(", ")}`
      : (
        "Review or supplement the extracted "
        + "JSON before resuming."
      ),
  );

  if (loadedInputForJobId === job.job_id) {
    return;
  }

  try {
    const input = await requestJson(
      `/api/jobs/${job.job_id}/input`,
    );

    if (inputJsonEditor) {
      inputJsonEditor.value = JSON.stringify(
        input.data,
        null,
        2,
      );
    }

    loadedInputForJobId = job.job_id;

    setText(
      editorMessage,
      "",
    );
  } catch (error) {
    if (inputJsonEditor) {
      inputJsonEditor.value = "";
    }

    setText(
      editorMessage,
      error.message,
    );
  }
}


/*
 * ==========================================================================
 * Asset operational context editor
 * ==========================================================================
 */

function hideAssetInputPanel() {
  hideElement(assetInputPanel);
  loadedAssetForJobId = null;
}


function showAssetInputPanel(job) {
  if (!assetInputPanel) {
    return;
  }

  showElement(assetInputPanel);
  hideElement(inputEditor);

  if (assetJobId) {
    assetJobId.value = job.job_id;
  }

  setText(
    assetCveId,
    job.cve_id || "this CVE",
  );

  const missing = (
    Array.isArray(job.missing_fields)
      ? job.missing_fields
      : []
  );

  setText(
    assetFormMessage,
    missing.length
      ? (
        "Required information: "
        + missing.join(", ")
      )
      : (
        "Enter the deployed asset information "
        + "to continue."
      ),
  );
}


function resetAssetForm() {
  if (assetInputForm) {
    assetInputForm.reset();
  }

  setInputValue(
    "asset-deployment-type",
    "unknown",
  );

  setInputValue(
    "asset-internet-exposed",
    "false",
  );

  setInputValue(
    "asset-patch-status",
    "unknown",
  );
}


function populateAssetForm(asset) {
  if (
    !asset
    || typeof asset !== "object"
  ) {
    return;
  }

  setInputValue(
    "asset-product-name",
    asset.product_name,
  );

  setInputValue(
    "asset-vendor",
    asset.vendor,
  );

  setInputValue(
    "asset-installed-version",
    asset.installed_version,
  );

  setInputValue(
    "asset-operating-system",
    asset.operating_system,
  );

  setInputValue(
    "asset-architecture",
    asset.architecture,
  );

  setInputValue(
    "asset-deployment-type",
    asset.deployment_type || "unknown",
  );

  const runtime = asset.runtime || {};

  setInputValue(
    "asset-service-running",
    nullableBooleanToFormValue(
      runtime.service_running,
    ),
  );

  setInputValue(
    "asset-feature-enabled",
    nullableBooleanToFormValue(
      runtime.vulnerable_feature_enabled,
    ),
  );

  setInputValue(
    "asset-component-loaded",
    nullableBooleanToFormValue(
      runtime.component_loaded,
    ),
  );

  setInputValue(
    "asset-component-reachable",
    nullableBooleanToFormValue(
      runtime.component_reachable,
    ),
  );

  setInputValue(
    "asset-service-name",
    runtime.service_name,
  );

  setInputValue(
    "asset-process-name",
    runtime.process_name,
  );

  const exposure = asset.exposure || {};

  setInputValue(
    "asset-internet-exposed",
    exposure.internet_exposed === true
      ? "true"
      : "false",
  );

  setInputValue(
    "asset-listening-ports",
    Array.isArray(exposure.listening_ports)
      ? exposure.listening_ports.join(", ")
      : "",
  );

  setInputValue(
    "asset-reachable-networks",
    Array.isArray(exposure.reachable_networks)
      ? exposure.reachable_networks.join(", ")
      : "",
  );

  setInputValue(
    "asset-auth-required",
    nullableBooleanToFormValue(
      exposure.authentication_required,
    ),
  );

  const controls = (
    asset.security_controls || {}
  );

  setInputValue(
    "asset-firewall-enabled",
    nullableBooleanToFormValue(
      controls.firewall_enabled,
    ),
  );

  setInputValue(
    "asset-network-segmentation",
    nullableBooleanToFormValue(
      controls.network_segmentation,
    ),
  );

  setInputValue(
    "asset-ids-enabled",
    nullableBooleanToFormValue(
      controls.ids_ips_enabled,
    ),
  );

  setInputValue(
    "asset-patch-status",
    asset.patch_status || "unknown",
  );

  setInputValue(
    "asset-evidence-notes",
    asset.evidence_notes,
  );
}


async function loadAssetInput(job) {
  if (
    job.status !== "needs_asset_input"
    && job.status !== "failed"
    && !(
      job.status === "succeeded"
      && job.analysis_mode === "asset_context_assessment"
    )
  ) {
    hideAssetInputPanel();
    return;
  }

  showAssetInputPanel(job);

  if (loadedAssetForJobId === job.job_id) {
    return;
  }

  resetAssetForm();

  /*
   * Load previously saved asset information when
   * the GET endpoint is implemented.
   *
   * If the endpoint returns 404, the blank form
   * remains available.
   */
  try {
    const response = await requestJson(
      `/api/jobs/${job.job_id}/asset-input`,
    );

    if (
      response
      && response.asset
    ) {
      populateAssetForm(
        response.asset,
      );
    }

    loadedAssetForJobId = job.job_id;
  } catch (error) {
    const message = String(
      error.message || "",
    ).toLowerCase();

    if (
      message.includes("404")
      || message.includes("not found")
    ) {
      loadedAssetForJobId = job.job_id;
      return;
    }

    setText(
      assetFormMessage,
      error.message,
    );
  }
}


function collectAssetInput() {
  const productName = getInputValue(
    "asset-product-name",
  ).trim();

  const installedVersion = getInputValue(
    "asset-installed-version",
  ).trim();

  if (!productName) {
    throw new Error(
      "Product name is required.",
    );
  }

  if (!installedVersion) {
    throw new Error(
      "Installed version is required.",
    );
  }

  return {
    product_name: productName,

    vendor: (
      getInputValue(
        "asset-vendor",
      ).trim()
      || null
    ),

    installed_version: installedVersion,

    operating_system: (
      getInputValue(
        "asset-operating-system",
      ).trim()
      || null
    ),

    architecture: (
      getInputValue(
        "asset-architecture",
      ).trim()
      || null
    ),

    deployment_type: (
      getInputValue(
        "asset-deployment-type",
      )
      || "unknown"
    ),

    runtime: {
      service_running: parseNullableBoolean(
        getInputValue(
          "asset-service-running",
        ),
      ),

      vulnerable_feature_enabled:
        parseNullableBoolean(
          getInputValue(
            "asset-feature-enabled",
          ),
        ),

      component_loaded:
        parseNullableBoolean(
          getInputValue(
            "asset-component-loaded",
          ),
        ),

      component_reachable:
        parseNullableBoolean(
          getInputValue(
            "asset-component-reachable",
          ),
        ),

      service_name: (
        getInputValue(
          "asset-service-name",
        ).trim()
        || null
      ),

      process_name: (
        getInputValue(
          "asset-process-name",
        ).trim()
        || null
      ),

      execution_context: null,
    },

    exposure: {
      internet_exposed: (
        getInputValue(
          "asset-internet-exposed",
        ) === "true"
      ),

      reachable_networks:
        parseCommaSeparatedStrings(
          getInputValue(
            "asset-reachable-networks",
          ),
        ),

      listening_ports: parsePorts(
        getInputValue(
          "asset-listening-ports",
        ),
      ),

      authentication_required:
        parseNullableBoolean(
          getInputValue(
            "asset-auth-required",
          ),
        ),

      access_restrictions: [],
    },

    security_controls: {
      firewall_enabled:
        parseNullableBoolean(
          getInputValue(
            "asset-firewall-enabled",
          ),
        ),

      network_segmentation:
        parseNullableBoolean(
          getInputValue(
            "asset-network-segmentation",
          ),
        ),

      application_allowlisting: null,

      ids_ips_enabled:
        parseNullableBoolean(
          getInputValue(
            "asset-ids-enabled",
          ),
        ),

      endpoint_protection_enabled: null,

      compensating_controls: [],
    },

    patch_status: (
      getInputValue(
        "asset-patch-status",
      )
      || "unknown"
    ),

    evidence: [],

    evidence_notes: (
      getInputValue(
        "asset-evidence-notes",
      ).trim()
      || null
    ),
  };
}


async function submitAssetInput(event) {
  event.preventDefault();

  if (!selectedJobId) {
    setText(
      assetFormMessage,
      "No job is selected.",
    );

    return;
  }

  try {
    const asset = collectAssetInput();

    if (assetSubmitButton) {
      assetSubmitButton.disabled = true;
    }

    setText(
      assetFormMessage,
      "Saving asset operational information...",
    );

    await requestJson(
      `/api/jobs/${selectedJobId}/asset-input`,
      {
        method: "PUT",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify({
          asset,
        }),
      },
    );

    setText(
      assetFormMessage,
      "Starting asset impact assessment...",
    );

    await requestJson(
      `/api/jobs/${selectedJobId}/assess-asset`,
      {
        method: "POST",
      },
    );

    loadedAssetForJobId = null;

    setText(
      assetFormMessage,
      "Asset impact assessment started.",
    );

    await refreshSelectedJob();
    await loadJobs();

    startPolling();
  } catch (error) {
    setText(
      assetFormMessage,
      error.message,
    );
  } finally {
    if (assetSubmitButton) {
      assetSubmitButton.disabled = false;
    }
  }
}


/*
 * ==========================================================================
 * Selected job rendering
 * ==========================================================================
 */

async function renderSelectedJob(job) {
  setText(
    selectedStatus,
    normalizeStatusLabel(job.status),
  );

  if (selectedStatus) {
    selectedStatus.className = (
      `status-badge ${statusClass(job.status)}`
    );
  }

  setText(
    detailCve,
    job.cve_id || "-",
  );

  setText(
    detailJobStatus,
    job.status || "-",
  );

  setText(
    detailJob,
    job.job_id || "-",
  );

  setText(
    detailStage,
    job.stage || "-",
  );

  setText(
    detailElement,
    JSON.stringify(
      job,
      null,
      2,
    ),
  );

  updateProgress(job.status);
  renderVerdict(job);
  await loadLikelihoodAssessment(job);

  if (job.status === "needs_asset_input") {
    hideElement(inputEditor);
    loadedInputForJobId = null;

    await loadAssetInput(job);
    return;
  }

  hideAssetInputPanel();

  await loadInputEditor(job);
}


/*
 * ==========================================================================
 * API loading
 * ==========================================================================
 */

async function loadJobs() {
  try {
    const response = await requestJson(
      "/api/jobs",
    );

    const jobs = Array.isArray(response)
      ? response
      : (
        Array.isArray(response.jobs)
          ? response.jobs
          : []
      );

    renderJobs(jobs);
  } catch (error) {
    if (jobsElement) {
      jobsElement.innerHTML = (
        '<div class="empty-state">'
        + error.message
        + "</div>"
      );
    }
  }
}


async function selectJob(jobId) {
  if (!jobId) {
    return;
  }

  selectedJobId = jobId;
  loadedInputForJobId = null;
  loadedAssetForJobId = null;

  stopPolling();

  await refreshSelectedJob();
  await loadJobs();

  /*
   * refreshSelectedJob() stops polling when the job is
   * paused or terminal. Start it only when the job may
   * still progress.
   */
  try {
    const job = await requestJson(
      `/api/jobs/${jobId}`,
    );

    if (!isPausedOrTerminalStatus(job.status)) {
      startPolling();
    }
  } catch {
    /*
     * The error is already displayed through
     * refreshSelectedJob().
     */
  }
}


async function refreshSelectedJob() {
  if (!selectedJobId) {
    return;
  }

  try {
    const [job, log] = await Promise.all([
      requestJson(
        `/api/jobs/${selectedJobId}`,
      ),

      requestJson(
        `/api/jobs/${selectedJobId}/log`,
      ),
    ]);

    await renderSelectedJob(job);

    if (logElement) {
      logElement.textContent = (
        log.content || "Log is empty."
      );

      logElement.scrollTop = (
        logElement.scrollHeight
      );
    }

    /*
     * Refresh the list so a job card does not remain
     * EXTRACTING after the detail changes to
     * needs_asset_input or another state.
     */
    await loadJobs();

    if (isPausedOrTerminalStatus(job.status)) {
      stopPolling();
    }
  } catch (error) {
    setText(
      detailElement,
      error.message,
    );
  }
}


/*
 * ==========================================================================
 * Event handlers
 * ==========================================================================
 */

if (resumeButton) {
  resumeButton.addEventListener(
    "click",
    async () => {
      if (!selectedJobId) {
        return;
      }

      if (!inputJsonEditor) {
        setText(
          editorMessage,
          "JSON editor is not available.",
        );

        return;
      }

      setText(
        editorMessage,
        "Validating JSON...",
      );

      try {
        const data = JSON.parse(
          inputJsonEditor.value,
        );

        await requestJson(
          `/api/jobs/${selectedJobId}/input`,
          {
            method: "PUT",

            headers: {
              "Content-Type": "application/json",
            },

            body: JSON.stringify({
              data,
            }),
          },
        );

        await requestJson(
          `/api/jobs/${selectedJobId}/resume`,
          {
            method: "POST",
          },
        );

        setText(
          editorMessage,
          "Saved. Job resumed.",
        );

        loadedInputForJobId = null;

        await selectJob(
          selectedJobId,
        );
      } catch (error) {
        setText(
          editorMessage,
          error.message,
        );
      }
    },
  );
}


if (assetInputForm) {
  assetInputForm.addEventListener(
    "submit",
    submitAssetInput,
  );
}


if (form) {
  form.addEventListener(
    "submit",
    async (event) => {
      event.preventDefault();

      setText(
        messageElement,
        "Submitting job...",
      );

      try {
        const cveInput = (
          document.getElementById("cve-id")
        );

        if (!cveInput) {
          throw new Error(
            "CVE input field was not found.",
          );
        }

        const cveId = cveInput.value
          .trim()
          .toUpperCase();

        const job = await requestJson(
          "/api/jobs",
          {
            method: "POST",

            headers: {
              "Content-Type": "application/json",
            },

            body: JSON.stringify({
              cve_id: cveId,
              run_type: "build,exploit,verify",
            }),
          },
        );

        setText(
          messageElement,
          `Created job ${job.job_id}`,
        );

        form.reset();

        await loadJobs();
        await selectJob(job.job_id);
      } catch (error) {
        setText(
          messageElement,
          error.message,
        );
      }
    },
  );
}


if (refreshButton) {
  refreshButton.addEventListener(
    "click",
    async () => {
      await loadJobs();

      if (selectedJobId) {
        await refreshSelectedJob();
      }
    },
  );
}


/*
 * ==========================================================================
 * Initial load
 * ==========================================================================
 */

loadJobs();