const form = document.querySelector("#analyze-form");
const input = document.querySelector("#email-file");
const textarea = document.querySelector("#raw-email");
const button = document.querySelector("#analyze-button");
const dropzone = document.querySelector("#dropzone");
const fileName = document.querySelector("#file-name");
const errorMessage = document.querySelector("#error-message");
const results = document.querySelector("#results");
const indicatorForm = document.querySelector("#indicator-form");
const analysisType = document.querySelector("#analysis-type");
const toolValue = document.querySelector("#tool-value");
const toolValueLabel = document.querySelector("#tool-value-label");
const toolHelper = document.querySelector("#tool-helper");
const textInputGroup = document.querySelector("#text-input-group");
const pdfInputGroup = document.querySelector("#pdf-input-group");
const pdfFile = document.querySelector("#pdf-file");
const indicatorButton = document.querySelector("#indicator-button");
const localBadge = document.querySelector(".local-badge");
const privacyNote = document.querySelector(".workspace-heading .privacy-note");
const publicDemoNotice = document.querySelector("#public-demo-notice");
const subtitle = document.querySelector(".subtitle");
const triageFields = [
  ["Reported through", document.querySelector("#report-source")],
  ["Case priority", document.querySelector("#case-priority")],
  ["Impacted account or team", document.querySelector("#impacted-account")],
  ["Analyst notes", document.querySelector("#analyst-notes")],
];
const MAX_BYTES = 1_000_000;
const MAX_PDF_BYTES = 5_000_000;

async function loadRuntimeConfig() {
  try {
    const response = await fetch("/api/config");
    if (!response.ok) throw new Error("Could not confirm the analyzer mode.");
    const config = await response.json();
    if (config.public_demo) {
      localBadge.replaceChildren();
      appendText(localBadge, "span", "", "status-dot");
      localBadge.append(" PUBLIC DEMO");
      privacyNote.textContent = "Hosted analysis · samples only";
      subtitle.textContent = "Triage email and inspect URLs, domains, HTML, and PDFs with explainable offline checks.";
      document.querySelector("#other-input-heading").previousElementSibling.textContent = "OFFLINE INDICATOR REVIEW";
      document.querySelector("footer > span:last-child").textContent = "Public demo · only synthetic or sanitized samples";
      publicDemoNotice.textContent = "Public demo: email and file contents are sent to the hosted server for analysis. Use fake or sanitized samples only; do not submit personal, work, or confidential information.";
      publicDemoNotice.hidden = false;
    }
  } catch {
    publicDemoNotice.textContent = "Could not confirm whether this is a local or hosted demo. Do not submit email contents until the page is reloaded and this notice is resolved.";
    publicDemoNotice.hidden = false;
    button.disabled = true;
    indicatorButton.disabled = true;
  }
}

loadRuntimeConfig();

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
}

function clearError() {
  errorMessage.textContent = "";
  errorMessage.hidden = true;
}

function appendText(parent, tag, text, className) {
  const element = document.createElement(tag);
  element.textContent = text;
  if (className) element.className = className;
  parent.append(element);
  return element;
}

function renderResults(data) {
  const documentType = data.document_type || "email";
  results.replaceChildren();
  const summary = document.createElement("div");
  summary.className = "result-summary";
  const scoreCard = document.createElement("div");
  scoreCard.className = `score-card risk-${data.risk_level}`;
  appendText(scoreCard, "span", "RISK SCORE", "eyebrow");
  appendText(scoreCard, "strong", String(data.risk_score), "score-value");
  appendText(scoreCard, "span", `${data.risk_level.toUpperCase()} RISK`, "risk-label");
  summary.append(scoreCard);
  const messageCard = document.createElement("div");
  messageCard.className = "message-card";
  appendText(messageCard, "span", `${documentType.toUpperCase()} ANALYSIS`, "eyebrow");
  appendText(messageCard, "h3", data.subject || "(no subject)");
  appendText(messageCard, "p", `${documentType === "email" ? "From" : "Input"}: ${data.from}`);
  if (data.sender_domain && documentType === "email") appendText(messageCard, "p", `Sender domain: ${data.sender_domain}`);
  if (data.reply_to) appendText(messageCard, "p", `Reply-To: ${data.reply_to}`);
  if (data.pdf_metadata) appendText(messageCard, "p", `PDF: ${data.pdf_metadata.pages} pages · ${data.pdf_metadata.text_characters} extracted characters · Title: ${data.pdf_metadata.title}`);
  summary.append(messageCard);
  results.append(summary);

  if (documentType === "email") {
    const metadataSection = document.createElement("section");
    metadataSection.className = "result-section";
    appendText(metadataSection, "h3", "Email header details");
    const metadataGrid = document.createElement("dl");
    metadataGrid.className = "metadata-grid";
    for (const [label, value] of [
      ["To", data.to],
      ["Cc", data.cc],
      ["Date", data.date],
      ["Return-Path", data.return_path],
      ["Message-ID", data.message_id],
    ]) {
      if (!value) continue;
      appendText(metadataGrid, "dt", label);
      appendText(metadataGrid, "dd", value);
    }
    if (metadataGrid.childElementCount) metadataSection.append(metadataGrid);
    const received = data.received_hops || [];
    if (received.length) {
      const receivedDetails = document.createElement("details");
      receivedDetails.className = "received-details";
      const total = data.received_hops_total || received.length;
      appendText(receivedDetails, "summary", `Received trace · ${total} hop${total === 1 ? "" : "s"} · newest first`);
      const receivedList = document.createElement("ol");
      receivedList.className = "received-list";
      for (const hop of received) appendText(receivedList, "li", hop);
      receivedDetails.append(receivedList);
      if (total > received.length) {
        appendText(receivedDetails, "p", `Showing the first ${received.length} of ${total} Received headers.`, "helper-text");
      }
      metadataSection.append(receivedDetails);
    }
    if (metadataGrid.childElementCount || received.length) results.append(metadataSection);
  }

  const context = triageFields
    .map(([label, field]) => [label, field.value.trim()])
    .filter(([, value]) => value);
  if (context.length) {
    const contextSection = document.createElement("section");
    contextSection.className = "result-section triage-result";
    appendText(contextSection, "h3", "Triage context");
    const contextGrid = document.createElement("dl");
    contextGrid.className = "metadata-grid";
    for (const [label, value] of context) {
      appendText(contextGrid, "dt", label);
      appendText(contextGrid, "dd", value);
    }
    contextSection.append(contextGrid);
    results.append(contextSection);
  }

  const bodyBrief = document.createElement("section");
  bodyBrief.className = "result-section body-brief";
  appendText(bodyBrief, "h3", documentType === "email" ? "Email body brief" : "Input analysis brief");
  appendText(bodyBrief, "p", data.body_summary, "brief-copy");
  appendText(bodyBrief, "span", "EXTRACTIVE SUMMARY", "summary-method");
  results.append(bodyBrief);

  const assessment = document.createElement("section");
  assessment.className = `result-section classification-card assessment-${data.classification.category}`;
  appendText(assessment, "h3", `Assessment: ${data.classification.label}`);
  const scores = document.createElement("div");
  scores.className = "classification-scores";
  appendText(scores, "span", `Phishing signals ${data.classification.phishing_score}/100`);
  appendText(scores, "span", `Bulk / spam cues ${data.classification.spam_score}/100`);
  assessment.append(scores);
  if (data.classification.evidence.length === 0) {
    appendText(assessment, "p", "No configured phishing or bulk-mail indicators were found.", "empty-state");
  } else {
    const evidenceList = document.createElement("ul");
    evidenceList.className = "evidence-list";
    for (const evidence of data.classification.evidence) {
      const item = document.createElement("li");
      item.className = `evidence-item evidence-${evidence.category}`;
      appendText(item, "strong", evidence.title);
      appendText(item, "span", `+${evidence.points}`);
      appendText(item, "p", evidence.detail);
      evidenceList.append(item);
    }
    assessment.append(evidenceList);
  }
  appendText(assessment, "p", data.classification.note, "classification-note");
  results.append(assessment);

  if (Object.keys(data.authentication || {}).length > 0) {
    const authSection = document.createElement("section");
    authSection.className = "result-section";
    appendText(authSection, "h3", "Authentication checks");
    const authGrid = document.createElement("div");
    authGrid.className = "auth-grid";
    for (const [method, status] of Object.entries(data.authentication)) {
      const item = document.createElement("div");
      item.className = "auth-item";
      appendText(item, "span", method.toUpperCase());
      appendText(item, "strong", status, `auth-status status-${status}`);
      authGrid.append(item);
    }
    authSection.append(authGrid);
    results.append(authSection);
  }

  const findingsSection = document.createElement("section");
  findingsSection.className = "result-section";
  appendText(findingsSection, "h3", `Findings (${data.findings.length})`);
  if (data.findings.length === 0) {
    appendText(findingsSection, "p", "No configured warning heuristics were triggered. This does not prove the email is safe.", "empty-state");
  }
  for (const finding of data.findings) {
    const item = document.createElement("article");
    item.className = `finding finding-${finding.severity}`;
    appendText(item, "span", finding.severity.toUpperCase(), "finding-severity");
    const copy = document.createElement("div");
    appendText(copy, "strong", finding.title);
    appendText(copy, "p", finding.detail);
    item.append(copy);
    findingsSection.append(item);
  }
  results.append(findingsSection);

  const linksSection = document.createElement("section");
  linksSection.className = "result-section";
  appendText(linksSection, "h3", `Links (${data.links.length})`);
  if (data.links.length === 0) appendText(linksSection, "p", "No HTTP or HTTPS links found.", "empty-state");
  for (const link of data.links) {
    const item = document.createElement("div");
    item.className = "link-item";
    appendText(item, "span", link.insecure ? "HTTP" : "HTTPS", link.insecure ? "protocol protocol-warning" : "protocol");
    appendText(item, "code", link.url);
    if (link.suspicious) appendText(item, "span", "REVIEW", "review-label");
    linksSection.append(item);
  }
  results.append(linksSection);

  const attachmentsSection = document.createElement("section");
  attachmentsSection.className = "result-section";
  appendText(attachmentsSection, "h3", `Attachments (${data.attachments.length})`);
  if (data.attachments.length === 0) appendText(attachmentsSection, "p", "No attachments found.", "empty-state");
  for (const attachment of data.attachments) {
    const item = document.createElement("div");
    item.className = "attachment-item";
    appendText(item, "span", attachment.risky ? "!" : "↳", attachment.risky ? "attachment-icon attachment-warning" : "attachment-icon");
    appendText(item, "strong", attachment.name);
    appendText(item, "span", attachment.type, "attachment-type");
    attachmentsSection.append(item);
  }
  results.append(attachmentsSection);
  appendText(results, "p", data.disclaimer, "disclaimer");
  results.hidden = false;
}

async function analyze(rawEmail) {
  clearError();
  results.hidden = true;
  button.disabled = true;
  button.querySelector("span").textContent = "Analyzing…";
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: rawEmail }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Analysis could not be completed.");
    renderResults(data);
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    showError(error.message || "Unable to reach the analyzer.");
  } finally {
    button.disabled = false;
    button.querySelector("span").textContent = "Analyze email";
  }
}

input.addEventListener("change", async () => {
  clearError();
  const file = input.files?.[0];
  if (!file) return;
  if (file.size > MAX_BYTES) {
    showError("That file is larger than the 1 MB limit.");
    input.value = "";
    return;
  }
  try {
    textarea.value = await file.text();
    fileName.textContent = file.name;
  } catch {
    showError("The selected file could not be read.");
  }
});

for (const eventName of ["dragenter", "dragover"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.add("dragging");
  });
}
for (const eventName of ["dragleave", "drop"]) {
  dropzone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropzone.classList.remove("dragging");
  });
}
dropzone.addEventListener("drop", (event) => {
  const file = event.dataTransfer?.files?.[0];
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".eml")) {
    showError("Choose a message file with the .eml extension.");
    return;
  }
  if (file.size > MAX_BYTES) {
    showError("That file is larger than the 1 MB limit.");
    return;
  }
  const transfer = new DataTransfer();
  transfer.items.add(file);
  input.files = transfer.files;
  input.dispatchEvent(new Event("change"));
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const rawEmail = textarea.value.trim();
  if (!rawEmail) {
    showError("Select an .eml file or paste the raw email source first.");
    return;
  }
  if (new TextEncoder().encode(rawEmail).length > MAX_BYTES) {
    showError("Email source must be smaller than 1 MB.");
    return;
  }
  await analyze(rawEmail);
});

const inputGuidance = {
  url: { label: "URL to inspect", placeholder: "https://example.test/login", helper: "The URL is inspected without being visited; no DNS or reputation lookup is made." },
  domain: { label: "Domain name", placeholder: "example.test", helper: "Checks basic hostname syntax only; no DNS, WHOIS, or reputation lookups are made." },
  html: { label: "HTML source", placeholder: "Paste HTML source…", helper: "Visible text and links are parsed; scripts are not executed and links are not visited." },
};

analysisType.addEventListener("change", () => {
  const kind = analysisType.value;
  const isPdf = kind === "pdf";
  textInputGroup.hidden = isPdf;
  pdfInputGroup.hidden = !isPdf;
  if (!isPdf) {
    toolValueLabel.textContent = inputGuidance[kind].label;
    toolValue.placeholder = inputGuidance[kind].placeholder;
    toolHelper.textContent = inputGuidance[kind].helper;
  } else {
    toolHelper.textContent = "Text and link annotations are extracted. Scanned pages are not OCR-processed.";
  }
  clearError();
});

indicatorForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearError();
  results.hidden = true;
  const kind = analysisType.value;
  let payload = { kind, value: toolValue.value.trim() };
  if (kind === "pdf") {
    const file = pdfFile.files?.[0];
    if (!file) {
      showError("Choose a PDF file first.");
      return;
    }
    if (file.size > MAX_PDF_BYTES) {
      showError("PDF files must be no larger than 5 MB.");
      return;
    }
    let bytes;
    try {
      bytes = new Uint8Array(await file.arrayBuffer());
    } catch {
      showError("The selected PDF could not be read from this browser.");
      return;
    }
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    payload.pdf_base64 = btoa(binary);
  } else if (!payload.value) {
    showError(`Provide ${kind === "html" ? "HTML source" : `a ${kind}`} to analyze.`);
    return;
  } else if (new TextEncoder().encode(payload.value).length > MAX_BYTES) {
    showError("Text input must be smaller than 1 MB.");
    return;
  }

  indicatorButton.disabled = true;
  indicatorButton.querySelector("span").textContent = "Analyzing…";
  try {
    const response = await fetch("/api/analyze-input", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Analysis could not be completed.");
    renderResults(data);
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    showError(error.message || "Unable to reach the analyzer.");
  } finally {
    indicatorButton.disabled = false;
    indicatorButton.querySelector("span").textContent = "Analyze input";
  }
});
