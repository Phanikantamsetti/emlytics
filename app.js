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
const domainScanForm = document.querySelector("#domain-scan-form");
const domainScanValue = document.querySelector("#domain-scan-value");
const domainScanButton = document.querySelector("#domain-scan-button");
const domainScanError = document.querySelector("#domain-scan-error");
const domainReputationLookup = document.querySelector("#domain-reputation-lookup");
const localBadge = document.querySelector(".local-badge");
const privacyNote = document.querySelector(".workspace-heading .privacy-note");
const publicDemoNotice = document.querySelector("#public-demo-notice");
const subtitle = document.querySelector(".subtitle");
const externalLookupControls = [...document.querySelectorAll(".external-lookup")];
const urlscanSubmitControls = [...document.querySelectorAll(".urlscan-submit")];
let configuredProviders = { virustotal: false, urlscan: false };
const HISTORY_KEY = "emlytics.scanHistory";
const MAX_HISTORY_ITEMS = 20;
const triageFields = [
  ["Reported through", document.querySelector("#report-source")],
  ["Case priority", document.querySelector("#case-priority")],
  ["Impacted account or team", document.querySelector("#impacted-account")],
  ["Analyst notes", document.querySelector("#analyst-notes")],
];
const MAX_BYTES = 1_000_000;
const MAX_PDF_BYTES = 5_000_000;
let accountsEnabled = false;
let aiEnabled = false;
let signedInUser = null;
let currentReport = null;

async function loadRuntimeConfig() {
  try {
    const response = await fetch("/api/config");
    if (!response.ok) throw new Error("Could not confirm the analyzer mode.");
    const config = await response.json();
    configuredProviders = config.providers || { virustotal: config.external_lookups_enabled, urlscan: config.external_lookups_enabled };
    accountsEnabled = config.accounts_enabled === true;
    aiEnabled = config.ai_enabled === true;
    document.querySelector("#account-state").textContent = accountsEnabled
      ? "Account service available"
      : "Account service needs server configuration";
    document.querySelector("#account-email").disabled = !accountsEnabled;
    document.querySelector("#account-password").disabled = !accountsEnabled;
    document.querySelector("#account-login-button").disabled = !accountsEnabled;
    document.querySelector("#account-signup-button").disabled = !accountsEnabled;
    document.querySelector("#account-reset-button").disabled = !accountsEnabled;
    document.querySelector("#url-reputation-opt-in").disabled = !configuredProviders.virustotal && !configuredProviders.urlscan;
    if (!configuredProviders.virustotal && !configuredProviders.urlscan) {
      for (const control of externalLookupControls) control.disabled = true;
      domainReputationLookup.disabled = true;
      document.querySelectorAll(".external-lookup-note").forEach((note) => {
        note.textContent = "External lookups are unavailable until a provider API key is configured on the server.";
      });
    } else {
      for (const control of externalLookupControls) control.disabled = false;
      domainReputationLookup.disabled = false;
      const available = [
        configuredProviders.virustotal ? "VirusTotal" : "",
        configuredProviders.urlscan ? "URLScan.io" : "",
      ].filter(Boolean).join(" and ");
      document.querySelectorAll(".external-lookup-label").forEach((label) => {
        const checkbox = label.querySelector("input");
        label.replaceChildren(checkbox, ` Check extracted indicators with ${available}`);
      });
      document.querySelectorAll(".external-lookup-note").forEach((note) => {
        note.textContent = `Enabled providers: ${available}. Only selected indicators are sent; up to 5 are checked.`;
      });
    }
    updateExternalControls();
    if (accountsEnabled) loadAccountState();
    if (config.public_demo) {
      localBadge.replaceChildren();
      appendText(localBadge, "span", "", "status-dot");
      localBadge.append(" PUBLIC DEMO");
      privacyNote.textContent = "Hosted analysis · samples only";
      subtitle.textContent = "Triage email and review domain configuration with explainable, consent-based checks.";
      document.querySelector("#other-input-heading").previousElementSibling.textContent = "QUICK INPUT CHECKS";
      document.querySelector("footer > span:last-child").textContent = "Public demo · only synthetic or sanitized samples";
      publicDemoNotice.textContent = "Public demo: submissions are processed by the hosted server. Domain checks contact public DNS/RDAP services and the specified public host; configured reputation lookups share indicators with vendors. URLScan submissions are public and visit targets. Use synthetic or sanitized samples only.";
      publicDemoNotice.hidden = false;
    }
  } catch {
    publicDemoNotice.textContent = "Could not confirm whether this is a local or hosted demo. Do not submit email contents until the page is reloaded and this notice is resolved.";
    publicDemoNotice.hidden = false;
    button.disabled = true;
    indicatorButton.disabled = true;
    domainScanButton.disabled = true;
    for (const control of [...externalLookupControls, ...urlscanSubmitControls]) control.disabled = true;
    domainReputationLookup.disabled = true;
  }
}

loadRuntimeConfig();

function updateExternalControls() {
  for (const control of urlscanSubmitControls) {
    const lookupControl = control.closest(".external-lookup-controls").querySelector(".external-lookup");
    control.disabled = !configuredProviders.urlscan || !lookupControl.checked || lookupControl.disabled;
    if (control.disabled) control.checked = false;
  }
}

for (const control of externalLookupControls) {
  control.addEventListener("change", updateExternalControls);
}

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
  currentReport = data;
  results.replaceChildren();
  const summary = document.createElement("div");
  summary.className = "result-summary";
  const scoreCard = document.createElement("div");
  const isDomainPosture = Boolean(data.domain_posture);
  const postureScore = data.domain_posture?.posture_score;
  const scoreLevel = Number.isFinite(postureScore)
    ? postureScore < 55 ? "high" : postureScore < 80 ? "medium" : "low"
    : "unknown";
  scoreCard.className = `score-card risk-${isDomainPosture ? scoreLevel : data.risk_level}`;
  appendText(scoreCard, "span", isDomainPosture ? "POSTURE SCORE" : "RISK SCORE", "eyebrow");
  appendText(scoreCard, "strong", isDomainPosture && !Number.isFinite(postureScore) ? "N/A" : String(isDomainPosture ? postureScore : data.risk_score), "score-value");
  appendText(scoreCard, "span", isDomainPosture
    ? Number.isFinite(postureScore) ? (data.domain_posture.score_label || "CONFIGURATION") : "COVERAGE UNAVAILABLE"
    : `${data.risk_level.toUpperCase()} RISK`, "risk-label");
  summary.append(scoreCard);
  const resultActions = document.createElement("div");
  resultActions.className = "result-actions";
  const exportButton = document.createElement("button");
  exportButton.type = "button";
  exportButton.className = "button-secondary";
  exportButton.textContent = "Export report";
  exportButton.addEventListener("click", () => {
    const report = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const downloadUrl = URL.createObjectURL(report);
    const downloadLink = document.createElement("a");
    downloadLink.href = downloadUrl;
    downloadLink.download = `emlytics-${documentType}-report.json`;
    downloadLink.click();
    URL.revokeObjectURL(downloadUrl);
  });
  resultActions.append(exportButton);
  if (accountsEnabled) {
    const saveButton = document.createElement("button");
    saveButton.type = "button";
    saveButton.className = "button-secondary";
    saveButton.textContent = signedInUser ? "Save to account" : "Sign in to save";
    saveButton.disabled = !signedInUser;
    saveButton.addEventListener("click", () => saveCurrentReport(saveButton));
    resultActions.append(saveButton);
  }
  const messageCard = document.createElement("div");
  messageCard.className = "message-card";
  appendText(messageCard, "span", `${documentType.toUpperCase()} ANALYSIS`, "eyebrow");
  appendText(messageCard, "h3", data.domain_posture ? "Domain security posture review" : data.subject || "(no subject)");
  appendText(messageCard, "p", `${documentType === "email" ? "From" : "Input"}: ${data.from}`);
  if (data.sender_domain && documentType === "email") appendText(messageCard, "p", `Sender domain: ${data.sender_domain}`);
  if (data.reply_to) appendText(messageCard, "p", `Reply-To: ${data.reply_to}`);
  if (data.pdf_metadata) appendText(messageCard, "p", `PDF: ${data.pdf_metadata.pages} pages · ${data.pdf_metadata.text_characters} extracted characters · Title: ${data.pdf_metadata.title}`);
  summary.append(messageCard);
  results.append(summary);
  results.append(resultActions);

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

  if (data.domain_posture) renderDomainPosture(data.domain_posture);

  if (!data.domain_posture) {
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
  }

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

  if (!data.domain_posture) {
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
  }

  if (!data.domain_posture && data.recommended_actions?.length) {
    const actions = document.createElement("section");
    actions.className = "result-section action-plan";
    appendText(actions, "h3", "Recommended next steps");
    const list = document.createElement("ol");
    for (const action of data.recommended_actions) appendText(list, "li", action);
    actions.append(list);
    results.append(actions);
  }

  if (!data.domain_posture && data.indicators_of_compromise?.length) {
    const iocs = document.createElement("section");
    iocs.className = "result-section";
    appendText(iocs, "h3", `Extracted indicators (${data.indicators_of_compromise.length})`);
    appendText(iocs, "p", "These indicators are extracted from the message; extraction is not confirmation of maliciousness.", "helper-text");
    for (const indicator of data.indicators_of_compromise) {
      const row = document.createElement("div");
      row.className = "link-item";
      appendText(row, "span", indicator.type.toUpperCase(), "protocol");
      appendText(row, "code", indicator.value);
      appendText(row, "span", indicator.source, "attachment-type");
      iocs.append(row);
    }
    results.append(iocs);
  }

  if (!data.domain_posture) {
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
  }

  if (Array.isArray(data.external_intelligence)) {
    const intelligenceSection = document.createElement("section");
    intelligenceSection.className = "result-section external-intelligence";
    appendText(intelligenceSection, "h3", "External reputation intelligence");
    appendText(intelligenceSection, "p", "These vendor results are time-sensitive and may be incomplete; they are not a safety verdict.", "helper-text");
    for (const lookup of data.external_intelligence) {
      const card = document.createElement("article");
      card.className = "intelligence-item";
      appendText(card, "code", `${lookup.type}: ${lookup.indicator}`);
      const virusTotal = lookup.virustotal || {};
      appendText(card, "strong", `VirusTotal · ${formatProviderStatus(virusTotal)}`);
      if (virusTotal.status === "found") {
        if (virusTotal.brief) appendText(card, "p", virusTotal.brief, "intelligence-brief");
        appendText(card, "p", `Malicious: ${virusTotal.malicious} · Suspicious: ${virusTotal.suspicious} · Harmless: ${virusTotal.harmless} · Undetected: ${virusTotal.undetected}`);
        if (virusTotal.detections?.length) {
          appendText(card, "p", `Flagged engines: ${virusTotal.detections.map(({ engine, result }) => `${engine} (${result})`).join("; ")}`);
        }
        if (virusTotal.reputation !== null) appendText(card, "p", `Community reputation: ${virusTotal.reputation}`);
        if (Number.isFinite(virusTotal.last_analysis_date)) appendText(card, "p", `Last analysis: ${new Date(virusTotal.last_analysis_date * 1000).toLocaleString()}`);
      }
      if (virusTotal.message) appendText(card, "p", virusTotal.message, "helper-text");
      const urlscan = lookup.urlscan || {};
      const existing = urlscan.existing || {};
      appendText(card, "strong", `URLScan.io existing reports · ${formatProviderStatus(existing)}`);
      if (existing.brief) appendText(card, "p", existing.brief, "intelligence-brief");
      if (existing.total !== undefined) appendText(card, "p", `Matching reports: ${existing.total}`);
      for (const scan of existing.scans || []) {
        const verdict = scan.malicious === true ? "flagged malicious" : scan.malicious === false ? "not flagged malicious" : "verdict unavailable";
        const scanSummary = `${scan.date || "Date unavailable"} · ${verdict} · score ${scan.score ?? "unavailable"} · ${scan.result_url}`;
        appendText(card, "p", scanSummary);
        const reportLabels = [...(scan.categories || []), ...(scan.brands || [])];
        if (reportLabels.length) appendText(card, "p", `Report labels: ${reportLabels.join(", ")}`);
      }
      if (existing.message) appendText(card, "p", existing.message, "helper-text");
      if (urlscan.submission) {
        const submission = urlscan.submission;
        appendText(card, "strong", `URLScan.io new scan · ${formatProviderStatus(submission)}`);
        if (submission.result_url) appendText(card, "p", `Result: ${submission.result_url}`);
        if (submission.message) appendText(card, "p", submission.message, "helper-text");
      }
      intelligenceSection.append(card);
    }
    if (data.external_intelligence_omitted) {
      appendText(intelligenceSection, "p", `${data.external_intelligence_omitted} additional indicator(s) were omitted to limit provider requests.`, "helper-text");
    }
    results.append(intelligenceSection);
  }

  if (!data.domain_posture) {
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
  }
  appendText(results, "p", data.disclaimer, "disclaimer");
  renderAssistantCard(data);
  results.hidden = false;
}

function renderAssistantCard(data) {
  const section = document.createElement("section");
  section.className = "result-section assistant-card";
  appendText(section, "h3", "Ask about this report");
  appendText(section, "p", aiEnabled
    ? "Answers use limited scan findings only; raw email bodies and headers are not sent. The configured AI provider may process the report evidence and question."
    : "AI Q&A is unavailable until the site owner configures a server-side AI provider key.", "helper-text");
  const consent = document.createElement("label");
  consent.className = "consent-row";
  const consentBox = document.createElement("input");
  consentBox.type = "checkbox";
  consentBox.disabled = !aiEnabled;
  consent.append(consentBox, document.createTextNode(" Send scan evidence and my question to the configured AI provider"));
  section.append(consent);
  const form = document.createElement("form");
  form.className = "assistant-form";
  const question = document.createElement("input");
  question.type = "text";
  question.maxLength = 1000;
  question.placeholder = "Ask about a finding or recommended next step…";
  question.required = true;
  const askButton = document.createElement("button");
  askButton.type = "submit";
  askButton.textContent = "Ask";
  askButton.disabled = !aiEnabled;
  const answer = document.createElement("p");
  answer.className = "assistant-answer";
  answer.hidden = true;
  form.append(question, askButton);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!consentBox.checked) {
      answer.textContent = "Confirm before sending the scan evidence to the AI provider.";
      answer.hidden = false;
      return;
    }
    askButton.disabled = true;
    askButton.textContent = "Thinking…";
    try {
      const response = await fetch("/api/assistant", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: question.value.trim(), report: data }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "The assistant could not answer.");
      answer.textContent = result.answer;
    } catch (error) {
      answer.textContent = error.message || "The assistant could not answer.";
    } finally {
      answer.hidden = false;
      askButton.disabled = !aiEnabled;
      askButton.textContent = "Ask";
    }
  });
  section.append(form, answer);
  results.append(section);
}

function renderDomainPosture(posture) {
  const section = document.createElement("section");
  section.className = "result-section domain-posture";
  appendText(section, "h3", "Domain security report");
  if (Number.isFinite(posture.posture_score)) {
    const scoreCard = document.createElement("div");
    scoreCard.className = "posture-score";
    appendText(scoreCard, "strong", String(posture.posture_score), "posture-score-value");
    appendText(scoreCard, "div", posture.score_label || "Configuration overview", "posture-score-label");
    appendText(scoreCard, "p", posture.score_note || "", "helper-text");
    section.append(scoreCard);
  }
  const brief = postureBrief(posture);
  appendText(section, "p", brief, "posture-brief");
  if (posture.categories?.length) {
    appendText(section, "h4", "Evidence by category");
    const categoryGrid = document.createElement("div");
    categoryGrid.className = "category-grid";
    for (const category of posture.categories) {
      const card = document.createElement("article");
      card.className = "category-card";
      appendText(card, "strong", category.name);
      appendText(card, "span", Number.isFinite(category.score) ? `${category.score}/${category.maximum}` : `Not assessed / ${category.maximum}`, "category-score");
      appendText(card, "p", category.description, "posture-detail");
      appendText(card, "small", category.coverage || "Coverage unknown", "category-coverage");
      for (const evidence of category.evidence || []) appendText(card, "p", evidence, "posture-detail");
      categoryGrid.append(card);
    }
    section.append(categoryGrid);
  }

  const dns = posture.dns || {};
  const dnsCard = document.createElement("article");
  dnsCard.className = "posture-card";
  appendText(dnsCard, "h4", "DNS configuration");
  appendText(dnsCard, "p", dns.status === "resolved" ? `Resolved addresses: ${(dns.addresses || []).join(", ")}` : dns.message || "Address resolution was unavailable.", "posture-detail");
  for (const [type, result] of Object.entries(dns.records || {})) {
    const values = result.records || [];
    const status = values.length ? values.join(" · ") : result.message || (result.status === "unavailable" ? "lookup unavailable" : "no records returned");
    appendText(dnsCard, "p", `${type}: ${status}`, "posture-detail");
  }
  const dnssec = posture.dnssec || {};
  appendText(dnsCard, "p", `DNSSEC: ${dnssec.status === "validated" ? "validated by the resolver" : dnssec.status === "not_validated" ? "not validated for the queried answers" : "status unavailable"}. ${dnssec.message || ""}`, "posture-detail");
  section.append(dnsCard);

  const records = dns.records || {};
  const mailCard = document.createElement("article");
  mailCard.className = "posture-card";
  appendText(mailCard, "h4", "Email domain protections");
  for (const [label, key, prefix] of [
    ["SPF", "TXT", "v=spf1"],
    ["DMARC", "DMARC", "v=dmarc1"],
  ]) {
    const result = records[key] || {};
    const values = (result.records || []).filter((record) => record.trim().replace(/^"+|"+$/g, "").toLowerCase().startsWith(prefix));
    let status;
    if (result.status === "unavailable") status = "lookup unavailable";
    else if (!values.length) status = "record not found";
    else status = values.join(" · ");
    appendText(mailCard, "p", `${label}: ${status}`, "posture-detail");
  }
  const dmarcRecords = records.DMARC || {};
  if (dmarcRecords.status !== "unavailable") {
    const dmarcValues = dmarcRecords.records || [];
    const policy = dmarcValues.map((record) => record.match(/(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b/i)?.[1]).find(Boolean);
    if (policy) appendText(mailCard, "p", `DMARC policy: p=${policy.toLowerCase()}${policy.toLowerCase() === "none" ? " (monitor-only)" : ""}`, "posture-detail");
  }
  section.append(mailCard);

  const rdap = posture.rdap || {};
  const rdapCard = document.createElement("article");
  rdapCard.className = "posture-card";
  appendText(rdapCard, "h4", "Registration (RDAP)");
  if (rdap.status === "found") {
    for (const [label, value] of [
      ["Registrar", rdap.registrar],
      ["Registered", rdap.registered],
      ["Expires", rdap.expires],
      ["Last changed", rdap.last_changed],
      ["Name servers", (rdap.nameservers || []).join(", ")],
    ]) {
      if (value) appendText(rdapCard, "p", `${label}: ${value}`, "posture-detail");
    }
  } else {
    appendText(rdapCard, "p", rdap.message || "Registration data unavailable.", "posture-detail");
  }
  section.append(rdapCard);

  const https = posture.https || {};
  const httpsCard = document.createElement("article");
  httpsCard.className = "posture-card";
  appendText(httpsCard, "h4", "HTTPS, TLS & security headers");
  if (https.status === "ok") {
    appendText(httpsCard, "p", `TLS ${https.tls_version || "version unavailable"} · HTTP ${https.http_status} · Certificate issuer: ${https.certificate?.issuer || "not reported"}`, "posture-detail");
    appendText(httpsCard, "p", `Certificate expires ${https.certificate?.expires_at || "date unavailable"}${Number.isFinite(https.certificate?.days_remaining) ? ` (${https.certificate.days_remaining} days)` : ""}.`, "posture-detail");
    const headers = document.createElement("ul");
    headers.className = "header-check-list";
    for (const [name, value] of Object.entries(https.security_headers || {})) {
      const item = document.createElement("li");
      item.className = value.present ? "header-present" : "header-missing";
      appendText(item, "strong", value.present ? "PRESENT" : "MISSING");
      appendText(item, "span", name);
      if (value.value) appendText(item, "code", value.value);
      headers.append(item);
    }
    httpsCard.append(headers);
  } else {
    appendText(httpsCard, "p", https.message || "HTTPS check unavailable.", "posture-detail");
  }
  section.append(httpsCard);

  const coverage = document.createElement("p");
  coverage.className = "helper-text";
  appendText(coverage, "strong", "Coverage: ");
  coverage.append(document.createTextNode(
    `DNS records (${dns.status === "resolved" ? "checked" : "unavailable"}), RDAP (${rdap.status || "not checked"}), HTTPS/TLS and common response headers (${https.status === "ok" ? "checked" : "unavailable"}). No site crawl, vulnerability test, or definitive phishing verdict is included.`
  ));
  section.append(coverage);

  if (posture.recommended_actions?.length) {
    const actions = document.createElement("article");
    actions.className = "posture-card action-plan";
    appendText(actions, "h4", "Recommended next steps");
    const list = document.createElement("ol");
    for (const action of posture.recommended_actions) appendText(list, "li", action);
    actions.append(list);
    section.append(actions);
  }

  if (posture.score_factors?.length) {
    appendText(section, "h4", "Items affecting the configuration score");
    for (const factor of posture.score_factors) {
      appendText(section, "p", `${factor.title} (${factor.impact}) — ${factor.detail}`, "posture-detail");
    }
  }
  results.append(section);
}

function postureBrief(posture) {
  const score = posture.posture_score;
  const findings = posture.score_factors || [];
  if (!Number.isFinite(score)) return "Some checks could not be completed. Review the sections below for provider-specific status.";
  if (!findings.length) return "The tested DNS, TLS, and common security-header checks returned no configured warnings. This does not establish that the domain or its content is safe.";
  return `Configuration score ${score}/100. ${findings.length} review item${findings.length === 1 ? "" : "s"} found: ${findings.slice(0, 3).map((item) => item.title.toLowerCase()).join(", ")}. This score reflects only the checks shown below.`;
}

function readScanHistory() {
  const saved = localStorage.getItem(HISTORY_KEY);
  if (!saved) return [];
  const history = JSON.parse(saved);
  if (!Array.isArray(history)) throw new Error("Saved scan history has an invalid format.");
  return history.slice(0, MAX_HISTORY_ITEMS);
}

function renderScanHistory() {
  const historyList = document.querySelector("#history-list");
  historyList.replaceChildren();
  try {
    const history = readScanHistory();
    if (!history.length) {
      appendText(historyList, "p", "No saved scans yet.", "empty-state");
      return;
    }
    for (const entry of history) {
      const item = document.createElement("article");
      item.className = "history-item";
      appendText(item, "span", new Date(entry.time).toLocaleString(), "history-time");
      appendText(item, "strong", entry.type);
      appendText(item, "span", entry.target || "Target not retained");
      appendText(item, "span", `${entry.label} · score ${entry.score}`);
      historyList.append(item);
    }
  } catch {
    appendText(historyList, "p", "Browser storage is unavailable or the saved history is invalid. You can clear it and try again.", "error-message");
  }
}

function saveScanHistory(type, target, data, enabled) {
  if (!enabled) return;
  try {
    const history = readScanHistory();
    history.unshift({
      type,
      target,
      time: new Date().toISOString(),
      score: Number.isFinite(data.domain_posture?.posture_score) ? data.domain_posture.posture_score : Number.isFinite(data.risk_score) ? data.risk_score : 0,
      label: data.domain_posture?.score_label || data.classification?.label || "Domain posture checked",
    });
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, MAX_HISTORY_ITEMS)));
    renderScanHistory();
  } catch {
    showError("The scan completed, but this browser could not save its history.");
  }
}

function urlHost(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return "";
  }
}

document.querySelector("#clear-history").addEventListener("click", () => {
  try {
    localStorage.removeItem(HISTORY_KEY);
    renderScanHistory();
  } catch {
    appendText(document.querySelector("#history-list"), "p", "Browser history could not be cleared.", "error-message");
  }
});
renderScanHistory();

domainScanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  domainScanError.textContent = "";
  domainScanError.hidden = true;
  let domain = domainScanValue.value.trim();
  if (/^https?:\/\//i.test(domain)) {
    try {
      const parsed = new URL(domain);
      if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password || !parsed.hostname) {
        throw new Error();
      }
      domain = parsed.hostname;
      domainScanValue.value = domain;
    } catch {
      domainScanError.textContent = "Enter a valid public hostname or HTTP(S) URL without embedded credentials.";
      domainScanError.hidden = false;
      return;
    }
  }
  if (!document.querySelector("#domain-scan-consent").checked) {
    domainScanError.textContent = "Confirm the public DNS/RDAP and HTTPS checks before scanning.";
    domainScanError.hidden = false;
    return;
  }
  results.hidden = true;
  domainScanButton.disabled = true;
  domainScanButton.querySelector("span").textContent = "Checking domain…";
  try {
    const response = await fetch("/api/analyze-input", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "domain",
        value: domain,
        domain_scan: true,
        external_lookup: domainReputationLookup.checked,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Domain checks could not be completed.");
    renderResults(data);
    saveScanHistory("Domain scan", data.sender_domain, data, document.querySelector("#domain-history-opt-in").checked);
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    domainScanError.textContent = error.message || "Unable to reach the analyzer.";
    domainScanError.hidden = false;
  } finally {
    domainScanButton.disabled = false;
    domainScanButton.querySelector("span").textContent = "Run domain check";
  }
});

function formatProviderStatus(result) {
  if (result.status === "found") return "report found";
  if (result.status === "not_found") return "no report found";
  if (result.status === "submitted") return "submitted";
  return result.message || "unavailable";
}

function confirmExternalSubmission(lookupControl, submitControl) {
  if (!lookupControl.checked) return true;
  if (!submitControl.checked) return true;
  return window.confirm("Submit extracted URLs to URLScan.io for public scans? The URLs will be publicly visible and URLScan's scanner will visit each target. Only indicators are sent; the email body and attachments are not.");
}

async function analyze(rawEmail, externalLookup, urlscanSubmit) {
  clearError();
  results.hidden = true;
  button.disabled = true;
  button.querySelector("span").textContent = "Analyzing…";
  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: rawEmail, external_lookup: externalLookup, urlscan_submit: urlscanSubmit }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Analysis could not be completed.");
    renderResults(data);
    saveScanHistory("Email", data.sender_domain, data, document.querySelector("#email-history-opt-in").checked);
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
  const lookupControl = document.querySelector("#email-external-lookup");
  const submitControl = document.querySelector("#email-urlscan-submit");
  if (!confirmExternalSubmission(lookupControl, submitControl)) return;
  await analyze(rawEmail, lookupControl.checked, submitControl.checked);
});

const inputGuidance = {
  url: { label: "URL to inspect", placeholder: "https://example.test/login", helper: "Checks URL format and common link warning signs only. It does not open the site; optional reputation lookups are available when configured." },
  domain: { label: "Domain name", placeholder: "example.test", helper: "Checks hostname format, direct-IP input, and punycode lookalikes only. For live DNS, registration, TLS, and header checks, use Scan a public domain above." },
  html: { label: "HTML source", placeholder: "Paste HTML source…", helper: "Extracts visible text and links, then checks them for common warning signs. Scripts are not run and links are not opened." },
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
    toolHelper.textContent = "Extracts PDF text, metadata, and link annotations, then checks the extracted content for common warning signs. Files are not executed; scanned pages are not OCR-processed.";
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
  const lookupControl = document.querySelector("#indicator-external-lookup");
  const submitControl = document.querySelector("#indicator-urlscan-submit");
  if (!confirmExternalSubmission(lookupControl, submitControl)) return;
  payload.external_lookup = lookupControl.checked;
  payload.urlscan_submit = submitControl.checked;

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
    const target = kind === "domain" ? data.sender_domain : kind === "url" ? urlHost(payload.value) : "";
    saveScanHistory(kind.toUpperCase(), target, data, document.querySelector("#indicator-history-opt-in").checked);
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    showError(error.message || "Unable to reach the analyzer.");
  } finally {
    indicatorButton.disabled = false;
    indicatorButton.querySelector("span").textContent = "Analyze input";
  }
});

async function apiRequest(url, options = {}) {
  let response = await fetch(url, { credentials: "same-origin", ...options });
  const nonRefreshableAuthRoutes = ["/api/auth/login", "/api/auth/signup", "/api/auth/reset", "/api/auth/refresh", "/api/auth/logout"];
  if (response.status === 401 && !nonRefreshableAuthRoutes.includes(url)) {
    const refreshed = await fetch("/api/auth/refresh", { method: "POST", credentials: "same-origin" });
    if (refreshed.ok) response = await fetch(url, { credentials: "same-origin", ...options });
  }
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error("The server returned an invalid response.");
  }
  if (!response.ok) throw new Error(data.error || "The request could not be completed.");
  return data;
}

function setAccountUser(user) {
  signedInUser = user;
  const authForm = document.querySelector("#auth-form");
  const signedInPanel = document.querySelector("#signed-in-panel");
  authForm.hidden = Boolean(user) || !accountsEnabled;
  signedInPanel.hidden = !user;
  document.querySelector("#account-state").textContent = user ? "Signed in" : accountsEnabled ? "Not signed in" : "Server setup required";
  document.querySelector("#signed-in-email").textContent = user?.email || "";
  if (currentReport && !document.querySelector("#results").hidden) renderResults(currentReport);
  if (user) {
    loadSavedReports();
    loadWatchlist();
  }
}

async function loadAccountState() {
  try {
    const data = await apiRequest("/api/auth/me");
    setAccountUser(data.user);
  } catch {
    setAccountUser(null);
  }
}

document.querySelector("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.querySelector("#account-error");
  error.hidden = true;
  error.classList.remove("account-success");
  try {
    const data = await apiRequest("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: document.querySelector("#account-email").value.trim(),
        password: document.querySelector("#account-password").value,
      }),
    });
    document.querySelector("#account-password").value = "";
    setAccountUser(data.user);
  } catch (reason) {
    error.textContent = reason.message || "Sign-in failed.";
    error.hidden = false;
  }
});

document.querySelector("#account-signup-button").addEventListener("click", async () => {
  const error = document.querySelector("#account-error");
  error.hidden = true;
  error.classList.remove("account-success");
  const email = document.querySelector("#account-email").value.trim();
  const password = document.querySelector("#account-password").value;
  if (!email || password.length < 10) {
    error.textContent = "Enter an email and a password with at least 10 characters.";
    error.hidden = false;
    return;
  }
  try {
    const data = await apiRequest("/api/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    document.querySelector("#account-password").value = "";
    if (data.confirmation_required) {
      error.textContent = "Account created. Confirm your email, then sign in.";
      error.hidden = false;
    } else {
      await loadAccountState();
    }
  } catch (reason) {
    error.textContent = reason.message || "Account creation failed.";
    error.hidden = false;
  }
});

document.querySelector("#account-reset-button").addEventListener("click", async () => {
  const error = document.querySelector("#account-error");
  error.hidden = true;
  error.classList.remove("account-success");
  const email = document.querySelector("#account-email").value.trim();
  if (!email) {
    error.textContent = "Enter your email address first.";
    error.hidden = false;
    return;
  }
  try {
    const data = await apiRequest("/api/auth/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    error.textContent = data.message;
    error.hidden = false;
    error.classList.add("account-success");
  } catch (reason) {
    error.textContent = reason.message || "Password reset could not be requested.";
    error.hidden = false;
  }
});

document.querySelector("#account-logout-button").addEventListener("click", async () => {
  await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  setAccountUser(null);
  document.querySelector("#saved-report-list").replaceChildren();
  document.querySelector("#watchlist-list").replaceChildren();
});

async function saveCurrentReport(button) {
  if (!currentReport || !signedInUser) return;
  button.disabled = true;
  const original = button.textContent;
  button.textContent = "Saving…";
  try {
    await apiRequest("/api/saved-reports", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ report: currentReport }),
    });
    button.textContent = "Saved";
    await loadSavedReports();
  } catch (error) {
    button.textContent = error.message || "Save failed";
  } finally {
    window.setTimeout(() => {
      button.textContent = original;
      button.disabled = false;
    }, 1800);
  }
}

async function loadSavedReports() {
  const list = document.querySelector("#saved-report-list");
  const error = document.querySelector("#reports-error");
  error.hidden = true;
  list.replaceChildren();
  try {
    const data = await apiRequest("/api/saved-reports");
    if (!data.reports?.length) {
      appendText(list, "p", "No saved reports yet.", "empty-state");
      return;
    }
    for (const report of data.reports) {
      const item = document.createElement("article");
      item.className = "account-list-item";
      appendText(item, "strong", report.target);
      appendText(item, "span", `${report.label} · ${report.score ?? "N/A"}/100 · ${new Date(report.created_at).toLocaleString()}`);
      const actions = document.createElement("div");
      actions.className = "account-item-actions";
      const viewButton = document.createElement("button");
      viewButton.type = "button";
      viewButton.className = "button-secondary";
      viewButton.textContent = "View report";
      viewButton.addEventListener("click", () => {
        const saved = { ...report.summary, document_type: report.report_type, from: report.target, sender_domain: report.target };
        saved.disclaimer ||= "This is a minimized saved report. Original message contents were not retained.";
        saved.body_summary ||= "Message content was not retained in this saved report.";
        saved.attachments ||= [];
        saved.links ||= [];
        saved.findings ||= [];
        renderResults(saved);
        document.querySelector("#results").scrollIntoView({ behavior: "smooth", block: "start" });
      });
      const deleteButton = document.createElement("button");
      deleteButton.type = "button";
      deleteButton.className = "button-secondary";
      deleteButton.textContent = "Delete";
      deleteButton.addEventListener("click", async () => {
        try {
          await apiRequest(`/api/saved-reports?id=${encodeURIComponent(report.id)}`, { method: "DELETE" });
          await loadSavedReports();
        } catch (reason) {
          error.textContent = reason.message;
          error.hidden = false;
        }
      });
      actions.append(viewButton, deleteButton);
      item.append(actions);
      list.append(item);
    }
  } catch (reason) {
    error.textContent = reason.message || "Saved reports could not be loaded.";
    error.hidden = false;
  }
}

document.querySelector("#refresh-reports-button").addEventListener("click", loadSavedReports);

async function loadWatchlist() {
  const list = document.querySelector("#watchlist-list");
  const error = document.querySelector("#watchlist-error");
  error.hidden = true;
  list.replaceChildren();
  try {
    const data = await apiRequest("/api/watchlist");
    if (!data.domains?.length) {
      appendText(list, "p", "Your watchlist is empty.", "empty-state");
      return;
    }
    for (const domain of data.domains) {
      const item = document.createElement("article");
      item.className = "account-list-item";
      appendText(item, "strong", domain.domain);
      appendText(item, "span", domain.last_checked_at
        ? `Last check: ${domain.last_verdict || "Coverage unavailable"} · ${domain.last_score ?? "N/A"}/100 · ${new Date(domain.last_checked_at).toLocaleString()}`
        : "Not checked yet.");
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "button-secondary";
      remove.textContent = "Remove";
      remove.addEventListener("click", async () => {
        try {
          await apiRequest(`/api/watchlist?id=${encodeURIComponent(domain.id)}`, { method: "DELETE" });
          await loadWatchlist();
        } catch (reason) {
          error.textContent = reason.message;
          error.hidden = false;
        }
      });
      item.append(remove);
      list.append(item);
    }
  } catch (reason) {
    error.textContent = reason.message || "Watchlist could not be loaded.";
    error.hidden = false;
  }
}

document.querySelector("#watchlist-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.querySelector("#watchlist-error");
  error.hidden = true;
  try {
    await apiRequest("/api/watchlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: document.querySelector("#watchlist-domain").value.trim() }),
    });
    document.querySelector("#watchlist-domain").value = "";
    await loadWatchlist();
  } catch (reason) {
    error.textContent = reason.message || "Could not add that domain.";
    error.hidden = false;
  }
});

document.querySelector("#check-watchlist-button").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  const error = document.querySelector("#watchlist-error");
  error.hidden = true;
  button.disabled = true;
  button.textContent = "Checking…";
  try {
    const data = await apiRequest("/api/watchlist/check", { method: "POST" });
    const changes = (data.domains || []).filter((item) => item.changed);
    if (changes.length) {
      error.textContent = `Change detected: ${changes.map((item) => `${item.domain} (${item.previous_score} → ${item.score ?? "N/A"})`).join(", ")}.`;
      error.hidden = false;
      error.classList.add("watchlist-change");
    }
    await loadWatchlist();
  } catch (reason) {
    error.textContent = reason.message || "Watchlist check failed.";
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Check watchlist now";
  }
});

document.querySelector("#compare-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const output = document.querySelector("#compare-results");
  const error = document.querySelector("#compare-error");
  error.hidden = true;
  output.replaceChildren();
  const button = event.currentTarget.querySelector("button[type=submit]");
  button.disabled = true;
  button.textContent = "Comparing…";
  try {
    const data = await apiRequest("/api/compare-domains", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domains: [
        document.querySelector("#compare-domain-one").value.trim(),
        document.querySelector("#compare-domain-two").value.trim(),
      ] }),
    });
    const grid = document.createElement("div");
    grid.className = "comparison-grid";
    for (const domain of data.domains) {
      const card = document.createElement("article");
      card.className = "comparison-card";
      appendText(card, "h4", domain.domain);
      appendText(card, "strong", Number.isFinite(domain.score) ? `${domain.score}/100 · ${domain.label}` : domain.label);
      for (const category of domain.categories || []) {
        appendText(card, "p", `${category.name}: ${Number.isFinite(category.score) ? `${category.score}/${category.maximum}` : "not assessed"} · ${category.coverage}`);
      }
      for (const finding of domain.findings || []) appendText(card, "p", `${finding.title}: ${finding.detail}`);
      grid.append(card);
    }
    output.append(grid);
    appendText(output, "p", data.note, "helper-text");
  } catch (reason) {
    error.textContent = reason.message || "Domain comparison failed.";
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Compare domains";
  }
});

document.querySelector("#url-intelligence-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const output = document.querySelector("#url-intelligence-results");
  const error = document.querySelector("#url-intelligence-error");
  error.hidden = true;
  output.replaceChildren();
  const button = event.currentTarget.querySelector("button[type=submit]");
  button.disabled = true;
  button.textContent = "Inspecting…";
  try {
    const data = await apiRequest("/api/url-intelligence", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: document.querySelector("#url-intelligence-value").value.trim(),
        external_lookup: document.querySelector("#url-reputation-opt-in").checked,
      }),
    });
    const card = document.createElement("article");
    card.className = "comparison-card";
    appendText(card, "h4", data.domain);
    appendText(card, "code", data.url);
    appendText(card, "p", data.message, data.possible_brand_lookalikes.length ? "error-message" : "posture-detail");
    appendText(card, "p", `Punycode hostname: ${data.hostname_is_punycode ? "yes — inspect carefully" : "no"}`, "posture-detail");
    appendText(card, "p", "The destination was not visited.", "helper-text");
    output.append(card);
    if (data.external_intelligence) {
      const reputation = document.createElement("pre");
      reputation.className = "url-reputation";
      reputation.textContent = JSON.stringify(data.external_intelligence, null, 2);
      output.append(reputation);
    }
  } catch (reason) {
    error.textContent = reason.message || "URL inspection failed.";
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Inspect URL";
  }
});
