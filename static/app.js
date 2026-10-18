/**
 * GhostData - Client-Side Controller
 * Handles drag-and-drop, secure AJAX uploads, findings rendering,
 * and post-cleaning verification visualization.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Elements
    const dropZone = document.getElementById("dropZone");
    const fileInput = document.getElementById("fileInput");
    const browseBtn = document.getElementById("browseBtn");
    const statusBox = document.getElementById("statusBox");
    const statusTitle = document.getElementById("statusTitle");
    const statusDetail = document.getElementById("statusDetail");
    const errorBox = document.getElementById("errorBox");
    const errorMessage = document.getElementById("errorMessage");

    const uploadSection = document.getElementById("uploadSection");
    const resultsSection = document.getElementById("resultsSection");
    const newFileBtn = document.getElementById("newFileBtn");

    // Results elements
    const resFileType = document.getElementById("resFileType");
    const resFileName = document.getElementById("resFileName");
    const resFileSize = document.getElementById("resFileSize");
    const resFileExtra = document.getElementById("resFileExtra");

    const riskBanner = document.getElementById("riskBanner");
    const riskLevelBadge = document.getElementById("riskLevelBadge");
    const riskSummaryHeadline = document.getElementById("riskSummaryHeadline");
    const riskSummaryDetails = document.getElementById("riskSummaryDetails");
    const severityCounters = document.getElementById("severityCounters");

    const findingsGrid = document.getElementById("findingsGrid");
    const findingsCountText = document.getElementById("findingsCountText");

    // Clean & Verification elements
    const cleanBtn = document.getElementById("cleanBtn");
    const verificationPanel = document.getElementById("verificationPanel");
    const verifTitle = document.getElementById("verifTitle");
    const verifSubtitle = document.getElementById("verifSubtitle");
    const validityText = document.getElementById("validityText");
    const validitySubtext = document.getElementById("validitySubtext");
    const diffList = document.getElementById("diffList");
    const unverifiedCard = document.getElementById("unverifiedCard");
    const unverifiedList = document.getElementById("unverifiedList");
    const downloadBtn = document.getElementById("downloadBtn");
    const reportBtn = document.getElementById("reportBtn");

    let currentFileId = null;

    // Get CSRF Token from meta tag
    const getCsrfToken = () => {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute("content") : "";
    };

    // Helper: Show/Hide Error
    const showError = (msg) => {
        errorMessage.textContent = msg;
        errorBox.classList.remove("hidden");
        statusBox.classList.add("hidden");
    };

    const clearError = () => {
        errorBox.classList.add("hidden");
        errorMessage.textContent = "";
    };

    // Helper: Show/Hide Status
    const setStatus = (title, detail) => {
        statusTitle.textContent = title;
        statusDetail.textContent = detail;
        statusBox.classList.remove("hidden");
        clearError();
    };

    const hideStatus = () => {
        statusBox.classList.add("hidden");
    };

    // Drag and Drop Events
    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove("dragover");
        });
    });

    dropZone.addEventListener("drop", (e) => {
        const dt = e.dataTransfer;
        if (dt && dt.files && dt.files.length > 0) {
            handleFileSelection(dt.files[0]);
        }
    });

    browseBtn.addEventListener("click", () => fileInput.click());
    dropZone.addEventListener("click", (e) => {
        if (e.target !== browseBtn) {
            fileInput.click();
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files.length > 0) {
            handleFileSelection(e.target.files[0]);
        }
    });

    newFileBtn.addEventListener("click", () => {
        resultsSection.classList.add("hidden");
        verificationPanel.classList.add("hidden");
        uploadSection.classList.remove("hidden");
        fileInput.value = "";
        currentFileId = null;
        clearError();
        hideStatus();
    });

    // Upload & Analysis Handler
    const handleFileSelection = (file) => {
        clearError();

        // Check local size restriction (10 MB)
        const maxBytes = 10 * 1024 * 1024;
        if (file.size > maxBytes) {
            showError(`File exceeds maximum allowed upload size (10 MB). Selected file is ${(file.size / (1024 * 1024)).toFixed(1)} MB.`);
            return;
        }

        setStatus("Validating File Signature...", "Verifying file headers and authentic magic bytes...");

        const formData = new FormData();
        formData.append("file", file);

        fetch("/api/upload", {
            method: "POST",
            headers: {
                "X-CSRF-Token": getCsrfToken()
            },
            body: formData
        })
        .then(async (response) => {
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || "Upload or validation failed.");
            }
            return data;
        })
        .then((data) => {
            hideStatus();
            displayResults(data);
        })
        .catch((err) => {
            showError(err.message || "An unexpected error occurred while communicating with the server.");
        });
    };

    // Render Analysis Results
    const displayResults = (data) => {
        currentFileId = data.file_id;

        // Populate Summary
        resFileType.textContent = data.file_type;
        resFileName.textContent = data.original_filename;
        resFileSize.textContent = data.file_size_formatted;

        const extraInfo = data.metadata.dimensions || (data.metadata.page_count ? `${data.metadata.page_count} page(s)` : "");
        resFileExtra.textContent = extraInfo;

        const risk = data.risk_report;

        // Update Risk Badge
        riskLevelBadge.className = `risk-badge ${risk.overall_risk}`;
        riskLevelBadge.textContent = `${risk.overall_risk} RISK`;
        riskSummaryHeadline.textContent = risk.overall_risk === "MINIMAL" ? "No Sensitive Exposure Found" : `${risk.overall_risk} Privacy Risk Exposure`;
        riskSummaryDetails.textContent = risk.risk_summary;

        // Severity Counters
        severityCounters.innerHTML = "";
        const severities = ["High", "Medium", "Low", "Informational"];
        severities.forEach(sev => {
            const count = risk.severity_counts[sev] || 0;
            const chip = document.createElement("div");
            chip.className = "counter-chip";
            chip.innerHTML = `<strong>${count}</strong>${sev}`;
            severityCounters.appendChild(chip);
        });

        // Findings count text
        findingsCountText.textContent = `Found ${risk.total_findings} item${risk.total_findings !== 1 ? 's' : ''}`;

        // Populate Findings Cards
        findingsGrid.innerHTML = "";
        if (risk.findings.length === 0) {
            findingsGrid.innerHTML = `
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 1.5rem; text-align: center; color: #34d399;">
                    ✨ <strong>Clean File:</strong> No known privacy-sensitive metadata fields (such as GPS, author, software, or serials) were found in this file.
                </div>
            `;
        } else {
            risk.findings.forEach((finding, idx) => {
                const card = document.createElement("div");
                card.className = `finding-card severity-${finding.severity}`;

                const safeRaw = encodeURIComponent(finding.raw_value);
                const safeMasked = encodeURIComponent(finding.masked_value);

                card.innerHTML = `
                    <div class="finding-header">
                        <div class="finding-title-group">
                            <span class="finding-field-name">${finding.field}</span>
                            <span class="finding-category">• ${finding.category}</span>
                        </div>
                        <span class="badge badge-${finding.severity.toLowerCase()}">${finding.severity}</span>
                    </div>

                    <div class="finding-value-row">
                        <span id="val-${idx}">${escapeHtml(finding.masked_value)}</span>
                        ${finding.raw_value !== finding.masked_value ? `
                            <button type="button" class="btn-toggle-mask" data-idx="${idx}" data-raw="${safeRaw}" data-masked="${safeMasked}">
                                Reveal
                            </button>
                        ` : ''}
                    </div>

                    <div class="finding-body">
                        <div class="finding-item">
                            <label>Privacy Concern</label>
                            <p>${escapeHtml(finding.privacy_concern)}</p>
                        </div>
                        <div class="finding-item">
                            <label>Plain-English Explanation</label>
                            <p>${escapeHtml(finding.plain_english_explanation)}</p>
                        </div>
                    </div>

                    <div class="finding-footer">
                        <span><strong>Suggested Action:</strong> ${escapeHtml(finding.suggested_action)}</span>
                        <span><em>${escapeHtml(finding.confidence)}</em></span>
                    </div>
                `;

                findingsGrid.appendChild(card);
            });

            // Attach toggle listeners for masked values
            document.querySelectorAll(".btn-toggle-mask").forEach(btn => {
                btn.addEventListener("click", (e) => {
                    const idx = e.target.getAttribute("data-idx");
                    const rawVal = decodeURIComponent(e.target.getAttribute("data-raw"));
                    const maskedVal = decodeURIComponent(e.target.getAttribute("data-masked"));
                    const valSpan = document.getElementById(`val-${idx}`);

                    if (e.target.textContent.trim() === "Reveal") {
                        valSpan.textContent = rawVal;
                        e.target.textContent = "Mask";
                    } else {
                        valSpan.textContent = maskedVal;
                        e.target.textContent = "Reveal";
                    }
                });
            });
        }

        // Show results and hide upload
        uploadSection.classList.add("hidden");
        resultsSection.classList.remove("hidden");
        verificationPanel.classList.add("hidden");
    };

    // Clean & Verify Action
    cleanBtn.addEventListener("click", () => {
        if (!currentFileId) return;

        cleanBtn.disabled = true;
        cleanBtn.innerHTML = `⏳ Sanitizing & Verifying Output...`;

        fetch("/api/clean", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken()
            },
            body: JSON.stringify({ file_id: currentFileId })
        })
        .then(async (response) => {
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || "Cleaning failed.");
            }
            return data;
        })
        .then((data) => {
            displayVerification(data.verification);
            cleanBtn.disabled = false;
            cleanBtn.innerHTML = `✨ Re-Sanitize Copy`;
        })
        .catch((err) => {
            cleanBtn.disabled = false;
            cleanBtn.innerHTML = `✨ Clean Metadata & Verify`;
            alert(`Cleaning Error: ${err.message}`);
        });
    });

    // Display Post-Cleaning Verification Report
    const displayVerification = (verif) => {
        verificationPanel.classList.remove("hidden");

        verifTitle.textContent = verif.verdict_summary;
        verifSubtitle.textContent = `Completed second-pass re-inspection on sanitized copy. Verified ${verif.removed_fields.length} removed field(s).`;

        // Integrity status
        validityText.textContent = verif.validity_check.is_valid ? "Valid Output Format Confirmed" : "Integrity Failure";
        validitySubtext.textContent = verif.validity_check.details || verif.validity_check.error;

        // Diff List
        diffList.innerHTML = "";
        if (verif.removed_fields.length === 0 && verif.remaining_fields.length === 0) {
            diffList.innerHTML = `<li>No metadata changes needed. File was verified clean.</li>`;
        }

        verif.removed_fields.forEach(rf => {
            const li = document.createElement("li");
            li.style.color = "#34d399";
            li.innerHTML = `✅ <strong>${escapeHtml(rf.field)}</strong>: Removed (${escapeHtml(rf.evidence)})`;
            diffList.appendChild(li);
        });

        verif.remaining_fields.forEach(rem => {
            const li = document.createElement("li");
            li.style.color = "#f87171";
            li.innerHTML = `❌ <strong>${escapeHtml(rem.field)}</strong>: Still present (${escapeHtml(rem.reason)})`;
            diffList.appendChild(li);
        });

        // Unverified structures
        if (verif.unverified_fields && verif.unverified_fields.length > 0) {
            unverifiedCard.classList.remove("hidden");
            unverifiedList.innerHTML = "";
            verif.unverified_fields.forEach(u => {
                const li = document.createElement("li");
                li.textContent = `${u.structure} — ${u.reason}`;
                unverifiedList.appendChild(li);
            });
        } else {
            unverifiedCard.classList.add("hidden");
        }

        // Links
        downloadBtn.href = `/download/${currentFileId}`;
        reportBtn.href = `/report/${currentFileId}`;

        // Scroll to verification panel smoothly
        verificationPanel.scrollIntoView({ behavior: "smooth" });
    };

    // Helper: Escape HTML
    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
