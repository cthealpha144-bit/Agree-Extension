document.addEventListener("DOMContentLoaded", () => {
  "use strict";

  const els = {
    gradeBadge: document.getElementById("app-grade"),
    container: document.getElementById("points-container"),
    tabAgreeBtn: document.getElementById("tab-agree"),
    tabOptionsBtn: document.getElementById("tab-options"),
    panelAgree: document.getElementById("panel-agree"),
    panelOptions: document.getElementById("panel-options"),
  };

  const INTERNAL_PREFIXES = ["chrome://", "chrome-extension://", "about:"];
  const LOCAL_PREFIX = "file://";
  let runId = 0;

  init();

  async function init() {
    wireTabs();
    await executeAnalysis();
  }

  function wireTabs() {
    els.tabAgreeBtn?.addEventListener("click", () => switchTab("agree"));
    els.tabOptionsBtn?.addEventListener("click", () => switchTab("options"));
  }

  function switchTab(tab) {
    const agree = tab === "agree";
    els.tabAgreeBtn?.classList.toggle("active", agree);
    els.tabOptionsBtn?.classList.toggle("active", !agree);
    els.panelAgree?.classList.toggle("hidden", !agree);
    els.panelOptions?.classList.toggle("hidden", agree);
  }

  async function executeAnalysis() {
    const currentRun = ++runId;
    setLoading("Analyzing page telemetry...");

    try {
      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });

      if (currentRun !== runId) return;

      if (!tab?.url) {
        return renderFallback("No Target", "No active webpage detected.");
      }

      if (INTERNAL_PREFIXES.some((p) => tab.url.startsWith(p))) {
        const report = {
          score: 100,
          verdict: "Safe",
          warnings: [
            {
              text: "Internal browser workspace. Environment is secure.",
              status: "safe",
            },
          ],
        };
        renderSavedData(report);
        renderAnalysisLog(
          tab.url,
          {
            isHttps: true,
            scriptCount: 0,
            formCount: 0,
            inputCount: 0,
            hasPassword: false,
            obfuscationFlag: false,
            hiddenIframe: false,
            hasKeywords: false,
          },
          report,
          false,
        );
        return;
      }

      if (tab.url.startsWith(LOCAL_PREFIX)) {
        return renderFallback(
          "Local File",
          "Offline system paths cannot be audited.",
        );
      }

      const urlObj = new URL(tab.url);
      const domain = urlObj.hostname.replace(/^www\./, "");
      const isHttps = urlObj.protocol === "https:";

      let domData = {
        hasPassword: false,
        obfuscationFlag: false,
        hiddenIframe: false,
        hasKeywords: false,
        scriptCount: 0,
        formCount: 0,
        inputCount: 0,
      };

      try {
        const scriptResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            const text = document.body?.innerText || "";
            const forms = document.querySelectorAll("form");
            const scripts = document.querySelectorAll("script");
            const iframes = document.querySelectorAll("iframe");
            const inputs = document.querySelectorAll("input");
            const hasPassword = !!document.querySelector(
              "input[type='password']",
            );

            let obfuscationFlag = false;
            scripts.forEach((s) => {
              const content = s.textContent || "";
              if (
                content.includes("eval(function(") ||
                content.includes("unescape(") ||
                (content.match(/\\x[0-9a-fA-F]{2}/g) || []).length > 25
              ) {
                obfuscationFlag = true;
              }
            });

            let hiddenIframe = false;
            iframes.forEach((i) => {
              const style = window.getComputedStyle(i);
              if (
                style.display === "none" ||
                style.visibility === "hidden" ||
                i.getAttribute("width") === "0" ||
                i.getAttribute("height") === "0"
              ) {
                hiddenIframe = true;
              }
            });

            const riskPhrases = [
              "verify your account",
              "confirm your password",
              "security alert: login",
              "unauthorized access detected",
              "billing update required",
              "suspend your wallet",
            ];
            const lowerText = text.toLowerCase();
            const hasKeywords = riskPhrases.some((phrase) =>
              lowerText.includes(phrase),
            );

            return {
              hasPassword,
              obfuscationFlag,
              hiddenIframe,
              hasKeywords,
              scriptCount: scripts.length,
              formCount: forms.length,
              inputCount: inputs.length,
            };
          },
        });

        if (scriptResults?.[0]?.result) {
          domData = scriptResults[0].result;
        }
      } catch (domErr) {
        console.warn(
          "DOM scraping blocked by local Content Security Policy rules:",
          domErr,
        );
      }

      let isTrackedNode = false;
      try {
        const radarCheck = await fetch(
          `https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/domains/${domain}.json`,
        );
        if (radarCheck.ok) {
          isTrackedNode = true;
        }
      } catch (_) {}

      if (currentRun !== runId) return;

      const analysisReport = calculateSafetyScore(
        isHttps,
        domData,
        isTrackedNode,
      );
      renderSavedData(analysisReport);
      renderAnalysisLog(tab.url, domData, analysisReport, isTrackedNode);
    } catch (err) {
      console.error(err);
      if (currentRun === runId) {
        renderFallback("Scanner Error", err.message);
      }
    }
  }

  function calculateSafetyScore(isHttps, dom, isTrackedNode) {
    let score = 100;
    const warnings = [];

    if (!isHttps) {
      score -= 30;
      warnings.push({
        text: "Insecure unencrypted connection profile (HTTP).",
        status: "danger",
      });
    } else {
      warnings.push({
        text: "Secure encryption handshake confirmed (HTTPS).",
        status: "safe",
      });
    }

    if (!isHttps && dom.hasPassword) {
      score -= 25;
      warnings.push({
        text: "Critical: Input passwords requested over unencrypted plain text.",
        status: "danger",
      });
    }

    if (dom.hasKeywords) {
      score -= 20;
      warnings.push({
        text: "Suspicious identity or credential manipulation text flags found.",
        status: "danger",
      });
    }

    if (dom.obfuscationFlag) {
      score -= 15;
      warnings.push({
        text: "Obfuscated Javascript string packs or runtime structures hidden.",
        status: "danger",
      });
    }

    if (dom.hiddenIframe) {
      score -= 10;
      warnings.push({
        text: "Hidden inline visual canvas frames (iframes) detected.",
        status: "warning",
      });
    }

    if (isTrackedNode) {
      score -= 10;
      warnings.push({
        text: "Domain explicitly indexed inside background tracker maps.",
        status: "warning",
      });
    }

    if (dom.scriptCount > 35) {
      score -= 5;
      warnings.push({
        text: `Heavy processing load: registers ${dom.scriptCount} external script bindings.`,
        status: "warning",
      });
    }

    score = Math.max(0, Math.min(100, score));

    let verdict = "Safe";
    if (score < 50) {
      verdict = "Unsafe";
    } else if (score < 80) {
      verdict = "Suspicious";
    }

    if (warnings.length === 1 && warnings[0].status === "safe") {
      warnings.push({
        text: "No hostile behavioral indicators flagged on the DOM surface.",
        status: "safe",
      });
    }

    return { score, verdict, warnings };
  }

  function renderSavedData(data) {
    const score = data.score;
    const verdict = data.verdict;

    els.gradeBadge.textContent = `${score}/100`;

    els.gradeBadge.className = "grade-badge";
    if (verdict === "Safe") {
      els.gradeBadge.classList.add("badge-safe");
    } else if (verdict === "Suspicious") {
      els.gradeBadge.classList.add("badge-warning");
    } else {
      els.gradeBadge.classList.add("badge-risk");
    }

    const classMap = {
      safe: "tag-safe",
      warning: "tag-warning",
      danger: "tag-risk",
    };

    els.container.innerHTML =
      `
      <div style="font-weight: 700; font-size: 13px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; padding-left: 4px;">
        <span>Verdict:</span> 
        <span class="risk-tag ${verdict === "Safe" ? "tag-safe" : verdict === "Suspicious" ? "tag-warning" : "tag-risk"}">
          ${verdict.toUpperCase()}
        </span>
      </div>
    ` +
      data.warnings
        .map(
          (w) => `
        <div class="point-item" style="border-left-color: ${w.status === "safe" ? "#198754" : w.status === "warning" ? "#ffc107" : "#dc3545"}">
          <span class="point-text">${escapeHtml(w.text)}</span>
          <span class="risk-tag ${classMap[w.status] || "tag-neutral"}">
            ${w.status === "danger" ? "WARNING" : w.status.toUpperCase()}
          </span>
        </div>
      `,
        )
        .join("");
  }

  function renderAnalysisLog(url, dom, report, trackerRadarMatch) {
    if (!els.panelOptions) return;

    const isHttps = url.startsWith("https:");

    els.panelOptions.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 10px; font-size: 12px; color: #333;">
        
        <div style="background: #f8f9fa; padding: 12px; border-radius: 12px; border: 1px solid #e9ecef;">
          <strong style="color: #6c757d; display: block; margin-bottom: 4px; text-transform: uppercase; font-size: 10px;">Target URL</strong>
          <span style="word-break: break-all; font-family: monospace; background: #e9ecef; padding: 4px 6px; border-radius: 6px; display: block;">${escapeHtml(url)}</span>
        </div>

        <div style="background: #f8f9fa; padding: 12px; border-radius: 12px; border: 1px solid #e9ecef;">
          <strong style="color: #6c757d; display: block; margin-bottom: 6px; text-transform: uppercase; font-size: 10px;">Scraped Metadata Indicators</strong>
          
          <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #e9ecef;">
            <span>Connection Security:</span>
            <span style="font-weight: 600; color: ${isHttps ? "#198754" : "#dc3545"}">${isHttps ? "HTTPS" : "HTTP"}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #e9ecef;">
            <span>Total Scripts Loaded:</span>
            <span style="font-weight: 600;">${dom.scriptCount}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #e9ecef;">
            <span>DOM Forms Detected:</span>
            <span style="font-weight: 600;">${dom.formCount}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #e9ecef;">
            <span>DOM Input Elements:</span>
            <span style="font-weight: 600;">${dom.inputCount}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #e9ecef;">
            <span>Password Vector Scraped:</span>
            <span style="font-weight: 600; color: ${dom.hasPassword ? "#dc3545" : "#198754"}">${dom.hasPassword ? "YES" : "NO"}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #e9ecef;">
            <span>Obfuscated/Packed Script:</span>
            <span style="font-weight: 600; color: ${dom.obfuscationFlag ? "#dc3545" : "#198754"}">${dom.obfuscationFlag ? "YES" : "NO"}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #e9ecef;">
            <span>Hidden Frame (iframes):</span>
            <span style="font-weight: 600; color: ${dom.hiddenIframe ? "#ffc107" : "#198754"}">${dom.hiddenIframe ? "YES" : "NO"}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #e9ecef;">
            <span>Phishing Keyword Match:</span>
            <span style="font-weight: 600; color: ${dom.hasKeywords ? "#dc3545" : "#198754"}">${dom.hasKeywords ? "YES" : "NO"}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 6px 0;">
            <span>Tracker Radar Listed:</span>
            <span style="font-weight: 600; color: ${trackerRadarMatch ? "#ffc107" : "#198754"}">${trackerRadarMatch ? "YES" : "NO"}</span>
          </div>

        </div>

        <div style="background: #f8f9fa; padding: 12px; border-radius: 12px; border: 1px solid #e9ecef;">
          <strong style="color: #6c757d; display: block; margin-bottom: 4px; text-transform: uppercase; font-size: 10px;">Scoring Processing Ledger</strong>
          <div style="font-size: 11px; font-family: monospace; line-height: 1.4; color: #495057;">
            Initial Baseline: 100 points<br>
            ${!isHttps ? "- Deduct 30: Insecure protocol<br>" : ""}
            ${!isHttps && dom.hasPassword ? "- Deduct 25: Unencrypted password input<br>" : ""}
            ${dom.hasKeywords ? "- Deduct 20: Phishing string match<br>" : ""}
            ${dom.obfuscationFlag ? "- Deduct 15: Obfuscated script payload<br>" : ""}
            ${dom.hiddenIframe ? "- Deduct 10: Off-canvas iframe element<br>" : ""}
            ${trackerRadarMatch ? "- Deduct 10: Listed tracker domain<br>" : ""}
            ${dom.scriptCount > 35 ? "- Deduct 5: High script volume threshold<br>" : ""}
            <div style="margin-top: 6px; padding-top: 6px; border-top: 1px dashed #dee2e6; font-weight: 700; font-size: 12px; color: #212529;">
              Calculated Remainder: ${report.score} / 100 (${report.verdict})
            </div>
          </div>
        </div>

      </div>
    `;
  }

  function renderFallback(title, msg) {
    els.gradeBadge.textContent = "?";
    els.gradeBadge.className = "grade-badge badge-unknown";

    els.container.innerHTML = `
      <div class="point-item">
        <span class="point-text">
          <strong>${escapeHtml(title)}</strong><br>
          ${escapeHtml(msg)}
        </span>
      </div>
    `;
  }

  function setLoading(text) {
    els.gradeBadge.textContent = "...";
    els.gradeBadge.className = "grade-badge badge-unknown";

    els.container.innerHTML = `
      <div class="point-item">
        <span class="point-text">${escapeHtml(text)}</span>
        <span class="risk-tag tag-neutral">RUNNING</span>
      </div>
    `;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
});
