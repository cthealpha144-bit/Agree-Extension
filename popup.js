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

  const INTERNAL_PREFIXES = [
    "chrome://",
    "chrome-extension://",
    "about:",
    "https://chromewebstore.google.com",
    "https://chrome.google.com/webstore",
  ];
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
    setLoading("Compiling structural runtime snapshots...");

    try {
      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });

      if (currentRun !== runId) return;

      if (!tab?.url) {
        return renderFallback(
          "Null Environment",
          "No structural webpage stream detected.",
        );
      }

      if (INTERNAL_PREFIXES.some((p) => tab.url.startsWith(p))) {
        const report = { score: 100, verdict: "Safe", warnings: [] };
        renderSavedData(report);
        renderAnalysisLog(tab.url, getEmptyDomObject(), report, [], false);
        return;
      }

      if (tab.url.startsWith(LOCAL_PREFIX)) {
        return renderFallback(
          "Local Target",
          "Offline system paths isolated from auditing.",
        );
      }

      const urlObj = new URL(tab.url);
      const domain = urlObj.hostname.replace(/^www\./, "");
      const isHttps = urlObj.protocol === "https:";

      let cookiesList = [];
      try {
        cookiesList = await chrome.cookies.getAll({ domain: urlObj.hostname });
      } catch (cErr) {
        console.warn("Storage API permissions initialization bypass:", cErr);
      }

      let domData = getEmptyDomObject();

      const aiUrlAnalysis = analyzeUrlWithHeuristics(tab.url);
      domData.aiUrlScore = aiUrlAnalysis.score;
      domData.aiUrlFlags = aiUrlAnalysis.flags;

      try {
        const scriptResults = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            const html = document.documentElement?.innerHTML || "";
            const text = document.body?.innerText || "";
            const titleText = document.title
              ? document.title.toLowerCase()
              : "";
            const forms = document.querySelectorAll("form");
            const scripts = document.querySelectorAll("script");
            const iframes = document.querySelectorAll("iframe");
            const inputs = document.querySelectorAll("input");
            const currentHostname = window.location.hostname;

            const whitelist = [
              "chatgpt.com",
              "gemini.google.com",
              "github.com",
              "docs.google.com",
            ];
            const isWhitelisted = whitelist.some((d) =>
              currentHostname.endsWith(d),
            );

            let isIpBased =
              !isWhitelisted &&
              /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(
                currentHostname,
              );
            let excessiveSubdomains =
              !isWhitelisted && currentHostname.split(".").length - 1 > 3;
            let punycodeSpoof = currentHostname.includes("xn--");

            let hiddenIframe = false;
            let overlayTrap = false;
            iframes.forEach((i) => {
              const style = window.getComputedStyle(i);
              if (
                style.display === "none" ||
                style.visibility === "hidden" ||
                i.getAttribute("width") === "0" ||
                i.getAttribute("height") === "0" ||
                style.opacity === "0"
              ) {
                hiddenIframe = true;
              }
              if (
                !isWhitelisted &&
                style.position === "fixed" &&
                (style.width === "100vw" || parseInt(style.width) > 900) &&
                style.opacity === "0"
              ) {
                overlayTrap = true;
              }
            });

            let hasPassword = !!document.querySelector(
              "input[type='password']",
            );
            let externalForm = false;
            forms.forEach((form) => {
              let action = form.getAttribute("action");
              if (action) {
                try {
                  let actionUrl = new URL(action, window.location.href);
                  if (
                    actionUrl.hostname !== currentHostname &&
                    !actionUrl.protocol.startsWith("chrome")
                  ) {
                    externalForm = true;
                  }
                } catch (_) {}
              }
            });

            let brandImpersonation = false;
            const targetBrands = {
              paypal: ["paypal.com"],
              microsoft: ["microsoft.com", "live.com", "office.com"],
              google: ["google.com", "accounts.google.com"],
              netflix: ["netflix.com"],
              facebook: ["facebook.com"],
              apple: ["apple.com", "icloud.com"],
            };
            for (const [brand, domains] of Object.entries(targetBrands)) {
              if (
                titleText.includes(brand) ||
                text.toLowerCase().includes(brand + " login")
              ) {
                let matchesLegit = domains.some((d) =>
                  currentHostname.endsWith(d),
                );
                if (!matchesLegit) brandImpersonation = true;
              }
            }

            let obfuscationFlag = false;
            let astObfuscationTokens = 0;
            scripts.forEach((s) => {
              const content = s.textContent || "";
              const hasEval =
                content.includes("eval(function(") ||
                content.includes("window.atob(");
              const matches = content.match(/_0x[a-f0-9]{4,6}/g);
              if (matches) {
                astObfuscationTokens += matches.length;
              }
              if (hasEval && matches) {
                obfuscationFlag = true;
              }
            });
            let highAstRisk = !isWhitelisted && astObfuscationTokens > 25;

            const riskPhrases = [
              "verify your account",
              "confirm your password",
              "security alert: login",
              "unauthorized access detected",
              "billing update required",
              "suspend your wallet",
            ];
            const lowerText = text.toLowerCase();
            const hasKeywords =
              !isWhitelisted &&
              riskPhrases.some((phrase) => lowerText.includes(phrase));

            let localStorageCount = 0;
            try {
              localStorageCount = Object.keys(window.localStorage).length;
            } catch (_) {}

            let mutationTriggers = window.__agreeMutationCount || 0;
            if (!window.__agreeObserved) {
              window.__agreeMutationCount = 0;
              const obs = new MutationObserver(() => {
                if (window.__agreeMutationCount < 150) {
                  window.__agreeMutationCount++;
                }
              });
              obs.observe(document.documentElement, {
                childList: true,
                subtree: true,
              });
              window.__agreeObserved = true;
            }

            return {
              isIpBased,
              excessiveSubdomains,
              punycodeSpoof,
              hiddenIframe,
              overlayTrap,
              hasPassword,
              externalForm,
              brandImpersonation,
              obfuscationFlag,
              highAstRisk,
              hasKeywords,
              scriptCount: scripts.length,
              formCount: forms.length,
              inputCount: inputs.length,
              localStorageCount,
              mutationTriggers,
            };
          },
        });

        if (scriptResults?.[0]?.result) {
          Object.assign(domData, scriptResults[0].result);
        }
      } catch (domErr) {
        console.warn("DOM payload execution constraint:", domErr);
      }

      let isTrackedNode = false;
      try {
        const radarCheck = await fetch(
          `https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/domains/${domain}.json`,
        );
        if (radarCheck.ok) isTrackedNode = true;
      } catch (_) {}

      if (currentRun !== runId) return;

      const analysisReport = calculateSafetyScore(
        isHttps,
        domData,
        isTrackedNode,
        cookiesList,
      );
      renderSavedData(analysisReport);
      renderAnalysisLog(
        tab.url,
        domData,
        analysisReport,
        cookiesList,
        isTrackedNode,
      );
    } catch (err) {
      console.error(err);
      if (currentRun === runId) {
        renderFallback("Audit Defect", err.message);
      }
    }
  }

  function getEmptyDomObject() {
    return {
      isIpBased: false,
      excessiveSubdomains: false,
      punycodeSpoof: false,
      hiddenIframe: false,
      overlayTrap: false,
      hasPassword: false,
      externalForm: false,
      brandImpersonation: false,
      obfuscationFlag: false,
      highAstRisk: false,
      hasKeywords: false,
      scriptCount: 0,
      formCount: 0,
      inputCount: 0,
      localStorageCount: 0,
      mutationTriggers: 0,
      aiUrlScore: 100,
      aiUrlFlags: [],
    };
  }

  function analyzeUrlWithHeuristics(urlStr) {
    let score = 100;
    const flags = [];

    try {
      const url = new URL(urlStr);
      const host = url.hostname.toLowerCase();
      const cleanHost = host.replace(/^www\./, "");

      const charCounts = {};
      for (let char of cleanHost) {
        charCounts[char] = (charCounts[char] || 0) + 1;
      }
      let entropy = 0;
      for (let char in charCounts) {
        let p = charCounts[char] / cleanHost.length;
        entropy -= p * Math.log2(p);
      }
      if (entropy > 4.2 && cleanHost.length > 22) {
        score -= 30;
        flags.push("High string entropy (randomized domain structure)");
      }

      const dashCount = (cleanHost.match(/-/g) || []).length;
      if (dashCount > 3) {
        score -= 20;
        flags.push("Excessive hyphen accumulation (phishing concatenation)");
      }

      const targetBrands = [
        "paypal",
        "microsoft",
        "google",
        "netflix",
        "facebook",
        "apple",
        "amazon",
        "chase",
        "bankofamerica",
        "chatgpt",
      ];

      targetBrands.forEach((brand) => {
        if (cleanHost.includes(brand)) {
          const parts = cleanHost.split(".");
          const mainDomain = parts.slice(-2).join(".");
          if (!mainDomain.includes(brand)) {
            score -= 45;
            flags.push(`Brand keyword manipulation detected [${brand}]`);
          }
        }
      });
    } catch (err) {
      console.error("AI URL parser error:", err);
    }

    return {
      score: Math.max(0, score),
      flags: flags,
    };
  }

  function calculateSafetyScore(isHttps, dom, isTrackedNode, cookies) {
    let score = 100;
    const warnings = [];

    if (dom.aiUrlScore < 100) {
      const totalDeduction = 100 - dom.aiUrlScore;
      score -= totalDeduction;
      dom.aiUrlFlags.forEach((flag) => {
        warnings.push({
          text: `AI Front-Line Guard: ${flag}.`,
          status: "danger",
        });
      });
    }

    if (dom.brandImpersonation) {
      score -= 50;
      warnings.push({
        text: "Critical: Target brand wording mismatch against context host domain.",
        status: "danger",
      });
    }
    if (dom.externalForm) {
      score -= 40;
      warnings.push({
        text: "Critical: Interactive input form routes directly to an external endpoint.",
        status: "danger",
      });
    }
    if (dom.punycodeSpoof) {
      score -= 35;
      warnings.push({
        text: "High: Character encoding match indicates potential homograph domain spoofing.",
        status: "danger",
      });
    }
    if (!isHttps) {
      score -= 30;
      warnings.push({
        text: "High: Plaintext connection protocol in use (HTTP).",
        status: "danger",
      });
    }
    if (dom.isIpBased) {
      score -= 25;
      warnings.push({
        text: "High: Address mapped entirely to raw IP array, bypasses DNS registration.",
        status: "danger",
      });
    }
    if (dom.highAstRisk) {
      score -= 25;
      warnings.push({
        text: "High: Multi-token array obfuscation match detected via static inspection.",
        status: "danger",
      });
    }
    if (dom.overlayTrap) {
      score -= 20;
      warnings.push({
        text: "Medium: Clear absolute canvas wrapper elements detected.",
        status: "warning",
      });
    }
    if (dom.hasKeywords) {
      score -= 20;
      warnings.push({
        text: "Medium: Urgent call-to-action semantic phishing syntax detected.",
        status: "warning",
      });
    }
    if (dom.obfuscationFlag) {
      score -= 15;
      warnings.push({
        text: "Medium: Runtime interpretation calls (eval/atob) identified inside DOM elements.",
        status: "warning",
      });
    }
    if (dom.excessiveSubdomains) {
      score -= 15;
      warnings.push({
        text: "Medium: Complex domain routing mapping multi-level layers.",
        status: "warning",
      });
    }
    if (dom.hiddenIframe) {
      score -= 10;
      warnings.push({
        text: "Medium: Zero-dimension canvas elements (iframes) present on surface.",
        status: "warning",
      });
    }
    if (isTrackedNode) {
      score -= 10;
      warnings.push({
        text: "Medium: Host structure matches tracking maps in tracker registry databases.",
        status: "warning",
      });
    }
    if (dom.scriptCount > 35) {
      score -= 5;
      warnings.push({
        text: `Low: High structural script footprint density (${dom.scriptCount} files).`,
        status: "caution",
      });
    }

    let weakCookies = 0;
    cookies.forEach((c) => {
      if (!c.secure || !c.httpOnly) weakCookies++;
    });
    if (weakCookies > 5) {
      score -= 5;
      warnings.push({
        text: `Low: Session attributes missing explicit script accessibility constraints.`,
        status: "caution",
      });
    }

    score = Math.max(0, Math.min(100, score));

    let verdict = "Safe";
    if (score < 40) verdict = "Unsafe";
    else if (score < 70) verdict = "Suspicious";
    else if (score < 90) verdict = "Caution";

    if (warnings.length === 0) {
      warnings.push({
        text: "No anomalous behavioral structural markers flagged during execution.",
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

    if (verdict === "Safe") els.gradeBadge.classList.add("badge-safe");
    else if (verdict === "Caution")
      els.gradeBadge.classList.add("badge-caution");
    else if (verdict === "Suspicious")
      els.gradeBadge.classList.add("badge-warning");
    else els.gradeBadge.classList.add("badge-risk");

    const classMap = {
      safe: "tag-safe",
      caution: "tag-caution",
      warning: "tag-warning",
      danger: "tag-risk",
    };

    els.container.innerHTML =
      `
      <div style="font-weight: 700; font-size: 13px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; padding-left: 4px;">
        <span>Processing Result:</span> 
        <span class="risk-tag ${verdict === "Safe" ? "tag-safe" : verdict === "Caution" ? "tag-caution" : verdict === "Suspicious" ? "tag-warning" : "tag-risk"}">
          ${verdict.toUpperCase()}
        </span>
      </div>
    ` +
      data.warnings
        .map(
          (w) => `
        <div class="point-item" style="border-left-color: ${w.status === "safe" ? "#198754" : w.status === "caution" ? "#f76707" : w.status === "warning" ? "#ffc107" : "#dc3545"}">
          <span class="point-text">${escapeHtml(w.text)}</span>
          <span class="risk-tag ${classMap[w.status] || "tag-neutral"}">
            ${w.status === "danger" ? "CRITICAL" : w.status.toUpperCase()}
          </span>
        </div>
      `,
        )
        .join("");
  }

  function renderAnalysisLog(url, dom, report, cookies, trackerRadarMatch) {
    if (!els.panelOptions) return;

    const isHttps = url.startsWith("https:");
    let secureCookiesCount = cookies.filter(
      (c) => c.secure && c.httpOnly,
    ).length;

    els.panelOptions.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 10px; font-size: 12px; color: #333;">
        
        <div style="background: #f8f9fa; padding: 12px; border-radius: 12px; border: 1px solid #e9ecef;">
          <strong style="color: #6c757d; display: block; margin-bottom: 4px; text-transform: uppercase; font-size: 10px;">Network Architecture</strong>
          <span style="word-break: break-all; font-family: monospace; background: #e9ecef; padding: 4px 6px; border-radius: 6px; display: block;">${escapeHtml(url)}</span>
        </div>

        <div style="background: #f8f9fa; padding: 12px; border-radius: 12px; border: 1px solid #e9ecef;">
          <strong style="color: #6c757d; display: block; margin-bottom: 6px; text-transform: uppercase; font-size: 10px;">Comprehensive DOM Telemetry Profiles</strong>
          
          <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #e9ecef;">
            <span>AI URL Profiler Engine:</span>
            <span style="font-weight: 600; color: ${dom.aiUrlScore === 100 ? "#198754" : "#dc3545"}">
              ${dom.aiUrlScore === 100 ? "CLEAN STRUCTURE" : "RISK PATTERNS FLAGGED"}
            </span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #e9ecef;">
            <span>Transport Protection:</span>
            <span style="font-weight: 600; color: ${isHttps ? "#198754" : "#dc3545"}">${isHttps ? "HTTPS" : "HTTP"}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #e9ecef;">
            <span>Brand Impersonation Vector:</span>
            <span style="font-weight: 600; color: ${dom.brandImpersonation ? "#dc3545" : "#198754"}">${dom.brandImpersonation ? "MISMATCH" : "MATCHED"}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #e9ecef;">
            <span>Form Processing Outflow:</span>
            <span style="font-weight: 600; color: ${dom.externalForm ? "#dc3545" : "#198754"}">${dom.externalForm ? "EXTERNAL SUBMIT" : "SAME-ORIGIN"}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #e9ecef;">
            <span>Static AST Obfuscation Match:</span>
            <span style="font-weight: 600; color: ${dom.highAstRisk ? "#dc3545" : "#198754"}">${dom.highAstRisk ? "HIGH PROBABILITY" : "NONE"}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #e9ecef;">
            <span>Deceptive Frame Layers:</span>
            <span style="font-weight: 600; color: ${dom.overlayTrap ? "#dc3545" : "#198754"}">${dom.overlayTrap ? "OVERLAY DETECTED" : "CLEAN"}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #e9ecef;">
            <span>Dynamic Mutation Count:</span>
            <span style="font-weight: 600;">${dom.mutationTriggers} events</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #e9ecef;">
            <span>Total Scripts Stacked:</span>
            <span style="font-weight: 600;">${dom.scriptCount}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #e9ecef;">
            <span>Total Inspected Storage Keys:</span>
            <span style="font-weight: 600;">${dom.localStorageCount + cookies.length}</span>
          </div>

          <div style="display: flex; justify-content: space-between; padding: 4px 0;">
            <span>Hardened Cookie Allocations:</span>
            <span style="font-weight: 600;">${secureCookiesCount} / ${cookies.length}</span>
          </div>

        </div>

        <div style="background: #f8f9fa; padding: 12px; border-radius: 12px; border: 1px solid #e9ecef;">
          <strong style="color: #6c757d; display: block; margin-bottom: 4px; text-transform: uppercase; font-size: 10px;">Deterministic Heuristic Engine Ledger</strong>
          <div style="font-size: 11px; font-family: monospace; line-height: 1.4; color: #495057;">
            Baseline Capacity: 100 points<br>
            ${dom.aiUrlScore < 100 ? `- Deduct ${100 - dom.aiUrlScore}: Front-line AI structural URL vector alerts<br>` : ""}
            ${dom.brandImpersonation ? "- Deduct 50: Brand name spoofing alert<br>" : ""}
            ${dom.externalForm ? "- Deduct 40: Cross-domain input action routing<br>" : ""}
            ${dom.punycodeSpoof ? "- Deduct 35: Punycode text manipulation mismatch<br>" : ""}
            ${!isHttps ? "- Deduct 30: Unencrypted wire transport layer<br>" : ""}
            ${dom.isIpBased ? "- Deduct 25: Raw numeric IP destination signature<br>" : ""}
            ${dom.highAstRisk ? "- Deduct 25: AST structural packing obfuscation signatures<br>" : ""}
            ${dom.overlayTrap ? "- Deduct 20: Full-screen interaction trap frames<br>" : ""}
            ${dom.hasKeywords ? "- Deduct 20: Phishing semantic keyword correlation rules<br>" : ""}
            ${dom.obfuscationFlag ? "- Deduct 15: Evaluation block runtime statements inside script<br>" : ""}
            ${dom.excessiveSubdomains ? "- Deduct 15: Subdomain path length depth overflow<br>" : ""}
            ${dom.hiddenIframe ? "- Deduct 10: Structural tracking window layers container nodes<br>" : ""}
            ${trackerRadarMatch ? "- Deduct 10: Tracker radar distribution listing hit<br>" : ""}
            ${dom.scriptCount > 35 ? "- Deduct 5: Script allocation limits crossed<br>" : ""}
            ${cookies.length - secureCookiesCount > 5 ? "- Deduct 5: Lax configuration properties inside cookie jar storage structures<br>" : ""}
            <div style="margin-top: 6px; padding-top: 6px; border-top: 1px dashed #dee2e6; font-weight: 700; font-size: 12px; color: #212529;">
              Remaining Core Balance: ${report.score} / 100 (${report.verdict})
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
        <span class="risk-tag tag-neutral">EVALUATING</span>
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
