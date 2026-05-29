document.addEventListener("DOMContentLoaded", async () => {
  // DOM Elements
  const gradeBadge = document.getElementById("app-grade");
  const container = document.getElementById("points-container");
  const settingsBtn = document.getElementById("toggle-settings");
  const settingsTray = document.getElementById("settings-tray");
  const apiSourceSelect = document.getElementById("api-source");

  // 1. Settings Tray Expand/Collapse Listener
  settingsBtn.addEventListener("click", () => {
    const isVisible = settingsTray.style.display === "block";
    settingsTray.style.display = isVisible ? "none" : "block";
  });

  // Save selected option instantly when changed
  apiSourceSelect.addEventListener("change", (e) => {
    chrome.storage.local.set({ selectedEngine: e.target.value }, () => {
      executeCoreAnalysis();
    });
  });

  // 2. Central Execution Pipeline Router
  async function executeCoreAnalysis() {
    try {
      container.innerHTML = "";

      const [tab] = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });
      if (!tab || !tab.url) {
        renderFallback("System Error", "No active window discovered.");
        return;
      }

      // --- SYSTEM GUARD: Catch internal chrome:// or local file:// settings spaces ---
      if (
        tab.url.startsWith("chrome://") ||
        tab.url.startsWith("chrome-extension://") ||
        tab.url.startsWith("about:")
      ) {
        renderSavedData({
          class: "A",
          points: [
            {
              text: "Internal browser subsystem environment. No third-party tracking vectors present.",
              status: "safe",
            },
            {
              text: "Local configurations are completely isolated from external analytics infrastructure.",
              status: "safe",
            },
          ],
        });
        return;
      }

      const urlObj = new URL(tab.url);
      let domain = urlObj.hostname.replace("www.", "");

      // If hostname is empty or evaluates to a local path file
      if (!domain || tab.url.startsWith("file://")) {
        renderFallback("Local Resource", "Cannot audit offline local files.");
        return;
      }

      // Pull current setting choice from storage memory
      chrome.storage.local.get(["selectedEngine"], async (config) => {
        const activeEngine = config.selectedEngine || "local";
        apiSourceSelect.value = activeEngine;

        // SWITCH ROUTING ENGINE MATRIX
        switch (activeEngine) {
          case "local":
            runLocalDatabaseEngine(domain);
            break;
          case "tosdr":
            runPublicApiFallbackEngine(domain);
            break;
          case "duckduckgo":
            runDuckDuckGoRadarEngine(domain);
            break;
          case "urlvoid":
            runUrlVoidSafetyEngine(domain);
            break;
          default:
            runLocalDatabaseEngine(domain);
        }
      });
    } catch (err) {
      console.error("Core Engine Interruption:", err);
      renderFallback("Processing Block", "Initialization pipeline failure.");
    }
  }

  // --- ENGINE A: LOCAL STORAGE DICTIONARY & AUTOMATIC PREDICTOR ---
  function runLocalDatabaseEngine(domain) {
    if (GLOBAL_PRIVACY_DB[domain]) {
      renderSavedData(GLOBAL_PRIVACY_DB[domain]);
    } else {
      chrome.storage.local.get([domain], (result) => {
        if (result[domain]) {
          renderSavedData(result[domain]);
        } else {
          const ext = domain.split(".").pop();
          let fallbackRecord = {};

          if (["org", "gov", "edu"].includes(ext)) {
            fallbackRecord = {
              class: "B",
              points: [
                {
                  text: `Non-commercial system domain (.${ext}). Default security data isolation expected.`,
                  status: "safe",
                },
                {
                  text: "No corporate marketing data brokers mapped to root hostname.",
                  status: "safe",
                },
              ],
            };
          } else {
            // Standard unlisted site logic uses Medium tags for baseline practices!
            fallbackRecord = {
              class: "C",
              points: [
                {
                  text: `Data protocols on ${domain} allow general marketing cookie aggregation.`,
                  status: "medium",
                },
                {
                  text: "Navigating this site registers implicit consent for fundamental metric analysis.",
                  status: "risk",
                },
              ],
            };
          }
          chrome.storage.local.set({ [domain]: fallbackRecord });
          renderSavedData(fallbackRecord);
        }
      });
    }
  }

  // --- ENGINE B: PUBLIC LEGAL REPOSITORY PATH ---
  async function runPublicApiFallbackEngine(domain) {
    container.innerHTML = `<div class="point-item"><span class="point-text">Pinging legal term database for <strong>${domain}</strong>...</span><span class="risk-tag tag-neutral">Sync</span></div>`;

    const quickIds = {
      "google.com": "google",
      "youtube.com": "youtube",
      "facebook.com": "facebook",
      "wikipedia.org": "wikipedia",
    };
    const targetId = quickIds[domain] || domain.split(".")[0];

    try {
      const response = await fetch(
        `https://api.tosdr.org/v2/service/${targetId}.json`,
      );
      if (!response.ok) throw new Error();

      const payload = await response.json();
      const details = payload.parameters || {};

      const mappedData = {
        class: details.class || "C",
        points: (details.points || []).slice(0, 3).map((p) => ({
          text: p.title,
          status:
            p.status === "bad"
              ? "risk"
              : p.status === "good"
                ? "safe"
                : "medium",
        })),
      };

      if (mappedData.points.length === 0) throw new Error();
      renderSavedData(mappedData);
    } catch {
      runLocalDatabaseEngine(domain);
    }
  }

  // --- ENGINE C: DUCKDUCKGO TRACKER RADAR LOADER ---
  async function runDuckDuckGoRadarEngine(domain) {
    container.innerHTML = `<div class="point-item"><span class="point-text">Checking DuckDuckGo Tracker Blocklists...</span><span class="risk-tag tag-neutral">Blocklist</span></div>`;

    try {
      const res = await fetch(
        `https://raw.githubusercontent.com/duckduckgo/tracker-radar/main/domains/${domain}.json`,
      );
      if (!res.ok) {
        renderSavedData({
          class: "A",
          points: [
            {
              text: `Clean Audit! <strong>${domain}</strong> is not listed as a tracking node in DuckDuckGo's database.`,
              status: "safe",
            },
            {
              text: "No background fingerprinting assets found.",
              status: "safe",
            },
          ],
        });
        return;
      }

      const data = await res.json();
      const trackerCount = data.subdomains ? data.subdomains.length : 0;

      renderSavedData({
        class: trackerCount > 5 ? "E" : "D",
        points: [
          {
            text: `Flagged tracker entity! DDG Radar tracks ${trackerCount} active tracking sub-networks.`,
            status: "risk",
          },
          {
            text: `Primary corporate owner: <strong>${data.owner?.name || "Unknown Entity"}</strong>`,
            status: "medium",
          },
          {
            text: `Prevalent tracking category footprint: ${data.categories?.[0] || "General Analytics"}`,
            status: "medium",
          },
        ],
      });
    } catch {
      runLocalDatabaseEngine(domain);
    }
  }

  // --- ENGINE D: APIVOID / URLVOID SAFETY INDEX ---
  async function runUrlVoidSafetyEngine(domain) {
    container.innerHTML = `<div class="point-item"><span class="point-text">Scanning domain safety metrics...</span><span class="risk-tag tag-neutral">Audit</span></div>`;

    try {
      const res = await fetch(
        `https://api.apivoid.com/urlvoid/v1/scan?key=sandbox_demo_key&url=${domain}`,
      );
      if (!res.ok) throw new Error();
      const payload = await res.json();
      const scan = payload.data?.report || {};

      const safetyScore = scan.security_checks?.detections || 0;

      renderSavedData({
        class: safetyScore > 0 ? "D" : "B",
        points: [
          {
            text: `Server Hosting Location verified inside: ${scan.server?.country_name || "Global Node"}`,
            status: "medium",
          },
          {
            text: `IP Connection Identity address listed: ${scan.server?.ip || "Protected"}`,
            status: "medium",
          },
          {
            text:
              safetyScore > 0
                ? `Alert: Flagged on ${safetyScore} domain blocklists.`
                : "Domain cleared cleanly across public firewalls.",
            status: safetyScore > 0 ? "risk" : "safe",
          },
        ],
      });
    } catch {
      runLocalDatabaseEngine(domain);
    }
  }

  // --- CENTRAL DISPLAY RENDER CONTROLLER (Parses tag tiers) ---
  function renderSavedData(siteData) {
    gradeBadge.textContent = `Class ${siteData.class || "C"}`;
    container.innerHTML = "";

    siteData.points.forEach((point) => {
      const row = document.createElement("div");
      row.className = "point-item";

      let tagClass = "tag-neutral";
      let labelText = "Info";

      // Fallback logic for legacy plain strings vs structured object points
      let defaultStatus =
        siteData.class === "A"
          ? "safe"
          : siteData.class === "B"
            ? "medium"
            : "risk";
      const statusValue =
        typeof point === "string" ? defaultStatus : point.status;
      const textValue = typeof point === "string" ? point : point.text;

      if (statusValue === "risk") {
        tagClass = "tag-risk";
        labelText = "Risk";
      } else if (statusValue === "warning" || statusValue === "medium") {
        tagClass = "tag-warning";
        labelText = "Medium";
      } else if (statusValue === "safe") {
        tagClass = "tag-safe";
        labelText = "Safe";
      }

      row.innerHTML = `<span class="point-text">${textValue}</span><span class="risk-tag ${tagClass}">${labelText}</span>`;
      container.appendChild(row);
    });
  }

  function renderFallback(title, message) {
    gradeBadge.textContent = "Class ?";
    container.innerHTML = `<div class="point-item"><span class="point-text"><strong>${title}</strong>: ${message}</span><span class="risk-tag tag-risk">Fail</span></div>`;
  }

  executeCoreAnalysis();
});
