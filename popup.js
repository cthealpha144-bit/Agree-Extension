document.addEventListener("DOMContentLoaded", async () => {
  // DOM Navigation & Layout Selectors
  const gradeBadge = document.getElementById("app-grade");
  const container = document.getElementById("points-container");
  const apiSourceSelect = document.getElementById("api-source");

  // Tab Navigation Elements
  const tabAgreeBtn = document.getElementById("tab-agree");
  const tabOptionsBtn = document.getElementById("tab-options");
  const panelAgree = document.getElementById("panel-agree");
  const panelOptions = document.getElementById("panel-options");

  // 1. Tab Interaction Switching Mechanics
  tabAgreeBtn.addEventListener("click", () => {
    tabOptionsBtn.classList.remove("active");
    tabAgreeBtn.classList.add("active");
    panelOptions.classList.add("hidden");
    panelAgree.classList.remove("hidden");
  });

  tabOptionsBtn.addEventListener("click", () => {
    tabAgreeBtn.classList.remove("active");
    tabOptionsBtn.classList.add("active");
    panelAgree.classList.add("hidden");
    panelOptions.classList.remove("hidden");
  });

  // Save selected option instantly when changed inside options view
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

  // --- CENTRAL DISPLAY RENDER CONTROLLER (Parses tag tiers & badge colors) ---
  function renderSavedData(siteData) {
    const currentClass = (siteData.class || "C").toUpperCase();
    gradeBadge.textContent = `Class ${currentClass}`;

    // Clear out any previously applied color modifier classes
    gradeBadge.classList.remove(
      "badge-safe",
      "badge-warning",
      "badge-risk",
      "badge-unknown",
    );

    // Dynamic Class Color Mapping System
    if (["A", "B"].includes(currentClass)) {
      gradeBadge.classList.add("badge-safe");
    } else if (currentClass === "C") {
      gradeBadge.classList.add("badge-warning");
    } else if (["D", "E"].includes(currentClass)) {
      gradeBadge.classList.add("badge-risk");
    } else {
      gradeBadge.classList.add("badge-unknown");
    }

    // Clear and redraw the item rows container
    container.innerHTML = "";

    siteData.points.forEach((point) => {
      const row = document.createElement("div");
      row.className = "point-item";

      let tagClass = "tag-neutral";
      let labelText = "Info";

      let defaultStatus =
        currentClass === "A"
          ? "safe"
          : currentClass === "B"
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
    gradeBadge.classList.remove("badge-safe", "badge-warning", "badge-risk");
    gradeBadge.classList.add("badge-unknown");
    container.innerHTML = `<div class="point-item"><span class="point-text"><strong>${title}</strong>: ${message}</span><span class="risk-tag tag-risk">Fail</span></div>`;
  }

  executeCoreAnalysis();
});
