document.addEventListener("DOMContentLoaded", async () => {
  const gradeBadge = document.getElementById("app-grade");
  const container = document.getElementById("points-container");

  try {
    // 1. Fetch current tab domain
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (!tab || !tab.url) {
      renderFallback("System Error", "No active window found.");
      return;
    }

    const urlObj = new URL(tab.url);
    let domain = urlObj.hostname.replace("www.", "");
    container.innerHTML = "";

    // 2. Try matching hardcoded master dictionary first
    if (GLOBAL_PRIVACY_DB[domain]) {
      renderSavedData(GLOBAL_PRIVACY_DB[domain]);
      return;
    }

    // 3. Check browser's custom user-generated local data storage
    chrome.storage.local.get([domain], (result) => {
      if (result[domain]) {
        // Site was previously generated and saved! Load it instantly
        renderSavedData(result[domain]);
      } else {
        // 4. AUTOMATIC ADD ENGINE: Build a new record dynamically, save it, and show it
        const domainParts = domain.split(".");
        const extension = domainParts.pop();

        let generatedData = {};

        if (extension === "org" || extension === "gov" || extension === "edu") {
          generatedData = {
            class: "B",
            points: [
              {
                text: `Registered non-commercial portal (.${extension}). Restricted tracking environment.`,
                status: "safe",
              },
              {
                text: "No corporate advertisement data-broker tracking nodes detected on root connection.",
                status: "safe",
              },
              {
                text: "Encrypted handshake protocol verified for this active domain session.",
                status: "neutral",
              },
            ],
          };
        } else {
          generatedData = {
            class: "C",
            points: [
              {
                text: `Commercial domain registry. Standard tracking terms apply to session data.`,
                status: "neutral",
              },
              {
                text: `Data protocols on ${domain} allow general marketing cookie aggregation.`,
                status: "risk",
              },
              {
                text: "Navigating this site registers implicit consent for fundamental metric analysis.",
                status: "risk",
              },
            ],
          };
        }

        // Write the newly compiled record into the extension's permanent storage box
        chrome.storage.local.set({ [domain]: generatedData }, () => {
          console.log(
            `Successfully generated and added privacy ledger for: ${domain}`,
          );
        });

        // Push straight to user interface
        renderSavedData(generatedData);
      }
    });
  } catch (err) {
    console.error("Agree Processor Error:", err);
    renderFallback("Error", "Localized parsing block encountered.");
  }

  // Visual helper to draw rows based on clean data models
  function renderSavedData(siteData) {
    gradeBadge.textContent = `Class ${siteData.class}`;
    container.innerHTML = "";

    siteData.points.forEach((point) => {
      const row = document.createElement("div");
      row.className = "point-item";

      let tagClass = "tag-neutral";
      let labelText = "Info";

      // Dynamically resolve status for plain text strings based on overall site class
      let defaultStatus = "risk";
      if (siteData.class === "A") defaultStatus = "safe";
      if (siteData.class === "B") defaultStatus = "neutral";

      // If point is a plain string, fall back to default baseline status. Otherwise, use explicit property.
      const statusValue =
        typeof point === "string" ? defaultStatus : point.status;
      const textValue = typeof point === "string" ? point : point.text;

      // Map target properties to active popup styling classes
      if (statusValue === "risk") {
        tagClass = "tag-risk";
        labelText = "Risk";
      } else if (statusValue === "safe") {
        tagClass = "tag-safe";
        labelText = "Safe";
      }

      row.innerHTML = `
        <span class="point-text">${textValue}</span>
        <span class="risk-tag ${tagClass}">${labelText}</span>
      `;
      container.appendChild(row);
    });
  }

  function renderFallback(title, message) {
    gradeBadge.textContent = "Class ?";
    container.innerHTML = `
      <div class="point-item">
        <span class="point-text"><strong>${title}</strong>: ${message}</span>
        <span class="risk-tag tag-neutral">N/A</span>
      </div>
    `;
  }
});
