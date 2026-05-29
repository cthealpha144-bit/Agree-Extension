// A pre-compiled local data registry mapping global web platforms to their ToS;DR classifications
const GLOBAL_PRIVACY_DB = {
  // Major Tech & Search
  "google.com": {
    class: "C",
    points: [
      {
        text: "Tracks browsing history across unrelated websites.",
        status: "risk",
      },
      {
        text: "Uses personal data for automated AI profiling.",
        status: "risk",
      },
      { text: "Maintains clear ad opt-out parameters.", status: "safe" },
    ],
  },
  "youtube.com": {
    class: "C",
    points: [
      { text: "Tracks comprehensive video viewing logs.", status: "risk" },
      {
        text: "Can remove content without prior notification.",
        status: "medium",
      },
      {
        text: "Allows users to clear search and watch history.",
        status: "safe",
      },
    ],
  },
  "apple.com": {
    class: "B",
    points: [
      { text: "Maintains strict on-device data isolation.", status: "safe" },
      {
        text: "Tracks hardware serial codes for diagnostic telemetry.",
        status: "medium",
      },
      { text: "Clear data deletion pipelines available.", status: "safe" },
    ],
  },
  "microsoft.com": {
    class: "D",
    points: [
      {
        text: "Aggregates multi-device keystroke and telemetry streams.",
        status: "risk",
      },
      {
        text: "Shares anonymized target profiles with brokers.",
        status: "risk",
      },
      { text: "Opt-outs are deeply nested in system menus.", status: "medium" },
    ],
  },

  // Reference & Developer Tools
  "wikipedia.org": {
    class: "A",
    points: [
      {
        text: "Zero third-party tracking cookie mechanisms active.",
        status: "safe",
      },
      {
        text: "Maintains no public tracking records of research habits.",
        status: "safe",
      },
      {
        text: "Fully open-source platform with transparent ledger logs.",
        status: "safe",
      },
    ],
  },
};
