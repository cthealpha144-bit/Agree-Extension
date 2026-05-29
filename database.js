const GLOBAL_PRIVACY_DB = {
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
        status: "neutral",
      },
      {
        text: "Allows users to clear search and watch history.",
        status: "safe",
      },
    ],
  },
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
  // ... you can update the rest of your database entries with this same pattern!
};
