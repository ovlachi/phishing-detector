/**
 * Complete implementation for batch results and details
 * This includes the showBatchDetails function and supporting functions
 */

// Global variable to store batch results data
window.batchResultsData = window.batchResultsData || [];

/**
 * Shows details for a specific URL from batch scan results
 *
 * @param {number} index - Index of the URL in the results array
 */
function showBatchDetails(index) {
  console.log("Showing batch details for index:", index);

  // Prevent default action and stop propagation
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }

  // Get references to the batch dashboard and results container
  const batchDashboard = document.getElementById("batch-dashboard");
  const batchResults = document.getElementById("batch-results");

  // Make sure we found the elements
  if (!batchDashboard || !batchResults) {
    console.error("Could not find batch dashboard or results container");
    return;
  }

  // Get the batch results data
  const resultsData = window.batchResults || window.batchResultsData || [];

  // Check if we have data for this index
  if (!resultsData[index]) {
    console.error("No data found for index:", index);
    alert("Details not available for this URL");
    return;
  }

  // Get the specific result data
  const urlData = resultsData[index];

  // Create or get the details container
  let detailsContainer = document.getElementById("batch-details-container");

  if (!detailsContainer) {
    // Create the container if it doesn't exist
    detailsContainer = document.createElement("div");
    detailsContainer.id = "batch-details-container";
    detailsContainer.className = "batch-details-container";

    // Add a back button at the top
    const backButton = document.createElement("button");
    backButton.className = "back-to-results-btn";
    backButton.textContent = "← Back to Results";
    backButton.addEventListener("click", function (e) {
      e.preventDefault();
      // Hide the details container and show the results list again
      detailsContainer.style.display = "none";
      batchResults.style.display = "block";
    });

    detailsContainer.appendChild(backButton);

    // Add the container to the batch dashboard, after the results container
    batchDashboard.insertBefore(detailsContainer, batchResults.nextSibling);
  }

  // Clear previous content (except the back button)
  while (detailsContainer.childNodes.length > 1) {
    detailsContainer.removeChild(detailsContainer.lastChild);
  }

  // Create the details card
  const detailsCard = document.createElement("div");
  detailsCard.className = "url-details-card";

  // Add URL header
  const urlHeader = document.createElement("h3");
  urlHeader.className = "url-details-header";
  urlHeader.textContent = urlData.url || "URL Details";
  detailsCard.appendChild(urlHeader);

  // Add risk label
  const riskLabel = document.createElement("div");
  riskLabel.className = "risk-label " + (urlData.risk || "unknown").toLowerCase();
  riskLabel.textContent = urlData.risk || "Unknown";
  detailsCard.appendChild(riskLabel);

  // Add confidence meter - FIXED VERSION
  const confidenceSection = document.createElement("div");
  confidenceSection.className = "confidence-section";

  // Calculate confidence from real API data
  let confidence = 0;

  if (urlData.final_confidence) {
    confidence = Math.round(urlData.final_confidence * 100);
  } else if (urlData.probabilities) {
    // Get the highest probability as confidence
    const probValues = Object.values(urlData.probabilities);
    confidence = Math.round(Math.max(...probValues) * 100);
  } else if (urlData.error) {
    confidence = 0; // No confidence for failed analyses
  } else {
    confidence = 50; // Default confidence for unknown cases
  }

  console.log("Calculated confidence:", confidence, "from data:", urlData);

  const confidenceLabel = document.createElement("div");
  confidenceLabel.className = "confidence-label";
  confidenceLabel.innerHTML = "<span>Confidence Level</span><span>" + confidence + "%</span>";
  confidenceSection.appendChild(confidenceLabel);

  const confidenceMeter = document.createElement("div");
  confidenceMeter.className = "confidence-meter";

  const confidenceFill = document.createElement("div");
  confidenceFill.className = "confidence-fill";
  confidenceFill.style.width = confidence + "%";

  // Set color based on confidence level
  if (confidence >= 80) {
    confidenceFill.style.backgroundColor = "#22c55e"; // Green
  } else if (confidence >= 60) {
    confidenceFill.style.backgroundColor = "#3b82f6"; // Blue
  } else if (confidence >= 40) {
    confidenceFill.style.backgroundColor = "#f59e0b"; // Orange
  } else {
    confidenceFill.style.backgroundColor = "#ef4444"; // Red
  }

  confidenceMeter.appendChild(confidenceFill);
  confidenceSection.appendChild(confidenceMeter);
  detailsCard.appendChild(confidenceSection);

  // Add quick stats
  const quickStats = document.createElement("div");
  quickStats.className = "quick-stats";

  // Add stats if available in your data structure
  // With this updated version:
  const statItems = [
    {
      label: "ML Prediction",
      value: urlData.error ? "Failed to analyze" : urlData.class_name || "Unknown"
    },
    {
      label: "Threat Intel",
      value: urlData.threat_level ? `${urlData.threat_level} risk` : "--"
    },
    {
      label: "URL Analysis",
      value: urlData.url_features ? "Analyzed" : "--"
    },
    {
      label: "Domain Age",
      value: urlData.url_features?.domain_age_days ? (urlData.url_features.domain_age_days < 30 ? `${urlData.url_features.domain_age_days} days` : "Established") : "--"
    }
  ];

  statItems.forEach((stat) => {
    const statItem = document.createElement("div");
    statItem.className = "stat-item";

    const statLabel = document.createElement("div");
    statLabel.className = "stat-label";
    statLabel.textContent = stat.label;

    const statValue = document.createElement("div");
    statValue.className = "stat-value";
    statValue.textContent = stat.value;

    statItem.appendChild(statLabel);
    statItem.appendChild(statValue);
    quickStats.appendChild(statItem);
  });

  detailsCard.appendChild(quickStats);

  // Add threat sources section if data available
  if (urlData.threatSources && urlData.threatSources.length) {
    const threatSection = document.createElement("div");
    threatSection.className = "detail-section";

    const threatHeader = document.createElement("h3");
    threatHeader.className = "detail-header";
    threatHeader.textContent = "Threat Intelligence Sources";
    threatSection.appendChild(threatHeader);

    const threatSources = document.createElement("div");
    threatSources.className = "threat-sources";

    urlData.threatSources.forEach((source) => {
      const sourceItem = document.createElement("div");
      sourceItem.className = "threat-source";

      const sourceName = document.createElement("div");
      sourceName.className = "source-name";
      sourceName.textContent = source.name || "";

      const sourceStatus = document.createElement("div");
      sourceStatus.className = "source-status " + (source.status || "").toLowerCase();
      sourceStatus.textContent = source.statusText || "";

      sourceItem.appendChild(sourceName);
      sourceItem.appendChild(sourceStatus);
      threatSources.appendChild(sourceItem);
    });

    threatSection.appendChild(threatSources);
    detailsCard.appendChild(threatSection);
  }

  // Add URL features section if data available
  if (urlData.features && urlData.features.length) {
    const featuresSection = document.createElement("div");
    featuresSection.className = "detail-section";

    const featuresHeader = document.createElement("h3");
    featuresHeader.className = "detail-header";
    featuresHeader.textContent = "URL Features";
    featuresSection.appendChild(featuresHeader);

    const featureList = document.createElement("div");
    featureList.className = "feature-list";

    urlData.features.forEach((feature) => {
      const featureItem = document.createElement("div");
      featureItem.className = "feature-item";

      const featureName = document.createElement("div");
      featureName.className = "feature-name";
      featureName.textContent = feature.name || "";

      const featureValue = document.createElement("div");
      featureValue.className = "feature-value " + (feature.status || "").toLowerCase();
      featureValue.textContent = feature.value || "";

      featureItem.appendChild(featureName);
      featureItem.appendChild(featureValue);
      featureList.appendChild(featureItem);
    });

    featuresSection.appendChild(featureList);
    detailsCard.appendChild(featuresSection);
  }

  // Add recommendation section
  const recommendationSection = document.createElement("div");
  recommendationSection.className = "recommendation-section";

  const recommendationHeader = document.createElement("div");
  recommendationHeader.className = "recommendation-header";
  recommendationHeader.textContent = "Recommendation";

  const recommendationText = document.createElement("div");
  recommendationText.className = "recommendation-text";
  recommendationText.textContent = urlData.error ? "UNKNOWN: Could not fully analyze this URL. Proceed with caution." : urlData.threat_level === "low" ? "This URL appears to be safe based on available analysis." : "Exercise caution with this URL.";

  recommendationSection.appendChild(recommendationHeader);
  recommendationSection.appendChild(recommendationText);
  detailsCard.appendChild(recommendationSection);

  // Add details card to the container
  detailsContainer.appendChild(detailsCard);

  // Hide the results list and show the details
  batchResults.style.display = "none";
  detailsContainer.style.display = "block";

  console.log("Batch details displayed successfully");

  return false; // Prevent default action for onclick handlers
}

/**
 * Initialize batch processing event handlers
 * Call this function to set up the batch scan functionality
 */
function initializeBatchScanHandlers() {
  console.log("Initializing batch scan handlers");

  document.addEventListener("DOMContentLoaded", function () {
    // // Set up the batch scan form
    // const batchScanForm = document.getElementById("batch-scan-form");
    // if (batchScanForm) {
    //   batchScanForm.addEventListener("submit", function (e) {
    //     e.preventDefault();
    //     const batchUrlInput = document.getElementById("batch-url-input");
    //     if (batchUrlInput && batchUrlInput.value) {
    //       processBatchScan(batchUrlInput.value);
    //     }
    //   });
    // }

    // Set up the CSV upload form
    const csvUploadForm = document.getElementById("csv-upload-form");
    if (csvUploadForm) {
      csvUploadForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const csvFileInput = document.getElementById("csv-file-input");
        if (csvFileInput && csvFileInput.files && csvFileInput.files[0]) {
          processCsvUpload(csvFileInput.files[0]);
        }
      });
    }

    // Set up filter and sort handlers
    const riskFilter = document.getElementById("risk-filter");
    if (riskFilter) {
      riskFilter.addEventListener("change", filterBatchResults);
    }

    const sortBy = document.getElementById("sort-by");
    if (sortBy) {
      sortBy.addEventListener("change", sortBatchResults);
    }
  });
}

/**
 * Process batch scan from text input
 *
 * @param {string} urlsText - Text containing URLs (one per line)
 */
// function processBatchScan(urlsText) {
//   console.log("Processing batch scan");

//   // Split text into URLs
//   const urls = urlsText
//     .split("\n")
//     .map((url) => url.trim())
//     .filter((url) => url && url.length > 0);

//   if (urls.length === 0) {
//     alert("Please enter at least one URL to scan");
//     return;
//   }

//   // Show loading indicator
//   // TODO: Add a loading spinner or progress indicator

//   // Simulate API call
//   setTimeout(function () {
//     // Generate sample results (replace with actual API call)
//     const results = urls.map((url) => ({
//       url: url,
//       risk: ["High", "Medium", "Low"][Math.floor(Math.random() * 3)],
//       confidence: Math.floor(Math.random() * 40) + 60, // 60-99
//       mlPrediction: Math.random() > 0.3 ? "Legitimate" : "Suspicious",
//       threatIntel: Math.random() > 0.3 ? "No threats" : "Some signals",
//       urlAnalysis: Math.random() > 0.3 ? "Normal" : "Unusual patterns",
//       domainAge: ["2 days", "6 months", "1+ year", "5+ years"][Math.floor(Math.random() * 4)],
//       threatSources: [
//         {
//           name: "VirusTotal",
//           status: Math.random() > 0.3 ? "safe" : "suspicious",
//           statusText: Math.random() > 0.3 ? "Clean" : "Suspicious"
//         },
//         {
//           name: "Google Safe Browsing",
//           status: Math.random() > 0.4 ? "safe" : "malicious",
//           statusText: Math.random() > 0.4 ? "No threats" : "Malicious"
//         }
//       ],
//       features: [
//         {
//           name: "Domain Age",
//           status: Math.random() > 0.3 ? "safe" : "suspicious",
//           value: Math.random() > 0.3 ? "5+ years" : "2 months"
//         },
//         {
//           name: "SSL Certificate",
//           status: Math.random() > 0.3 ? "safe" : "suspicious",
//           value: Math.random() > 0.3 ? "Valid (EV)" : "Self-signed"
//         }
//       ],
//       recommendation: Math.random() > 0.3 ? "This URL appears to be safe. You can proceed with confidence." : "Exercise caution with this URL. Several suspicious patterns were detected."
//     }));

//     // Update the UI with results
//     initializeBatchResults(results);
//   }, 2000);
// }

/**
 * Process CSV upload
 *
 * @param {File} file - The uploaded CSV file
 */
function processCsvUpload(file) {
  console.log("Processing CSV upload:", file.name);

  // Read the file
  const reader = new FileReader();
  reader.onload = function (e) {
    const text = e.target.result;
    const urls = text
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && line.length > 0);

    if (urls.length === 0) {
      alert("No URLs found in the CSV file");
      return;
    }

    // Process the URLs (reuse the batch scan function)
    processBatchScan(urls.join("\n"));
  };

  reader.onerror = function () {
    alert("Error reading the CSV file");
  };

  reader.readAsText(file);
}

/**
 * Filter batch results by risk level
 */
function filterBatchResults() {
  const filterValue = document.getElementById("risk-filter").value;
  console.log("Filtering batch results by:", filterValue);

  // Get all result items
  const resultItems = document.querySelectorAll(".batch-result-item");

  // Show or hide based on filter
  resultItems.forEach((item) => {
    // FIXED: Look for the right class and text content
    const statusElement = item.querySelector(".url-status");
    if (!statusElement) return;

    const risk = statusElement.textContent.toLowerCase().trim();
    console.log(`Item risk: "${risk}", Filter: "${filterValue}"`);

    let showItem = false;

    if (filterValue === "all") {
      showItem = true;
    } else if (filterValue === "high" && risk.includes("high")) {
      showItem = true;
    } else if (filterValue === "medium" && risk.includes("medium")) {
      showItem = true;
    } else if (filterValue === "safe" && (risk.includes("safe") || risk.includes("low"))) {
      showItem = true;
    } else if (filterValue === "suspicious" && risk.includes("suspicious")) {
      showItem = true;
    }

    item.style.display = showItem ? "flex" : "none";
  });
}

/**
 * Sort batch results
 */
function sortBatchResults() {
  const sortBy = document.getElementById("sort-by").value;
  console.log("Sorting batch results by:", sortBy);

  // Get the container and all items
  const container = document.getElementById("batch-results");
  const items = Array.from(container.querySelectorAll(".batch-result-item"));

  // Sort the items
  items.sort((a, b) => {
    if (sortBy === "risk") {
      // Sort by risk (high -> medium -> low)
      const riskA = a.querySelector(".url-status").textContent.toLowerCase();
      const riskB = b.querySelector(".url-status").textContent.toLowerCase();

      const riskOrder = { high: 0, medium: 1, low: 2 };
      return riskOrder[riskA] - riskOrder[riskB];
    } else if (sortBy === "confidence") {
      // Sort by confidence (highest first)
      const confA = parseInt(a.querySelector(".confidence-indicator").textContent);
      const confB = parseInt(b.querySelector(".confidence-indicator").textContent);
      return confB - confA;
    } else if (sortBy === "url") {
      // Sort alphabetically by URL
      const urlA = a.querySelector(".url-text").textContent.toLowerCase();
      const urlB = b.querySelector(".url-text").textContent.toLowerCase();
      return urlA.localeCompare(urlB);
    }

    return 0;
  });

  // Reorder the DOM
  items.forEach((item) => container.appendChild(item));
}

/**
 * Initialize the batch scan results
 *
 * @param {Array} resultsData - Array of result objects
 */
function initializeBatchResults(resultsData) {
  console.log("Initializing batch results with REAL API data:", resultsData);

  // Store the results data for later use
  window.batchResultsData = resultsData || [];
  window.batchResults = resultsData || []; // Ensure both variables are set

  // Get the batch results container
  const batchResults = document.getElementById("batch-results");
  if (!batchResults) {
    console.error("Batch results container not found");
    return;
  }

  // Clear previous results
  batchResults.innerHTML = "";

  // Generate result items using REAL API data structure
  window.batchResultsData.forEach((result, index) => {
    const resultItem = document.createElement("div");
    resultItem.className = "batch-result-item";

    // Map real API data to display format
    // Fixed code:
    let displayRisk = "Unknown";
    let riskClass = "unknown";

    if (result.error) {
      displayRisk = "Suspicious";
      riskClass = "suspicious";
    } else if (result.class_name) {
      switch (result.class_name.toLowerCase()) {
        case "legitimate":
          displayRisk = "Safe";
          riskClass = "safe";
          break;
        case "credential phishing":
          displayRisk = "High Risk";
          riskClass = "high";
          break;
        case "malware distribution":
          displayRisk = "High Risk";
          riskClass = "high";
          break;
        default:
          displayRisk = "Suspicious";
          riskClass = "suspicious";
      }
    } else {
      // No error but no classification = suspicious
      displayRisk = "Suspicious";
      riskClass = "suspicious";
    }

    // Calculate confidence from real API data
    let confidence = 0;
    if (result.final_confidence) {
      confidence = Math.round(result.final_confidence * 100);
    } else if (result.probabilities) {
      confidence = Math.round(Math.max(...Object.values(result.probabilities)) * 100);
    }

    // Create the UI elements
    const riskIndicator = document.createElement("div");
    riskIndicator.className = `risk-indicator ${riskClass}`;
    resultItem.appendChild(riskIndicator);

    const urlInfo = document.createElement("div");
    urlInfo.className = "url-info";

    const urlText = document.createElement("div");
    urlText.className = "url-text";
    urlText.textContent = result.url || "Unknown URL";

    const urlStatus = document.createElement("div");
    urlStatus.className = `url-status ${riskClass}`;
    urlStatus.textContent = displayRisk;

    urlInfo.appendChild(urlText);
    urlInfo.appendChild(urlStatus);
    resultItem.appendChild(urlInfo);

    // Add confidence using real data
    const confidenceIndicator = document.createElement("div");
    confidenceIndicator.className = "confidence-indicator";
    confidenceIndicator.textContent = confidence + "%";
    resultItem.appendChild(confidenceIndicator);

    // Add actions
    const actions = document.createElement("div");
    actions.className = "batch-actions-cell";

    const detailsButton = document.createElement("button");
    detailsButton.className = "batch-action";
    detailsButton.textContent = "Details";
    detailsButton.dataset.index = index;

    detailsButton.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      showBatchDetails(parseInt(this.dataset.index));
    });

    actions.appendChild(detailsButton);
    resultItem.appendChild(actions);
    batchResults.appendChild(resultItem);
  });

  // Update summary with real data
  updateBatchSummary(window.batchResultsData);

  // Show the dashboard
  const batchDashboard = document.getElementById("batch-dashboard");
  if (batchDashboard) {
    batchDashboard.classList.remove("hidden");
  }
}

/**
 * Update the batch summary statistics
 */

function updateBatchSummary(resultsData) {
  console.log("=== phishr_batch_scan.js updateBatchSummary called ===");
  console.log("ResultsData:", resultsData);
  console.log("Updating batch summary stats with data:", resultsData);

  // Count risk levels
  const stats = {
    total: resultsData.length,
    high: 0,
    medium: 0,
    safe: 0,
    suspicious: 0 // Add suspicious category
  };

  // Count URLs by risk level - FIXED VERSION
  resultsData.forEach((result) => {
    console.log("Processing result for summary:", result);

    // Check if this is a failed analysis or unknown result
    if (result.error || !result.class_name || result.class_name === null) {
      stats.suspicious++; // Count as suspicious
      console.log("  -> Counted as SUSPICIOUS");
      return;
    }

    if (result.class_name) {
      switch (result.class_name.toLowerCase()) {
        case "legitimate":
          stats.safe++;
          console.log("  -> Counted as SAFE");
          break;
        case "credential phishing":
        case "malware distribution":
          stats.high++;
          console.log("  -> Counted as HIGH");
          break;
        default:
          stats.suspicious++;
          console.log("  -> Counted as SUSPICIOUS (unknown class)");
          break;
      }
    } else {
      stats.suspicious++;
      console.log("  -> Counted as SUSPICIOUS (no class)");
    }
  });

  console.log("Final stats:", stats);

  // Update summary stats in the UI
  const totalUrls = document.getElementById("total-urls");
  if (totalUrls) {
    console.log("Setting total-urls to:", stats.total);
    totalUrls.textContent = stats.total;
  } else {
    console.error("Element 'total-urls' not found");
  }

  const highRisk = document.getElementById("high-risk");
  if (highRisk) {
    console.log("Setting high-risk to:", stats.high);
    highRisk.textContent = stats.high;
  } else {
    console.error("Element 'high-risk' not found");
  }

  const mediumRisk = document.getElementById("medium-risk");
  if (mediumRisk) {
    console.log("Setting medium-risk to:", stats.medium);
    mediumRisk.textContent = stats.medium;
  } else {
    console.error("Element 'medium-risk' not found");
  }

  const safeUrls = document.getElementById("safe-urls");
  if (safeUrls) {
    console.log("Setting safe-urls to:", stats.safe);
    safeUrls.textContent = stats.safe;
  } else {
    console.error("Element 'safe-urls' not found");
  }
}

/**
 * Simple fix to add at the end of your phishr_batch_scan.js file
 */

// Add this code at the very end of your file
(function () {
  console.log("Adding batch summary fix");

  // Store reference to the original function
  const originalUpdateBatchSummary = updateBatchSummary;

  // Override the function with our enhanced version
  updateBatchSummary = function (resultsData) {
    // Call the original function first
    originalUpdateBatchSummary(resultsData);

    // Then add our fix that runs after a delay
    setTimeout(function () {
      console.log("Running batch summary fix");

      // Get all the batch result items
      const batchResults = document.getElementById("batch-results");
      if (!batchResults) return;

      // Count the items by their UI indicators
      const items = batchResults.querySelectorAll(".batch-result-item");
      let highCount = 0;
      let mediumCount = 0;

      items.forEach((item) => {
        // Look for HIGH badge
        if (item.textContent.includes("HIGH")) {
          highCount++;
        }
        // Look for MEDIUM badge
        else if (item.textContent.includes("MEDIUM")) {
          mediumCount++;
        }
      });

      // Get total count
      const totalCount = items.length;

      // Calculate safe count
      const safeCount = totalCount - highCount - mediumCount;

      console.log(`Found in UI: HIGH=${highCount}, MEDIUM=${mediumCount}, Total=${totalCount}`);

      // Only update if the counts are different from what's displayed
      const currentHighCount = parseInt(document.getElementById("high-risk").textContent);
      const currentMediumCount = parseInt(document.getElementById("medium-risk").textContent);

      if (highCount !== currentHighCount || mediumCount !== currentMediumCount) {
        console.log("Updating summary counts");
        document.getElementById("high-risk").textContent = highCount.toString();
        document.getElementById("medium-risk").textContent = mediumCount.toString();
        document.getElementById("safe-urls").textContent = safeCount.toString();
      }
    }, 500);
  };

  console.log("Batch summary fix added");
})();

// Initialize everything
initializeBatchScanHandlers();
