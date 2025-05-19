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
  const resultsData = window.batchResultsData || [];

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

  // Add confidence meter
  const confidenceSection = document.createElement("div");
  confidenceSection.className = "confidence-section";

  const confidenceLabel = document.createElement("div");
  confidenceLabel.className = "confidence-label";
  confidenceLabel.innerHTML = "<span>Confidence Level</span><span>" + (urlData.confidence || "0") + "%</span>";
  confidenceSection.appendChild(confidenceLabel);

  const confidenceMeter = document.createElement("div");
  confidenceMeter.className = "confidence-meter";

  const confidenceFill = document.createElement("div");
  confidenceFill.className = "confidence-fill";
  confidenceFill.style.width = (urlData.confidence || "0") + "%";
  confidenceMeter.appendChild(confidenceFill);

  confidenceSection.appendChild(confidenceMeter);
  detailsCard.appendChild(confidenceSection);

  // Add quick stats
  const quickStats = document.createElement("div");
  quickStats.className = "quick-stats";

  // Add stats if available in your data structure
  const statItems = [
    { label: "ML Prediction", value: urlData.mlPrediction || "--" },
    { label: "Threat Intel", value: urlData.threatIntel || "--" },
    { label: "URL Analysis", value: urlData.urlAnalysis || "--" },
    { label: "Domain Age", value: urlData.domainAge || "--" }
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
  recommendationText.textContent = urlData.recommendation || "No recommendation available.";

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
    // Set up the batch scan form
    const batchScanForm = document.getElementById("batch-scan-form");
    if (batchScanForm) {
      batchScanForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const batchUrlInput = document.getElementById("batch-url-input");
        if (batchUrlInput && batchUrlInput.value) {
          processBatchScan(batchUrlInput.value);
        }
      });
    }

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
function processBatchScan(urlsText) {
  console.log("Processing batch scan");

  // Split text into URLs
  const urls = urlsText
    .split("\n")
    .map((url) => url.trim())
    .filter((url) => url && url.length > 0);

  if (urls.length === 0) {
    alert("Please enter at least one URL to scan");
    return;
  }

  // Show loading indicator
  // TODO: Add a loading spinner or progress indicator

  // Simulate API call
  setTimeout(function () {
    // Generate sample results (replace with actual API call)
    const results = urls.map((url) => ({
      url: url,
      risk: ["High", "Medium", "Low"][Math.floor(Math.random() * 3)],
      confidence: Math.floor(Math.random() * 40) + 60, // 60-99
      mlPrediction: Math.random() > 0.3 ? "Legitimate" : "Suspicious",
      threatIntel: Math.random() > 0.3 ? "No threats" : "Some signals",
      urlAnalysis: Math.random() > 0.3 ? "Normal" : "Unusual patterns",
      domainAge: ["2 days", "6 months", "1+ year", "5+ years"][Math.floor(Math.random() * 4)],
      threatSources: [
        {
          name: "VirusTotal",
          status: Math.random() > 0.3 ? "safe" : "suspicious",
          statusText: Math.random() > 0.3 ? "Clean" : "Suspicious"
        },
        {
          name: "Google Safe Browsing",
          status: Math.random() > 0.4 ? "safe" : "malicious",
          statusText: Math.random() > 0.4 ? "No threats" : "Malicious"
        }
      ],
      features: [
        {
          name: "Domain Age",
          status: Math.random() > 0.3 ? "safe" : "suspicious",
          value: Math.random() > 0.3 ? "5+ years" : "2 months"
        },
        {
          name: "SSL Certificate",
          status: Math.random() > 0.3 ? "safe" : "suspicious",
          value: Math.random() > 0.3 ? "Valid (EV)" : "Self-signed"
        }
      ],
      recommendation: Math.random() > 0.3 ? "This URL appears to be safe. You can proceed with confidence." : "Exercise caution with this URL. Several suspicious patterns were detected."
    }));

    // Update the UI with results
    initializeBatchResults(results);
  }, 2000);
}

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
    const risk = item.querySelector(".url-status").textContent.toLowerCase();

    if (filterValue === "all" || (filterValue === "high" && risk === "high") || (filterValue === "medium" && risk === "medium") || (filterValue === "safe" && risk === "low")) {
      item.style.display = "flex";
    } else {
      item.style.display = "none";
    }
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
  console.log("Initializing batch results with data:", resultsData);

  // Store the results data for later use
  window.batchResultsData = resultsData || [];

  // Update summary stats FIRST
  updateBatchSummary(resultsData);

  // Get the batch results container
  const batchResults = document.getElementById("batch-results");
  if (!batchResults) {
    console.error("Batch results container not found");
    return;
  }

  // Clear previous results
  batchResults.innerHTML = "";

  // Update summary statistics
  updateBatchSummary(window.batchResultsData);

  // Generate result items
  window.batchResultsData.forEach((result, index) => {
    // Create result item
    const resultItem = document.createElement("div");
    resultItem.className = "batch-result-item";

    // Add risk indicator
    const riskIndicator = document.createElement("div");
    riskIndicator.className = "risk-indicator " + (result.risk || "").toLowerCase();
    resultItem.appendChild(riskIndicator);

    // Add URL info
    const urlInfo = document.createElement("div");
    urlInfo.className = "url-info";

    const urlText = document.createElement("div");
    urlText.className = "url-text";
    urlText.textContent = result.url || "Unknown URL";

    const urlStatus = document.createElement("div");
    urlStatus.className = "url-status " + (result.risk || "").toLowerCase();
    urlStatus.textContent = result.risk || "Unknown";

    urlInfo.appendChild(urlText);
    urlInfo.appendChild(urlStatus);
    resultItem.appendChild(urlInfo);

    // Add confidence
    const confidenceIndicator = document.createElement("div");
    confidenceIndicator.className = "confidence-indicator";
    confidenceIndicator.textContent = (result.confidence || "0") + "%";
    resultItem.appendChild(confidenceIndicator);

    // Add actions
    const actions = document.createElement("div");
    actions.className = "batch-actions-cell";

    const detailsButton = document.createElement("button");
    detailsButton.className = "batch-action";
    detailsButton.textContent = "Details";
    detailsButton.dataset.index = index; // Store the index in a data attribute

    // Use addEventListener instead of onclick
    detailsButton.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      showBatchDetails(parseInt(this.dataset.index));
    });

    actions.appendChild(detailsButton);
    resultItem.appendChild(actions);

    // Add to container
    batchResults.appendChild(resultItem);
  });

  // Show the dashboard
  const batchDashboard = document.getElementById("batch-dashboard");
  if (batchDashboard) {
    batchDashboard.classList.remove("hidden");
  }

  console.log("Batch results initialized successfully");
}

/**
 * Update the batch summary statistics
 */

function updateBatchSummary(resultsData) {
  console.log("Updating batch summary stats with data:", resultsData);

  // Count risk levels
  const stats = {
    total: resultsData.length,
    high: 0,
    medium: 0,
    safe: 0
  };

  // Count URLs by risk level
  resultsData.forEach((result) => {
    const risk = (result.risk || "").toLowerCase();

    // Check for various risk level terms
    if (risk.includes("high") || risk.includes("critical") || risk.includes("severe")) {
      stats.high++;
    } else if (risk.includes("medium") || risk.includes("moderate") || risk.includes("warning")) {
      stats.medium++;
    } else if (risk.includes("low") || risk.includes("safe") || risk.includes("minimal")) {
      stats.safe++;
    }
    // If none match, default to counting as "safe"
    else {
      stats.safe++;
    }
  });

  console.log("Calculated summary stats:", stats);

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
