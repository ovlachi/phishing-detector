/**
 * Enhanced UI JavaScript for PhishR
 * This file contains the client-side functionality for displaying enhanced URL analysis
 */

// Global variable to store batch results
window.batchResults = [];

/**
 * Display enhanced result with threat intelligence and URL features
 * @param {Object} result - Result from the API with enhanced fields
 */
function displayEnhancedResult(result) {
  console.log("displayEnhancedResult called with:", result);

  // Check if necessary elements exist
  if (!document.getElementById("result-card")) {
    console.error("Error: result-card element not found!");
    return;
  }

  // Hide any existing results or loading indicators
  document.getElementById("loading-spinner").style.display = "none";

  // Show the result card
  const resultCard = document.getElementById("result-card");
  if (resultCard) {
    resultCard.style.display = "block";
  }

  // Hide batch dashboard if it's visible
  const batchDashboard = document.getElementById("batch-dashboard");
  if (batchDashboard) {
    batchDashboard.style.display = "none";
  }

  // Update basic info
  if (document.getElementById("result-title")) {
    document.getElementById("result-title").textContent = result.class_name || result.error || "Unknown";
  }

  if (document.getElementById("result-url")) {
    document.getElementById("result-url").textContent = result.url;
    // Also set as href if it's a link
    const urlElement = document.getElementById("scanned-url");
    if (urlElement) {
      urlElement.href = result.url;
      urlElement.textContent = result.url;
    }
  }

  // Update threat icon and badge
  updateThreatVisuals(result);

  // Update confidence meter
  updateConfidenceMeter(result);

  // Update quick stats
  updateQuickStats(result);

  // Populate detailed analysis
  populateDetailedAnalysis(result);

  // Show details toggle
  const detailsToggle = document.getElementById("details-toggle");
  if (detailsToggle) {
    detailsToggle.style.display = "block";
  }
}

/**
 * Update threat level visuals based on classification
 * @param {Object} result - Result from API
 */
function updateThreatVisuals(result) {
  const icon = document.getElementById("result-icon");
  const badge = document.getElementById("threat-badge");

  if (!icon || !badge) return;

  const threatLevel = result.threat_level || "unknown";
  const confidenceBadge = document.getElementById("confidence-badge");

  // Reset badge classes
  badge.className = "threat-badge";

  switch (threatLevel) {
    case "high":
    case "critical":
      icon.textContent = "🛑";
      badge.textContent = "HIGH RISK";
      badge.classList.add("badge-high");
      break;
    case "medium":
      icon.textContent = "⚠️";
      badge.textContent = "MEDIUM RISK";
      badge.classList.add("badge-medium");
      break;
    case "low":
      icon.textContent = "✓";
      badge.textContent = "LOW RISK";
      badge.classList.add("badge-low");
      break;
    case "safe":
      icon.textContent = "✅";
      badge.textContent = "SAFE";
      badge.classList.add("badge-safe");
      break;
    default:
      if (result.error) {
        icon.textContent = "❓";
        badge.textContent = "ERROR";
        badge.classList.add("badge-analyzing");
      } else {
        icon.textContent = "🔍";
        badge.textContent = "ANALYZING";
        badge.classList.add("badge-analyzing");
      }
  }

  // Update confidence badge if it exists
  if (confidenceBadge) {
    const confidence = result.final_confidence || (result.probabilities ? Math.max(...Object.values(result.probabilities)) : 0);

    confidenceBadge.style.display = "inline-block";

    if (confidence >= 0.9) {
      confidenceBadge.textContent = "HIGH CONFIDENCE";
      confidenceBadge.className = "threat-badge badge-safe";
    } else if (confidence >= 0.7) {
      confidenceBadge.textContent = "GOOD CONFIDENCE";
      confidenceBadge.className = "threat-badge badge-medium";
    } else {
      confidenceBadge.textContent = "LOW CONFIDENCE";
      confidenceBadge.className = "threat-badge badge-high";
    }
  }
}

/**
 * Update confidence meter visualization
 * @param {Object} result - Result from API
 */
function updateConfidenceMeter(result) {
  const fill = document.getElementById("confidence-fill");
  const text = document.getElementById("confidence-text");

  if (!fill || !text) return;

  // Calculate confidence - use final_confidence if available, otherwise use max probability
  let confidence = 0;

  if (result.final_confidence !== null && result.final_confidence !== undefined) {
    confidence = result.final_confidence;
  } else if (result.probabilities) {
    confidence = Math.max(...Object.values(result.probabilities));
  } else if (result.url_confidence_score) {
    confidence = result.url_confidence_score;
  }

  // Update the visual fill
  fill.style.width = `${confidence * 100}%`;
  text.textContent = `${Math.round(confidence * 100)}%`;

  // Set color based on confidence
  if (confidence >= 0.8) {
    fill.style.background = "#22c55e"; // Green
  } else if (confidence >= 0.6) {
    fill.style.background = "#3b82f6"; // Blue
  } else {
    fill.style.background = "#ef4444"; // Red
  }
}

/**
 * Update quick stats section
 * @param {Object} result - Result from API
 */
function updateQuickStats(result) {
  // ML Prediction
  const mlPrediction = document.getElementById("ml-prediction");
  if (mlPrediction) {
    if (result.probabilities && result.class_name) {
      const maxProb = Math.max(...Object.values(result.probabilities));
      mlPrediction.textContent = `${Math.round(maxProb * 100)}% ${result.class_name}`;
    } else if (result.error) {
      mlPrediction.textContent = "Failed to analyze";
    } else {
      mlPrediction.textContent = "Unknown";
    }
  }

  // Threat Intelligence
  const threatIntel = document.getElementById("threat-intel");
  if (threatIntel) {
    if (result.url_features) {
      // For now, we'll use a placeholder since we don't have actual threat intel sources
      threatIntel.textContent = `URL Analysis: ${result.threat_level || "Unknown"}`;
    } else {
      threatIntel.textContent = "Not available";
    }
  }

  // URL Analysis
  const urlAnalysis = document.getElementById("url-analysis");
  if (urlAnalysis) {
    if (result.url_features) {
      let analysis = "Normal";

      if (result.url_features.has_common_typos > 0) {
        analysis = "Typo detected";
      } else if (result.url_features.has_security_keywords > 2) {
        analysis = "Suspicious keywords";
      } else if (result.url_features.has_ip_address) {
        analysis = "IP address";
      }

      urlAnalysis.textContent = analysis;
    } else {
      urlAnalysis.textContent = "Not analyzed";
    }
  }

  // Domain Age
  const domainAge = document.getElementById("domain-age");
  if (domainAge) {
    if (result.url_features && result.url_features.domain_age_days !== undefined) {
      const days = result.url_features.domain_age_days;
      if (days < 0) {
        domainAge.textContent = "Unknown";
      } else if (days < 30) {
        domainAge.textContent = `${days} days old`;
      } else {
        domainAge.textContent = "Established";
      }
    } else {
      domainAge.textContent = "Unknown";
    }
  }
}

/**
 * Populate detailed analysis panel
 * @param {Object} result - Result from API
 */
function populateDetailedAnalysis(result) {
  // Populate threat sources
  const threatSources = document.getElementById("threat-sources");
  if (threatSources) {
    threatSources.innerHTML = "";

    // For now, add a simple placeholder since we don't have actual threat intel
    const div = document.createElement("div");
    div.className = "source-item";

    // Determine indicator color based on threat level
    let indicator = "green";
    if (result.threat_level === "high" || result.threat_level === "critical") {
      indicator = "red";
    } else if (result.threat_level === "medium") {
      indicator = "yellow";
    }

    div.innerHTML = `
            <div class="source-indicator indicator-${indicator}"></div>
            <span>URL Analysis: ${result.threat_level || "Unknown"}</span>
        `;
    threatSources.appendChild(div);
  }

  // Populate URL features
  const featureList = document.getElementById("feature-list");
  if (featureList) {
    featureList.innerHTML = "";

    if (result.url_features) {
      const features = [
        {
          label: "Domain typo",
          value: result.url_features.has_common_typos > 0 ? "Detected" : "None",
          risk: result.url_features.has_common_typos > 0 ? "high" : "low"
        },
        {
          label: "Security keywords",
          value: result.url_features.has_security_keywords,
          risk: result.url_features.has_security_keywords > 2 ? "high" : "low"
        },
        {
          label: "HTTPS",
          value: result.url_features.has_https ? "Yes" : "No",
          risk: result.url_features.has_https ? "low" : "medium"
        }
      ];

      features.forEach((feature) => {
        const div = document.createElement("div");
        div.className = "feature-item";
        div.innerHTML = `
                    <span class="feature-label">${feature.label}</span>
                    <span>
                        <span class="feature-value">${feature.value}</span>
                        <span class="feature-risk risk-${feature.risk}">${feature.risk}</span>
                    </span>
                `;
        featureList.appendChild(div);
      });
    } else {
      // Add a placeholder if no URL features available
      const div = document.createElement("div");
      div.className = "feature-item";
      div.innerHTML = `
                <span class="feature-label">URL Features</span>
                <span>
                    <span class="feature-value">Not available</span>
                </span>
            `;
      featureList.appendChild(div);
    }
  }

  // Update recommendation
  const recommendationText = document.getElementById("recommendation-text");
  if (recommendationText) {
    recommendationText.textContent = generateRecommendation(result);
  }
}

/**
 * Generate a recommendation based on analysis
 * @param {Object} result - Result from API
 * @returns {string} - Recommendation text
 */
function generateRecommendation(result) {
  const threatLevel = result.threat_level || "unknown";

  if (result.error) {
    if (result.url_features && result.url_features.url_confidence_score > 0.7) {
      return "CAUTION: Could not analyze content, but URL structure appears suspicious. Proceed with caution.";
    } else {
      return "UNKNOWN: Could not fully analyze this URL. Proceed with caution.";
    }
  }

  switch (threatLevel) {
    case "high":
    case "critical":
      return "BLOCK: High risk detected. Do not visit this URL.";
    case "medium":
      return "CAUTION: Potential risk detected. Proceed with extreme caution and verify legitimacy.";
    case "low":
      return "ATTENTION: Low risk detected, but still exercise caution.";
    case "safe":
      return "ALLOW: No significant threats detected. URL appears to be safe.";
    default:
      return "REVIEW: Insufficient data for confident assessment. Manual review recommended.";
  }
}

/**
 * Toggle the visibility of the detailed analysis panel
 */
function toggleDetails() {
  const panel = document.getElementById("details-panel");
  const toggle = document.getElementById("details-toggle");

  if (!panel || !toggle) return;

  if (panel.style.display === "none") {
    panel.style.display = "block";
    toggle.textContent = "Hide Detailed Analysis ▲";
  } else {
    panel.style.display = "none";
    toggle.textContent = "Show Detailed Analysis ▼";
  }
}

/**
 * Display batch results in dashboard
 * @param {Array} results - Array of URL scan results
 */
function displayBatchResults(results) {
  console.log("=== DEBUGGING displayBatchResults ===");
  console.log("Results received:", results);

  results.forEach((result, index) => {
    console.log(`Result ${index}:`, result);
    console.log(`  class_name: ${result.class_name}`);
    console.log(`  final_confidence: ${result.final_confidence}`);
    console.log(`  probabilities: ${JSON.stringify(result.probabilities)}`);
    console.log(`  error: ${result.error}`);
    console.log(`  threat_level: ${result.threat_level}`);
  });
  console.log("================================");
  // Store results globally for reference
  window.batchResults = results;
  window.batchResultsData = results; // For debugging

  // Hide single result, show batch dashboard
  if (document.getElementById("result-card")) {
    document.getElementById("result-card").style.display = "none";
  }

  const batchDashboard = document.getElementById("batch-dashboard");
  if (batchDashboard) {
    batchDashboard.style.display = "block";
  }

  // Hide loading spinner
  if (document.getElementById("loading-spinner")) {
    document.getElementById("loading-spinner").style.display = "none";
  }

  // Update summary stats
  updateBatchSummary(results);

  // Render results list
  renderBatchList(results);
}

/**
 * Update batch summary statistics
 * @param {Array} results - Array of URL scan results
 */
function updateBatchSummary(results) {
  console.log("=== enhanced-ui.js updateBatchSummary called ===");
  console.log("Results:", results);
  console.log("Updating batch summary stats with data:", results);

  const stats = {
    total: results.length,
    high: 0,
    medium: 0,
    safe: 0
  };

  results.forEach((result) => {
    const threatLevel = result.threat_level || "unknown";
    // FIXED: Don't count errors/unknown as safe
    if (result.error || !result.class_name || result.class_name === null) {
      // Don't count failed analyses as safe - they should be neutral/unknown
      return; // Don't increment any counter for failed analyses
    }
    switch (threatLevel) {
      case "high":
      case "critical":
        stats.high++;
        break;
      case "medium":
        stats.medium++;
        break;
      case "low":
      case "safe":
        // Only count as safe if ML actually analyzed it successfully
        if (result.class_name && result.class_name !== null) {
          stats.safe++;
        }
        break;
      default:
        // Unknown/failed analyses don't count as safe
        break;
    }
  });

  console.log("Calculated summary stats:", stats);

  // Update the summary boxes
  if (document.getElementById("total-urls")) {
    document.getElementById("total-urls").textContent = stats.total;
  }

  if (document.getElementById("high-risk")) {
    document.getElementById("high-risk").textContent = stats.high;
  }

  if (document.getElementById("medium-risk")) {
    document.getElementById("medium-risk").textContent = stats.medium;
  }

  if (document.getElementById("safe-urls")) {
    document.getElementById("safe-urls").textContent = stats.safe;
  }
}

/**
 * Render batch results list
 * @param {Array} results - Array of URL scan results
 */
function renderBatchList(results) {
  const container = document.getElementById("batch-results");
  if (!container) return;

  container.innerHTML = "";

  results.forEach((result, index) => {
    const item = createBatchResultItem(result, index);
    container.appendChild(item);
  });
}

/**
 * Create a batch result item
 * @param {Object} result - Single URL result
 * @param {number} index - Index in batch array
 * @returns {HTMLElement} - Batch result item element
 */
function createBatchResultItem(result, index) {
  const div = document.createElement("div");
  div.className = "batch-result-item";

  const threatLevel = result.threat_level || "unknown";
  let icon = "✅";
  let badgeClass = "badge-safe";

  switch (threatLevel) {
    case "high":
    case "critical":
      icon = "🛑";
      badgeClass = "badge-high";
      break;
    case "medium":
      icon = "⚠️";
      badgeClass = "badge-medium";
      break;
    case "low":
      icon = "✓";
      badgeClass = "badge-low";
      break;
  }

  const confidence = result.final_confidence || (result.probabilities ? Math.max(...Object.values(result.probabilities)) : 0);

  div.innerHTML = `
        <div class="batch-icon">${icon}</div>
        <div class="batch-info">
            <div class="batch-url">${result.url}</div>
            <div class="batch-details">
                <span>${result.class_name || "Unknown"}</span>
                <span>•</span>
                <span>Confidence: ${Math.round(confidence * 100)}%</span>
                <span>•</span>
                <span class="threat-badge ${badgeClass}" style="padding: 2px 6px; margin: 0;">${threatLevel.toUpperCase()}</span>
            </div>
        </div>
        <button class="batch-action" onclick="showBatchDetails(${index})">Details</button>
    `;

  return div;
}

/**
 * Show details for a specific batch result
 * @param {number} index - Index of result in batch array
 */
function showBatchDetails(index) {
  if (!window.batchResults || index >= window.batchResults.length) return;

  const result = window.batchResults[index];
  displayEnhancedResult(result);

  // Scroll to result card
  document.getElementById("result-card").scrollIntoView({ behavior: "smooth" });
}

/**
 * Filter batch results by threat level
 */
function filterBatchResults() {
  const filterSelect = document.getElementById("risk-filter");
  if (!filterSelect || !window.batchResults) return;

  const filter = filterSelect.value;
  let filteredResults = [...window.batchResults];

  if (filter !== "all") {
    filteredResults = window.batchResults.filter((result) => {
      const threatLevel = result.threat_level || "unknown";

      if (filter === "high") return ["high", "critical"].includes(threatLevel);
      if (filter === "medium") return threatLevel === "medium";
      if (filter === "safe") return ["low", "safe", "unknown"].includes(threatLevel);

      return true;
    });
  }

  renderBatchList(filteredResults);
}

/**
 * Sort batch results by different criteria
 */
function sortBatchResults() {
  const sortSelect = document.getElementById("sort-by");
  if (!sortSelect || !window.batchResults) return;

  const sortBy = sortSelect.value;
  let sortedResults = [...window.batchResults];

  sortedResults.sort((a, b) => {
    if (sortBy === "risk") {
      const riskOrder = { critical: 4, high: 3, medium: 2, low: 1, safe: 0, unknown: -1 };
      const levelA = a.threat_level || "unknown";
      const levelB = b.threat_level || "unknown";

      return (riskOrder[levelB] || 0) - (riskOrder[levelA] || 0);
    } else if (sortBy === "confidence") {
      const confA = a.final_confidence || (a.probabilities ? Math.max(...Object.values(a.probabilities)) : 0);
      const confB = b.final_confidence || (b.probabilities ? Math.max(...Object.values(b.probabilities)) : 0);

      return confB - confA;
    } else if (sortBy === "url") {
      return a.url.localeCompare(b.url);
    }

    return 0;
  });

  renderBatchList(sortedResults);
}

/**
 * Function to save current result to favorites
 */
function saveToFavorites() {
  alert("Saving to favorites... This feature is being implemented.");
  // Implementation will depend on your backend API
}

/**
 * Function to share the current result
 */
function shareResult() {
  alert("Sharing result... This feature is being implemented.");
  // Implementation will depend on your sharing functionality
}

/**
 * Function to export batch results as CSV
 */
function exportResults() {
  if (!window.batchResults || window.batchResults.length === 0) {
    alert("No results to export");
    return;
  }

  // Build CSV content
  let csv = "URL,Classification,Threat Level,Confidence\n";

  window.batchResults.forEach((result) => {
    const confidence = result.final_confidence || (result.probabilities ? Math.max(...Object.values(result.probabilities)) : 0);

    csv += `"${result.url}","${result.class_name || "Unknown"}","${result.threat_level || "unknown"}","${confidence.toFixed(4)}"\n`;
  });

  // Create download link
  const blob = new Blob([csv], { type: "text/csv" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");

  a.href = url;
  a.download = `phishr-batch-results-${new Date().toISOString().substring(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();

  // Cleanup
  setTimeout(() => {
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
  }, 100);
}

/**
 * Function to save all batch results to history
 */
function saveAllResults() {
  alert("Saving all results... This feature is being implemented.");
  // Implementation will depend on your backend API
}

// Initialize event listeners when the document is ready
document.addEventListener("DOMContentLoaded", function () {
  // Add event listeners for filter and sort controls
  const riskFilter = document.getElementById("risk-filter");
  if (riskFilter) {
    riskFilter.addEventListener("change", filterBatchResults);
  }

  const sortBy = document.getElementById("sort-by");
  if (sortBy) {
    sortBy.addEventListener("change", sortBatchResults);
  }

  // Add event listener for details toggle
  const detailsToggle = document.getElementById("details-toggle");
  if (detailsToggle) {
    detailsToggle.addEventListener("click", toggleDetails);
  }

  console.log("Enhanced UI functionality initialized");
});

// Listen for scan form submission
document.addEventListener("DOMContentLoaded", function () {
  const scanForm = document.getElementById("scan-form");
  if (scanForm) {
    scanForm.addEventListener("submit", function (e) {
      // The default form handling may already be working
      // This is just for demonstration if you want to override it
      // Uncomment if you want to override the default form submission
      /*
            e.preventDefault();
            const url = document.getElementById('url-input').value;
            
            // Show loading spinner
            document.getElementById('loading-spinner').style.display = 'flex';
            document.getElementById('result-card').style.display = 'none';
            
            // Call API
            fetch('/classify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url })
            })
            .then(response => response.json())
            .then(result => {
                // Display enhanced result
                displayEnhancedResult(result);
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error scanning URL. Please try again.');
            });
            */
    });
  }
  console.log("Enhanced UI script loaded");
});
