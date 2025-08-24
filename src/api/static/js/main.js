/**
 * PhishR - Main JavaScript
 * Handles all client-side functionality for the phishing detection application
 */

// Wait for DOM to be fully loaded
document.addEventListener("DOMContentLoaded", function () {
  // Initialize different components based on which elements exist on the page
  initializeSingleUrlScanner();
  initializeBatchUrlScanner();
  loadScanHistory();

  // Check if message container is needed for notifications
  createMessageContainer();

  console.log("PhishR JavaScript initialized");
});

// ====== HELPER FUNCTIONS ======

/**
 * Get a cookie value by name
 */
function getCookie(name) {
  const value = `; ${document.cookie}`;
  console.log(`Looking for cookie: ${name} in cookies:`, document.cookie);
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) {
    const cookieValue = parts.pop().split(";").shift();
    console.log(`Found cookie ${name}:`, cookieValue);
    return cookieValue;
  }
  console.log(`Cookie ${name} not found`);
  return null;
}

/**
 * Show a message notification
 */
function showMessage(message, type = "info") {
  // Create message container if it doesn't exist
  let messageContainer = document.getElementById("message-container");
  if (!messageContainer) {
    messageContainer = createMessageContainer();
  }

  // Create message element
  const messageElement = document.createElement("div");
  messageElement.className = `message ${type}`;
  messageElement.textContent = message;
  messageElement.style.padding = "10px 15px";
  messageElement.style.margin = "5px 0";
  messageElement.style.borderRadius = "4px";
  messageElement.style.boxShadow = "0 2px 5px rgba(0, 0, 0, 0.2)";

  // Set background color based on type
  if (type === "error") {
    messageElement.style.backgroundColor = "#f8d7da";
    messageElement.style.color = "#721c24";
    messageElement.style.borderLeft = "4px solid #dc3545";
  } else if (type === "success") {
    messageElement.style.backgroundColor = "#d4edda";
    messageElement.style.color = "#155724";
    messageElement.style.borderLeft = "4px solid #28a745";
  } else {
    messageElement.style.backgroundColor = "#cce5ff";
    messageElement.style.color = "#004085";
    messageElement.style.borderLeft = "4px solid #007bff";
  }

  // Add close button
  const closeButton = document.createElement("span");
  closeButton.textContent = "×";
  closeButton.style.float = "right";
  closeButton.style.cursor = "pointer";
  closeButton.style.marginLeft = "10px";
  closeButton.style.fontWeight = "bold";
  closeButton.onclick = function () {
    messageContainer.removeChild(messageElement);
  };
  messageElement.prepend(closeButton);

  // Add to container
  messageContainer.appendChild(messageElement);

  // Auto-remove after 5 seconds
  setTimeout(() => {
    if (messageElement.parentNode === messageContainer) {
      messageContainer.removeChild(messageElement);
    }
  }, 5000);
}

/**
 * Create the message container for notifications
 */
function createMessageContainer() {
  let messageContainer = document.getElementById("message-container");
  if (!messageContainer) {
    messageContainer = document.createElement("div");
    messageContainer.id = "message-container";
    messageContainer.style.position = "fixed";
    messageContainer.style.top = "20px";
    messageContainer.style.right = "20px";
    messageContainer.style.zIndex = "1000";
    document.body.appendChild(messageContainer);
  }
  return messageContainer;
}

// ====== SINGLE URL SCANNER ======

/**
 * Initialize the single URL scanner
 */
function initializeSingleUrlScanner() {
  const scanForm = document.getElementById("scan-form");
  const urlInput = document.getElementById("url-input");
  const scanButton = document.getElementById("scan-button");
  const resultsSection = document.getElementById("results-section");
  const resultsContainer = document.getElementById("results-container");
  const loadingSpinner = document.getElementById("loading-spinner");

  // Check if enhanced UI is available
  const hasEnhancedUI = document.getElementById("result-card") !== null;

  // Check if we're on a page with the scanner
  if (!scanForm) return;

  // Hide results section initially
  if (resultsSection) {
    resultsSection.style.display = "none";
  }

  // Handle form submission
  scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    // Get URL from input
    const url = urlInput.value.trim();

    // Validate URL
    if (!url) {
      showMessage("Please enter a URL", "error");
      return;
    }

    try {
      new URL(url); // This will throw an error if URL is invalid
    } catch (err) {
      showMessage("Please enter a valid URL (including http:// or https://)", "error");
      return;
    }

    // Show loading state
    if (scanButton) scanButton.disabled = true;
    if (loadingSpinner) loadingSpinner.style.display = "block";

    // Hide previous results
    if (resultsContainer) resultsContainer.innerHTML = "";
    if (resultsSection) resultsSection.style.display = "block";

    // If using enhanced UI, hide the result card while loading
    if (hasEnhancedUI) {
      const resultCard = document.getElementById("result-card");
      if (resultCard) resultCard.style.display = "none";
    }

    try {
      // Get authentication token if available
      const token = getCookie("access_token");

      // Call API to scan URL
      const response = await fetch("/classify", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: token } : {})
        },
        body: JSON.stringify({ url: url })
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      const data = await response.json();

      // Log API response for debugging
      console.log("API Response:", data);

      // Check if we should use enhanced display or original display
      if (hasEnhancedUI && typeof displayEnhancedResult === "function") {
        console.log("Using enhanced display");
        // Use enhanced UI display
        displayEnhancedResult(data);
      } else {
        console.log("Using original display");
        // Use original display
        displayResults(data);
      }

      // Show success message
      showMessage("URL scanned successfully", "success");
    } catch (error) {
      console.error("Error scanning URL:", error);
      showMessage("An error occurred while scanning the URL", "error");

      // Show error in original UI
      if (resultsContainer) {
        resultsContainer.innerHTML = `
                  <div class="error-message">
                      <p>${error.message || "An error occurred while scanning the URL"}</p>
                  </div>
              `;
      }

      // Show error in enhanced UI if available
      if (hasEnhancedUI && typeof displayEnhancedResult === "function") {
        try {
          const errorData = {
            url: url,
            error: error.message || "An error occurred while scanning the URL",
            threat_level: "unknown"
          };
          displayEnhancedResult(errorData);
        } catch (displayError) {
          console.error("Error displaying enhanced error:", displayError);
        }
      }
    } finally {
      // Hide loading state
      if (scanButton) scanButton.disabled = false;
      if (loadingSpinner) loadingSpinner.style.display = "none";
    }
  });
}
/**
 * Display single URL scan results with proper classification display
 */
function displayResults(data) {
  const resultsSection = document.getElementById("results-section");
  const resultsContainer = document.getElementById("results-container");

  if (!resultsSection || !resultsContainer) return;

  resultsContainer.innerHTML = "";
  resultsSection.style.display = "block";

  const resultCard = document.createElement("div");
  resultCard.className = "result-card";

  // Handle Unknown results with detailed explanations
  if (data.class_name === "Unknown" || data.class_name === null) {
    resultCard.innerHTML = createUnknownResultDisplay(data);
  } else {
    resultCard.innerHTML = createNormalResultDisplay(data);
  }

  resultsContainer.appendChild(resultCard);
  resultsSection.scrollIntoView({ behavior: "smooth" });
}

function createUnknownResultDisplay(data) {
  const errorDetails = data.error_details || {};

  return `
    <div class="result-header unknown-result">
      <span class="result-icon">❓</span>
      <h3 class="result-title">Unable to Classify URL</h3>
    </div>
    
    <div class="result-details">
      <p class="result-url"><strong>URL:</strong> ${data.url}</p>
      
      <div class="error-explanation">
        <h4>🔍 Why couldn't this URL be classified?</h4>
        
        <div class="error-reason">
          <strong>Issue:</strong> ${errorDetails.reason || "Technical Error"}
        </div>
        
        <div class="error-description">
          <p>${errorDetails.explanation || "Unable to analyze this URL due to technical issues."}</p>
        </div>
        
        ${
          errorDetails.possible_causes
            ? `
          <div class="possible-causes">
            <strong>Possible reasons:</strong>
            <ul>
              ${errorDetails.possible_causes.map((cause) => `<li>${cause}</li>`).join("")}
            </ul>
          </div>
        `
            : ""
        }
        
        ${
          errorDetails.user_action
            ? `
          <div class="user-action">
            <strong>💡 What you can do:</strong>
            <p>${errorDetails.user_action}</p>
          </div>
        `
            : ""
        }
        
        <div class="security-recommendation">
          <h5>🛡️ Security Recommendation:</h5>
          <p>If you're unsure about this URL, <strong>avoid visiting it</strong> until you can verify its legitimacy through other means.</p>
        </div>
      </div>
      
      ${
        data.url_features
          ? `
        <div class="url-analysis">
          <h4>📊 URL Analysis (Available)</h4>
          <p>While we couldn't fetch the website content, we were able to analyze the URL structure.</p>
          <small>Features extracted: ${Object.keys(data.url_features).length}</small>
        </div>
      `
          : ""
      }
      
      <details class="technical-details">
        <summary>🔧 Technical Details (for developers)</summary>
        <pre>${data.error || "No technical details available"}</pre>
      </details>
    </div>
  `;
}

function createNormalResultDisplay(data) {
  const resultIcon = data.threat_level === "high" ? "🚨" : data.threat_level === "medium" ? "⚠️" : "✅";

  const resultMessage = data.threat_level === "high" ? "High Risk Detected" : data.threat_level === "medium" ? "Medium Risk" : "Low Risk";

  return `
    <div class="result-header">
      <span class="result-icon">${resultIcon}</span>
      <h3 class="result-title">${resultMessage}</h3>
    </div>
    
    <div class="result-details">
      <p class="result-url"><strong>URL:</strong> ${data.url}</p>
      <p class="result-classification"><strong>Classification:</strong> ${data.class_name}</p>
      
      <!-- Your existing enhanced analysis display -->
      <div class="enhanced-analysis">
        <div class="threat-level-section">
          <p><strong>Threat Level:</strong> 
            <span class="threat-${data.threat_level || "unknown"}">${(data.threat_level || "unknown").toUpperCase()}</span>
          </p>
          <p><strong>Combined Confidence:</strong> ${data.final_confidence ? (data.final_confidence * 100).toFixed(1) + "%" : "N/A"}</p>
        </div>
        
        <!-- Analysis Sources Breakdown -->
        <div class="analysis-sources">
          <h4>Analysis Sources:</h4>
          <div class="source-item">
            <span class="source-label">🤖 ML Analysis:</span>
            <span>${data.class_name || "Failed"}</span>
          </div>
          <div class="source-item">
            <span class="source-label">🛡️ VirusTotal:</span>
            <span>${data.url_features?.virustotal_status || "Checked"}</span>
          </div>
        </div>
      </div>
      
      ${
        data.probabilities
          ? `
        <div class="result-probabilities">
          <p><strong>ML Confidence Breakdown:</strong></p>
          ${createProbabilityBars(data.probabilities)}
        </div>
      `
          : ""
      }
    </div>
  `;
}

// Add this helper function if it doesn't exist:

function createProbabilityBars(probabilities) {
  if (!probabilities) return "";

  let html = "";
  for (const [className, probability] of Object.entries(probabilities)) {
    const percentage = (probability * 100).toFixed(1);
    html += `
      <div class="probability-bar">
        <span class="probability-label">${className}: ${percentage}%</span>
        <div class="probability-progress">
          <div class="probability-fill" style="width: ${percentage}%"></div>
        </div>
      </div>
    `;
  }
  return html;
}

// ====== BATCH URL SCANNER ======

/**
 * Initialize the batch URL scanner with enhanced UI support
 */
function initializeBatchUrlScanner() {
  const batchScanForm = document.getElementById("batch-scan-form");
  const batchUrlInput = document.getElementById("batch-url-input");
  const batchScanButton = document.getElementById("batch-scan-button");
  const csvUploadForm = document.getElementById("csv-upload-form");
  const csvFileInput = document.getElementById("csv-file-input");

  // Check if we're on a page with the batch scanner
  if (!batchScanForm) return;

  // Check if enhanced UI is available (batch dashboard exists)
  const hasEnhancedUI = document.getElementById("batch-dashboard") !== null;
  const loadingSpinner = document.getElementById("loading-spinner");

  // Update URL count in batch textarea label
  function updateUrlCount() {
    if (!batchUrlInput) return;

    const urlLines = batchUrlInput.value.split("\n").filter((line) => line.trim().length > 0);
    const urlCount = urlLines.length;
    const maxUrls = 10;

    // Find and update the label
    const label = batchUrlInput.parentElement.querySelector("label");
    if (label) {
      label.textContent = `Please enter a new URL on each line (Limit ${urlCount}/${maxUrls})`;
    }

    // Validate against max limit
    if (urlCount > maxUrls) {
      batchUrlInput.classList.add("error");
      if (batchScanButton) batchScanButton.disabled = true;
    } else {
      batchUrlInput.classList.remove("error");
      if (batchScanButton) batchScanButton.disabled = false;
    }
  }

  // Initialize URL count updating
  if (batchUrlInput) {
    batchUrlInput.addEventListener("input", updateUrlCount);
    updateUrlCount(); // Initialize count
  }

  // Handle batch scan form submission
  if (batchScanForm) {
    batchScanForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      // Get URLs from input
      const urlLines = batchUrlInput.value
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);

      if (urlLines.length === 0) {
        showMessage("Please enter at least one URL", "error");
        return;
      }

      if (urlLines.length > 10) {
        showMessage("Please enter no more than 10 URLs", "error");
        return;
      }

      // Validate URLs
      const invalidUrls = urlLines.filter((url) => {
        try {
          new URL(url);
          return false; // URL is valid
        } catch (err) {
          return true; // URL is invalid
        }
      });

      if (invalidUrls.length > 0) {
        showMessage(`The following URLs are invalid:\n${invalidUrls.join("\n")}\n\nPlease fix them and try again.`, "error");
        return;
      }

      // Disable button and show loading state
      batchScanButton.disabled = true;
      batchScanButton.textContent = "Scanning...";

      // If using enhanced UI, show loading spinner
      if (hasEnhancedUI && loadingSpinner) {
        loadingSpinner.style.display = "block";

        // Hide any existing results
        const resultCard = document.getElementById("result-card");
        if (resultCard) resultCard.style.display = "none";

        const batchDashboard = document.getElementById("batch-dashboard");
        if (batchDashboard) batchDashboard.style.display = "none";
      }

      try {
        // Get the token from cookies
        const token = getCookie("access_token");
        console.log("Authorization token for batch scan:", token);

        // Build headers
        const headers = {
          "Content-Type": "application/json"
        };

        if (token) {
          // Remove any quotes from the token
          let authToken = token;
          if (authToken.startsWith('"') && authToken.endsWith('"')) {
            authToken = authToken.substring(1, authToken.length - 1);
          }

          headers["Authorization"] = authToken; // Don't add extra quotes
          console.log("Added Authorization header:", headers["Authorization"]);
        } else {
          console.warn("No token available for request");
        }

        // Call API for batch scanning with Authorization header
        console.log("Sending batch scan request with headers:", headers);
        const response = await fetch("/classify-batch", {
          method: "POST",
          headers: headers,
          body: JSON.stringify({ urls: urlLines })
        });

        console.log("Batch scan response status:", response.status);

        if (response.status === 401) {
          console.error("Authentication failed (401 Unauthorized)");
          throw new Error("Authentication required. Please log in again.");
        }

        if (!response.ok) {
          console.error("API error with status:", response.status);
          throw new Error(`API error: ${response.status}`);
        }

        const data = await response.json();
        console.log("Batch scan data received:", data);

        // Process results - this function now handles both UIs
        processBatchResults(data.results);

        // Show success message
        showMessage("Batch scan completed successfully", "success");

        // Clear input
        batchUrlInput.value = "";
        updateUrlCount();

        // Refresh scan history
        setTimeout(() => {
          loadScanHistory();
        }, 1000);
      } catch (error) {
        console.error("Error in batch scan:", error);
        showMessage(error.message || "An error occurred during batch scanning. Please try again.", "error");
      } finally {
        // Reset button state
        batchScanButton.disabled = false;
        batchScanButton.textContent = "SCAN";

        // Hide loading spinner if using enhanced UI
        if (hasEnhancedUI && loadingSpinner) {
          loadingSpinner.style.display = "none";
        }
      }
    });
  }

  // Handle CSV upload form submission
  if (csvUploadForm && csvFileInput) {
    csvUploadForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const file = csvFileInput.files[0];
      if (!file) {
        showMessage("Please select a CSV file", "error");
        return;
      }

      if (file.type !== "text/csv" && !file.name.endsWith(".csv")) {
        showMessage("Please upload a valid CSV file", "error");
        return;
      }

      // Disable button and show loading state
      const submitButton = csvUploadForm.querySelector("button");
      submitButton.disabled = true;
      submitButton.textContent = "Scanning...";

      // If using enhanced UI, show loading spinner
      if (hasEnhancedUI && loadingSpinner) {
        loadingSpinner.style.display = "block";

        // Hide any existing results
        const resultCard = document.getElementById("result-card");
        if (resultCard) resultCard.style.display = "none";

        const batchDashboard = document.getElementById("batch-dashboard");
        if (batchDashboard) batchDashboard.style.display = "none";
      }

      // Read file
      const reader = new FileReader();
      reader.onload = async (event) => {
        const csvContent = event.target.result;
        const urls = csvContent
          .split("\n")
          .map((line) => line.trim())
          .filter((line) => line.length > 0)
          .slice(0, 10); // Limit to 10 URLs

        if (urls.length === 0) {
          showMessage("No URLs found in the CSV file", "error");

          // Reset button state
          submitButton.disabled = false;
          submitButton.textContent = "Upload & Scan";

          // Hide loading spinner
          if (hasEnhancedUI && loadingSpinner) {
            loadingSpinner.style.display = "none";
          }

          return;
        }

        // Validate URLs
        const invalidUrls = urls.filter((url) => {
          try {
            new URL(url);
            return false; // URL is valid
          } catch (err) {
            return true; // URL is invalid
          }
        });

        if (invalidUrls.length > 0) {
          showMessage(`The following URLs in the CSV are invalid:\n${invalidUrls.join("\n")}\n\nPlease fix them and try again.`, "error");

          // Reset button state
          submitButton.disabled = false;
          submitButton.textContent = "Upload & Scan";

          // Hide loading spinner
          if (hasEnhancedUI && loadingSpinner) {
            loadingSpinner.style.display = "none";
          }

          return;
        }

        try {
          // Get the token from cookies
          const token = getCookie("access_token");

          // Call API for batch scanning with Authorization header
          const response = await fetch("/classify-batch", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: token || ""
            },
            body: JSON.stringify({ urls })
          });

          if (response.status === 401) {
            throw new Error("Authentication required. Please log in again.");
          }

          if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
          }

          const data = await response.json();

          // Process and display results - works with both UIs
          processBatchResults(data.results);

          // Show success message
          showMessage("CSV scan completed successfully", "success");

          // Clear input
          csvFileInput.value = "";

          // Refresh scan history
          setTimeout(() => {
            loadScanHistory();
          }, 1000);
        } catch (error) {
          console.error("Error in CSV scan:", error);
          showMessage(error.message || "An error occurred during CSV scanning. Please try again.", "error");
        } finally {
          // Reset button state
          submitButton.disabled = false;
          submitButton.textContent = "Upload & Scan";

          // Hide loading spinner if using enhanced UI
          if (hasEnhancedUI && loadingSpinner) {
            loadingSpinner.style.display = "none";
          }
        }
      };

      reader.readAsText(file);
    });
  }
}

/**
 * Process and display batch scan results with enhanced UI and error handling
 */
function processBatchResults(results) {
  console.log("Processing batch results:", results);

  const resultsSection = document.getElementById("results-section");
  let batchResultsContainer = document.getElementById("batch-results-container");

  // Check if results section exists
  if (!resultsSection) {
    console.error("Results section not found");
    showMessage("Error: Results section not found on page", "error");
    return;
  }

  // Create batch results container if it doesn't exist
  if (!batchResultsContainer) {
    console.log("Creating batch results container");
    batchResultsContainer = document.createElement("div");
    batchResultsContainer.id = "batch-results-container";
    batchResultsContainer.className = "batch-results-container";

    // Add it to the results section
    resultsSection.appendChild(batchResultsContainer);
  }

  // Clear any existing content
  batchResultsContainer.innerHTML = "";

  // Validate results
  if (!results || !Array.isArray(results)) {
    console.error("Invalid results data:", results);
    showMessage("Error: Invalid results data received", "error");
    return;
  }

  // Count results by status
  const statusCounts = {
    high: results.filter((r) => r && r.threat_level === "high").length,
    medium: results.filter((r) => r && r.threat_level === "medium").length,
    low: results.filter((r) => r && r.threat_level === "low").length,
    unknown: results.filter((r) => r && (r.class_name === "Unknown" || r.class_name === null)).length
  };

  // Get unknown results for detailed display
  const unknownResults = results.filter((r) => r && (r.class_name === "Unknown" || r.class_name === null));

  console.log("Status counts:", statusCounts);
  console.log("Unknown results:", unknownResults);

  try {
    // Create the batch results HTML
    batchResultsContainer.innerHTML = `
      <h3>🎯 Batch Analysis Results (${results.length} URLs)</h3>
      
      <div class="batch-summary">
        <div class="summary-stats">
          <div class="stat high-risk">🚨 High Risk: ${statusCounts.high}</div>
          <div class="stat medium-risk">⚠️ Medium Risk: ${statusCounts.medium}</div>
          <div class="stat low-risk">✅ Low Risk: ${statusCounts.low}</div>
          <div class="stat unknown-risk">❓ Unknown: ${statusCounts.unknown}</div>
        </div>
      </div>
      
      ${
        unknownResults.length > 0
          ? `
        <div class="batch-unknown-summary">
          <h4>❓ ${unknownResults.length} URL(s) Could Not Be Classified</h4>
          <p>The following URLs could not be analyzed due to technical issues:</p>
          <div class="unknown-urls-list">
            ${unknownResults
              .map(
                (result, index) => `
              <div class="unknown-url-item">
                <div class="url">${result.url || "Unknown URL"}</div>
                <div class="reason">
                  ${result.error_details?.reason || "Analysis failed"}: 
                  ${result.error_details?.explanation || result.error || "Technical error occurred"}
                </div>
                <button class="details-btn small-btn" onclick="showUnknownDetailsModal('${result.url}', '${encodeURIComponent(JSON.stringify(result))}')">
                  Why Unknown?
                </button>
              </div>
            `
              )
              .join("")}
          </div>
          <p><strong>💡 Recommendation:</strong> Verify these URLs manually in your browser and be cautious if they don't load properly.</p>
        </div>
      `
          : ""
      }
    `;

    // Create and add the results table
    const table = document.createElement("table");
    table.className = "batch-results-table";
    table.innerHTML = `
      <thead>
        <tr>
          <th>URL</th>
          <th>Classification</th>
          <th>Threat Level</th>
          <th>Combined Confidence</th>
          <th>Status</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody></tbody>
    `;

    const tbody = table.querySelector("tbody");

    results.forEach((result, index) => {
      if (!result) {
        console.warn("Skipping null result at index", index);
        return;
      }

      const row = document.createElement("tr");
      const isUnknown = result.class_name === "Unknown" || result.class_name === null;
      const statusClass = isUnknown ? "status-unknown" : result.threat_level === "high" ? "status-high-risk" : result.threat_level === "medium" ? "status-medium-risk" : "status-low-risk";

      const combinedConfidence = result.final_confidence ? (result.final_confidence * 100).toFixed(1) + "%" : "N/A";

      row.innerHTML = `
        <td class="url-cell" title="${result.url || "Unknown URL"}">${result.url || "Unknown URL"}</td>
        <td>${isUnknown ? "Unable to Classify" : result.class_name || "Unknown"}</td>
        <td><span class="threat-${result.threat_level || "unknown"}">${(result.threat_level || "unknown").toUpperCase()}</span></td>
        <td>${combinedConfidence}</td>
        <td class="${statusClass}">${isUnknown ? "Analysis Failed" : "Analyzed"}</td>
        <td>
          ${
            isUnknown
              ? `
            <button class="details-btn" onclick="showUnknownDetailsFromTable(${index})">
              Why Unknown?
            </button>
          `
              : `
            <button class="details-btn" onclick="showResultDetails(${index})">
              View Details
            </button>
          `
          }
        </td>
      `;

      tbody.appendChild(row);
    });

    batchResultsContainer.appendChild(table);

    // Show the results section and scroll to it
    resultsSection.style.display = "block";
    resultsSection.scrollIntoView({ behavior: "smooth" });

    // Store results for detail functions
    window.batchResults = results;

    console.log("✅ Batch results displayed successfully");
  } catch (error) {
    console.error("Error displaying batch results:", error);
    showMessage("Error displaying batch results: " + error.message, "error");
  }
}

// Enhanced function to show unknown details from the table
function showUnknownDetailsFromTable(index) {
  if (!window.batchResults || !window.batchResults[index]) {
    showMessage("Error: Result data not found", "error");
    return;
  }

  const result = window.batchResults[index];
  showUnknownDetailsModal(result.url, encodeURIComponent(JSON.stringify(result)));
}

// Function to show unknown details modal
function showUnknownDetailsModal(url, encodedResult) {
  console.log("Showing unknown details for:", url);

  try {
    const result = JSON.parse(decodeURIComponent(encodedResult));
    const errorDetails = result.error_details || {};

    // Create modal HTML with corrected close button
    const modalHtml = `
      <div class="modal-overlay">
        <div class="modal-content" onclick="event.stopPropagation()">
          <div class="modal-header">
            <h3>❓ Why couldn't this URL be classified?</h3>
            <button class="modal-close" onclick="closeModal(document.querySelector('.modal-overlay'))">&times;</button>
          </div>
          
          <div class="modal-body">
            <div class="modal-url">
              <strong>URL:</strong> ${url || "Unknown"}
            </div>
            
            <div class="modal-error-details">
              <div class="error-reason">
                <strong>Issue:</strong> ${errorDetails.reason || "Content Fetch Failed"}
              </div>
              
              <div class="error-description">
                <p>${errorDetails.explanation || "Unable to fetch and analyze website content. This could be due to various technical issues."}</p>
              </div>
              
              <div class="possible-causes">
                <strong>Possible reasons:</strong>
                <ul>
                  <li>Domain has expired or been taken down</li>
                  <li>Domain is blocked by security filters</li>
                  <li>DNS configuration issues</li>
                  <li>Website is blocking automated requests</li>
                  <li>Server is down or unreachable</li>
                  <li>Potentially malicious domain that has been sinkholed</li>
                </ul>
              </div>
              
              <div class="user-action">
                <strong>💡 What you can do:</strong>
                <p>Try accessing the website directly in your browser to verify if it loads normally. Be cautious if it doesn't load - this could indicate a security risk.</p>
              </div>
              
              <div class="security-recommendation">
                <h5>🛡️ Security Recommendation:</h5>
                <p>If you're unsure about this URL, <strong>avoid visiting it</strong> until you can verify its legitimacy.</p>
              </div>
              
              ${
                result.error
                  ? `
                <details class="technical-details">
                  <summary>🔧 Technical Details</summary>
                  <pre>${result.error}</pre>
                </details>
              `
                  : ""
              }
            </div>
          </div>
        </div>
      </div>
    `;

    // Remove any existing modals
    const existingModal = document.querySelector(".modal-overlay");
    if (existingModal) {
      existingModal.remove();
    }

    // Add modal to page
    document.body.insertAdjacentHTML("beforeend", modalHtml);

    // Add click outside to close functionality
    const newModal = document.querySelector(".modal-overlay");
    newModal.addEventListener("click", function (event) {
      if (event.target === newModal) {
        newModal.remove();
      }
    });
  } catch (error) {
    console.error("Error showing unknown details:", error);
    showMessage("Error showing details: " + error.message, "error");
  }
}

// Update the showResultDetails function similarly:
function showResultDetails(index) {
  if (!window.batchResults || !window.batchResults[index]) {
    showMessage("Error: Result data not found", "error");
    return;
  }

  const result = window.batchResults[index];
  console.log("Showing result details for:", result.url);

  try {
    // Create detailed modal HTML for successful results with corrected close button
    const modalHtml = `
      <div class="modal-overlay">
        <div class="modal-content" onclick="event.stopPropagation()">
          <div class="modal-header">
            <h3>🔍 Detailed Analysis Results</h3>
            <button class="modal-close" onclick="closeModal(document.querySelector('.modal-overlay'))">&times;</button>
          </div>
          
          <div class="modal-body">
            <div class="modal-url">
              <strong>URL:</strong> ${result.url || "Unknown"}
            </div>
            
            <!-- Classification Summary -->
            <div class="classification-summary">
              <h4>📊 Classification Summary</h4>
              <div class="summary-grid">
                <div class="summary-item">
                  <strong>Classification:</strong>
                  <span class="classification-badge ${result.class_name?.toLowerCase().replace(" ", "-") || "unknown"}">
                    ${result.class_name || "Unknown"}
                  </span>
                </div>
                <div class="summary-item">
                  <strong>Threat Level:</strong>
                  <span class="threat-badge threat-${result.threat_level || "unknown"}">
                    ${(result.threat_level || "unknown").toUpperCase()}
                  </span>
                </div>
                <div class="summary-item">
                  <strong>Combined Confidence:</strong>
                  <span class="confidence-value">
                    ${result.final_confidence ? (result.final_confidence * 100).toFixed(1) + "%" : "N/A"}
                  </span>
                </div>
              </div>
            </div>

            <!-- ML Analysis Details -->
            ${
              result.probabilities
                ? `
              <div class="ml-analysis">
                <h4>🤖 Machine Learning Analysis</h4>
                <div class="probability-breakdown">
                  ${Object.entries(result.probabilities)
                    .map(
                      ([className, probability]) => `
                    <div class="probability-item">
                      <div class="probability-header">
                        <span class="class-name">${className}</span>
                        <span class="probability-value">${(probability * 100).toFixed(1)}%</span>
                      </div>
                      <div class="probability-bar-container">
                        <div class="probability-bar-fill" style="width: ${probability * 100}%; background-color: ${getProbabilityColor(className, probability)}"></div>
                      </div>
                    </div>
                  `
                    )
                    .join("")}
                </div>
              </div>
            `
                : ""
            }

            <!-- Analysis Sources -->
            <div class="analysis-sources">
              <h4>🛡️ Analysis Sources</h4>
              <div class="sources-grid">
                <div class="source-item">
                  <span class="source-icon">🤖</span>
                  <div class="source-details">
                    <strong>Machine Learning</strong>
                    <small>${result.probabilities ? "Analysis completed" : "Analysis failed"}</small>
                  </div>
                </div>
                <div class="source-item">
                  <span class="source-icon">🛡️</span>
                  <div class="source-details">
                    <strong>VirusTotal</strong>
                    <small>${result.url_features?.virustotal_status || "Checked"}</small>
                  </div>
                </div>
                <div class="source-item">
                  <span class="source-icon">🔧</span>
                  <div class="source-details">
                    <strong>URL Features</strong>
                    <small>${result.url_features ? Object.keys(result.url_features).length + " features extracted" : "No features"}</small>
                  </div>
                </div>
              </div>
            </div>

            <!-- URL Features (if available) -->
            ${
              result.url_features
                ? `
              <div class="url-features">
                <h4>🔧 URL Features Analysis</h4>
                <div class="features-grid">
                  ${Object.entries(result.url_features)
                    .slice(0, 8)
                    .map(
                      ([feature, value]) => `
                    <div class="feature-item">
                      <span class="feature-name">${formatFeatureName(feature)}:</span>
                      <span class="feature-value">${formatFeatureValue(value)}</span>
                    </div>
                  `
                    )
                    .join("")}
                  ${
                    Object.keys(result.url_features).length > 8
                      ? `
                    <div class="feature-item">
                      <span class="feature-name">... and ${Object.keys(result.url_features).length - 8} more features</span>
                    </div>
                  `
                      : ""
                  }
                </div>
              </div>
            `
                : ""
            }

            <!-- Security Recommendations -->
            <div class="security-recommendations">
              <h4>🛡️ Security Recommendations</h4>
              ${getSecurityRecommendations(result)}
            </div>

            <!-- Technical Details -->
            <details class="technical-details">
              <summary>🔧 Technical Details</summary>
              <pre>${JSON.stringify(result, null, 2)}</pre>
            </details>
          </div>
        </div>
      </div>
    `;

    // Remove any existing modals
    const existingModal = document.querySelector(".modal-overlay");
    if (existingModal) {
      existingModal.remove();
    }

    // Add modal to page
    document.body.insertAdjacentHTML("beforeend", modalHtml);

    // Add click outside to close functionality
    const newModal = document.querySelector(".modal-overlay");
    newModal.addEventListener("click", function (event) {
      if (event.target === newModal) {
        newModal.remove();
      }
    });
  } catch (error) {
    console.error("Error showing result details:", error);
    showMessage("Error showing details: " + error.message, "error");
  }
}

/**
 * Helper function to get probability bar color
 */
function getProbabilityColor(className, probability) {
  if (className.toLowerCase().includes("legitimate")) {
    return `hsl(120, ${probability * 100}%, 40%)`; // Green for legitimate
  } else if (className.toLowerCase().includes("phishing")) {
    return `hsl(0, ${probability * 100}%, 50%)`; // Red for phishing
  } else if (className.toLowerCase().includes("malware")) {
    return `hsl(15, ${probability * 100}%, 45%)`; // Orange-red for malware
  } else {
    return `hsl(200, ${probability * 100}%, 50%)`; // Blue for others
  }
}

/**
 * Helper function to format feature names
 */
function formatFeatureName(feature) {
  return feature.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase());
}

/**
 * Helper function to format feature values
 */
function formatFeatureValue(value) {
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  } else if (typeof value === "number") {
    return Number.isInteger(value) ? value.toString() : value.toFixed(2);
  } else {
    return value?.toString() || "N/A";
  }
}

/**
 * Helper function to get security recommendations based on results
 */
function getSecurityRecommendations(result) {
  const threatLevel = result.threat_level?.toLowerCase();
  const classification = result.class_name?.toLowerCase();

  if (threatLevel === "high" || classification?.includes("phishing")) {
    return `
      <div class="recommendation high-risk">
        <strong>⚠️ HIGH RISK:</strong> This URL appears to be malicious. 
        <strong>Do not visit this website</strong> or enter any personal information.
        <ul>
          <li>Block this URL in your security systems</li>
          <li>Report it to your security team</li>
          <li>Warn others about this threat</li>
        </ul>
      </div>
    `;
  } else if (threatLevel === "medium") {
    return `
      <div class="recommendation medium-risk">
        <strong>⚠️ MEDIUM RISK:</strong> This URL shows some suspicious characteristics.
        <ul>
          <li>Exercise caution when visiting</li>
          <li>Do not enter sensitive information</li>
          <li>Verify the website's legitimacy through other means</li>
          <li>Use additional security measures if you must visit</li>
        </ul>
      </div>
    `;
  } else if (threatLevel === "low" || classification?.includes("legitimate")) {
    return `
      <div class="recommendation low-risk">
        <strong>✅ LOW RISK:</strong> This URL appears to be legitimate.
        <ul>
          <li>The website is likely safe to visit</li>
          <li>Still exercise normal web browsing caution</li>
          <li>Verify HTTPS encryption when entering sensitive data</li>
        </ul>
      </div>
    `;
  } else {
    return `
      <div class="recommendation unknown-risk">
        <strong>❓ UNKNOWN:</strong> Unable to determine the risk level.
        <ul>
          <li>Exercise caution when visiting</li>
          <li>Manually verify the website's legitimacy</li>
          <li>Do not enter sensitive information until verified</li>
        </ul>
      </div>
    `;
  }
}

// ====== SCAN HISTORY ======

/**
 * Load scan history from the server
 */
function loadScanHistory() {
  const scanHistoryBody = document.getElementById("scan-history-body");

  // Check if we're on a page with scan history
  if (!scanHistoryBody) return;

  // Get authentication token
  const token = getCookie("access_token");
  if (!token) {
    console.warn("No token available for scan history");
    scanHistoryBody.innerHTML = `
          <tr>
              <td colspan="7" class="empty-history">
                  Authentication required to view scan history.
              </td>
          </tr>
      `;
    return;
  }

  console.log("Loading scan history with token:", token.substring(0, 15) + "...");

  // Build headers with proper token handling
  const headers = {
    "Content-Type": "application/json"
  };

  // Remove any quotes from the token
  let authToken = token;
  if (authToken.startsWith('"') && authToken.endsWith('"')) {
    authToken = authToken.substring(1, authToken.length - 1);
  }

  headers["Authorization"] = authToken; // Don't add extra quotes
  console.log("Added Authorization header for scan history:", headers["Authorization"].substring(0, 20) + "...");

  // Fetch scan history from server
  fetch("/scan-history", {
    headers: headers
  })
    .then((response) => {
      console.log("Scan history response status:", response.status);
      if (!response.ok) {
        throw new Error(`Failed to load scan history: ${response.status}`);
      }
      return response.json();
    })
    .then((data) => {
      console.log("Scan history data received:", data);
      displayScanHistory(data.history || []);
    })
    .catch((error) => {
      console.error("Error loading scan history:", error);
      scanHistoryBody.innerHTML = `
          <tr>
              <td colspan="7" class="empty-history">
                  Error loading scan history. Please try refreshing the page.
              </td>
          </tr>
      `;
    });
}

/**
 * Display scan history in the table
 */
function displayScanHistory(history) {
  const scanHistoryBody = document.getElementById("scan-history-body");
  if (!scanHistoryBody) return;

  // Clear existing rows
  scanHistoryBody.innerHTML = "";

  if (!history || history.length === 0) {
    const emptyRow = document.createElement("tr");
    emptyRow.innerHTML = `<td colspan="7" class="empty-history">No scan history available yet</td>`;
    scanHistoryBody.appendChild(emptyRow);
    return;
  }

  // Add history entries
  history.forEach((entry) => {
    const row = document.createElement("tr");

    // Format date
    const date = new Date(entry.timestamp);
    const formattedDate = `${date.getDate()}-${["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][date.getMonth()]}-${date.getFullYear()}`;

    // Determine status class
    let statusClass = "status-unknown";
    if (entry.disposition) {
      const disposition = entry.disposition.toLowerCase();
      if (disposition === "clean" || disposition === "legitimate") {
        statusClass = "status-clean";
      } else if (disposition === "phishing" || disposition === "malware") {
        statusClass = "status-phishing";
      }
    }

    row.innerHTML = `
          <td><a href="${entry.url}" target="_blank">${entry.url}</a></td>
          <td>${entry.ip_address || "--"}</td>
          <td>${entry.hosting_provider || "--"}</td>
          <td class="${statusClass}">${entry.disposition || "Unknown"}</td>
          <td>${formattedDate}</td>
          <td>${entry.brand || "Unknown"}</td>
          <td>${entry.source || "Single Scan"}</td>
      `;

    scanHistoryBody.appendChild(row);
  });
}

// Add this function to your main.js file (you can place it near the other modal functions):

/**
 * Function to close modal
 */
function closeModal(modalElement) {
  if (modalElement) {
    modalElement.remove();
  }
}

// Alternative version that finds the modal if you pass any child element
function closeModalFromChild(element) {
  const modal = element.closest(".modal-overlay");
  if (modal) {
    modal.remove();
  }
}

// Also add keyboard support for closing modal with Escape key
document.addEventListener("keydown", function (event) {
  if (event.key === "Escape") {
    const modal = document.querySelector(".modal-overlay");
    if (modal) {
      modal.remove();
    }
  }
});

// Add click-outside-to-close functionality
document.addEventListener("click", function (event) {
  if (event.target.classList.contains("modal-overlay")) {
    event.target.remove();
  }
});

// Enhanced sticky header scroll effect
window.addEventListener("scroll", function () {
  const header = document.querySelector(".site-header");
  if (window.scrollY > 20) {
    header.classList.add("scrolled");
  } else {
    header.classList.remove("scrolled");
  }
});
