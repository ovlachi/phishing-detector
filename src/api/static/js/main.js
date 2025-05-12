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
    if (resultsContainer) resultsContainer.innerHTML = "";
    if (resultsSection) resultsSection.style.display = "block";

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

      // Display results
      displayResults(data);

      // Show success message
      showMessage("URL scanned successfully", "success");
    } catch (error) {
      console.error("Error scanning URL:", error);
      showMessage("An error occurred while scanning the URL", "error");

      if (resultsContainer) {
        resultsContainer.innerHTML = `
                  <div class="error-message">
                      <p>${error.message || "An error occurred while scanning the URL"}</p>
                  </div>
              `;
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

  // Ensure the results section exists before proceeding
  if (!resultsSection || !resultsContainer) {
    console.error("Results elements not found");
    return;
  }

  // Show results section
  resultsSection.style.display = "block";

  // Clear previous results
  resultsContainer.innerHTML = "";

  // Check if there's an error
  if (data.error) {
    // Create error-specific result card
    const errorCard = document.createElement("div");
    errorCard.className = "result-card error-card";

    // Check if it's a fetch error
    if (data.error.includes("Failed to fetch content")) {
      errorCard.innerHTML = `
              <div class="result-header">
                  <span class="result-icon">⚠️</span>
                  <h3 class="result-title">Failed to Fetch Content</h3>
              </div>
              <div class="result-details">
                  <p class="result-url"><strong>URL:</strong> ${data.url}</p>
                  <p class="error-explanation">Unable to access the website content for analysis. This may be due to:</p>
                  <ul class="error-reasons">
                      <li>Network connectivity issues</li>
                      <li>Website temporarily unavailable</li>
                      <li>SSL/TLS certificate problems</li>
                      <li>Access restrictions on the target site</li>
                  </ul>
                  <p class="error-note">Please try again later or verify the URL is correct.</p>
              </div>
          `;
    } else {
      // Generic error message
      errorCard.innerHTML = `
              <div class="result-header">
                  <span class="result-icon">❌</span>
                  <h3 class="result-title">Error</h3>
              </div>
              <div class="result-details">
                  <p class="error-message">${data.error}</p>
              </div>
          `;
    }

    resultsContainer.appendChild(errorCard);
    return;
  }

  // Create result card for successful scan
  const resultCard = document.createElement("div");
  resultCard.className = "result-card";

  // Determine result styling based on class - CASE INSENSITIVE COMPARISON
  let resultClass = "neutral";
  let resultIcon = "❓";
  let resultMessage = "Unknown";

  // Convert to lowercase for case-insensitive comparison
  const className = data.class_name ? data.class_name.toLowerCase() : "";

  // Check for specific classifications
  if (className === "legitimate") {
    resultClass = "safe";
    resultIcon = "✅";
    resultMessage = "This URL appears to be legitimate";
  } else if (className === "phishing" || className === "credential phishing") {
    resultClass = "dangerous";
    resultIcon = "⚠️";
    resultMessage = "Warning: This URL may be a credential phishing attempt";
  } else if (className === "malware" || className === "malware distribution") {
    resultClass = "dangerous";
    resultIcon = "🛑";
    resultMessage = "Danger: This URL may contain malware";
  }

  // If classification is still unknown, but we have probabilities, use the highest one
  if (resultClass === "neutral" && data.probabilities) {
    let highestProb = 0;
    let highestClass = "Unknown";

    for (const [className, probability] of Object.entries(data.probabilities)) {
      if (probability > highestProb) {
        highestProb = probability;
        highestClass = className;
      }
    }

    // If we found a high probability class, use that
    if (highestProb > 0.3) {
      // 30% threshold
      const highClassName = highestClass.toLowerCase();
      if (highClassName === "legitimate") {
        resultClass = "safe";
        resultIcon = "✅";
        resultMessage = "This URL appears to be legitimate";
      } else if (highClassName === "phishing" || highClassName === "credential phishing") {
        resultClass = "dangerous";
        resultIcon = "⚠️";
        resultMessage = "Warning: This URL may be a credential phishing attempt";
      } else if (highClassName === "malware" || highClassName === "malware distribution") {
        resultClass = "dangerous";
        resultIcon = "🛑";
        resultMessage = "Danger: This URL may contain malware";
      }
    }
  }

  // Add class to card
  resultCard.classList.add(resultClass);

  // Normalize the class name for display
  let displayClassification = data.class_name || "Unknown";
  if (displayClassification.toLowerCase() === "phishing") {
    displayClassification = "Credential Phishing";
  } else if (displayClassification.toLowerCase() === "credential phishing") {
    displayClassification = "Credential Phishing";
  }

  // Create HTML for result
  resultCard.innerHTML = `
      <div class="result-header">
          <span class="result-icon">${resultIcon}</span>
          <h3 class="result-title">${resultMessage}</h3>
      </div>
      <div class="result-details">
          <p class="result-url"><strong>URL:</strong> ${data.url}</p>
          <p class="result-classification"><strong>Classification:</strong> ${displayClassification}</p>
          <div class="result-probabilities">
              <p><strong>Confidence:</strong></p>
              ${createProbabilityBars(data.probabilities)}
          </div>
      </div>
  `;

  // Add to results container
  resultsContainer.appendChild(resultCard);

  // Scroll to results without interfering with the header
  window.scrollTo({
    top: resultsSection.offsetTop,
    behavior: "smooth"
  });

  // Refresh scan history if available
  setTimeout(() => {
    if (typeof loadScanHistory === "function") {
      loadScanHistory();
    }
  }, 1000);
}

/**
 * Create probability bars for displaying confidence levels
 */
function createProbabilityBars(probabilities) {
  if (!probabilities) return "<p>No probability data available</p>";

  let barsHtml = "";

  for (const [className, probability] of Object.entries(probabilities)) {
    const percentage = Math.round(probability * 100);

    // Normalize the class name for display
    let displayClassName = className;
    if (className.toLowerCase() === "phishing") {
      displayClassName = "Credential Phishing";
    } else if (className.toLowerCase() === "credential phishing") {
      displayClassName = "Credential Phishing";
    } else if (className.toLowerCase() === "malware distribution") {
      displayClassName = "Malware Distribution";
    } else {
      // Capitalize first letter
      displayClassName = className.charAt(0).toUpperCase() + className.slice(1);
    }

    barsHtml += `
      <div class="probability-item">
          <div class="probability-label">${displayClassName}</div>
          <div class="probability-bar-container">
              <div class="probability-bar" style="width: ${percentage}%"></div>
              <div class="probability-value">${percentage}%</div>
          </div>
      </div>
      `;
  }

  return barsHtml;
}

// ====== BATCH URL SCANNER ======

/**
 * Initialize the batch URL scanner
 */
function initializeBatchUrlScanner() {
  const batchScanForm = document.getElementById("batch-scan-form");
  const batchUrlInput = document.getElementById("batch-url-input");
  const batchScanButton = document.getElementById("batch-scan-button");
  const csvUploadForm = document.getElementById("csv-upload-form");
  const csvFileInput = document.getElementById("csv-file-input");

  // Check if we're on a page with the batch scanner
  if (!batchScanForm) return;

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
          return;
        }

        const submitButton = csvUploadForm.querySelector("button");
        submitButton.disabled = true;
        submitButton.textContent = "Scanning...";

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

          // Process and display results
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
        }
      };

      reader.readAsText(file);
    });
  }
}

/**
 * Process and display batch scan results
 */
function processBatchResults(results) {
  // Create a results section if it doesn't exist
  let resultsSection = document.getElementById("batch-results-section");

  if (!resultsSection) {
    resultsSection = document.createElement("section");
    resultsSection.id = "batch-results-section";
    resultsSection.className = "results-section";
    resultsSection.innerHTML = `
          <div class="container">
              <h2>Batch Scan Results</h2>
              <div id="batch-results-container" class="results-container"></div>
          </div>
      `;

    // Add after the features section
    const featuresSection = document.querySelector(".features");
    if (featuresSection) {
      featuresSection.after(resultsSection);
    } else {
      document.querySelector("main").appendChild(resultsSection);
    }
  }

  const batchResultsContainer = document.getElementById("batch-results-container");
  if (!batchResultsContainer) return;

  // Clear previous results
  batchResultsContainer.innerHTML = "";

  // Create table for results
  const table = document.createElement("table");
  table.className = "batch-results-table";

  // Add table header
  table.innerHTML = `
      <thead>
          <tr>
              <th>URL</th>
              <th>Classification</th>
              <th>Confidence</th>
              <th>Status</th>
          </tr>
      </thead>
      <tbody></tbody>
  `;

  const tbody = table.querySelector("tbody");

  // Add rows for each result
  results.forEach((result) => {
    const row = document.createElement("tr");

    if (result.error) {
      // Special handling for fetch errors
      let errorStatusClass = "status-error";
      let errorMessage = result.error;

      if (result.error.includes("Failed to fetch content")) {
        errorStatusClass = "status-fetch-error";
        errorMessage = "Failed to fetch content";
      }

      row.innerHTML = `
              <td>${result.url}</td>
              <td colspan="2">Error</td>
              <td class="${errorStatusClass}" title="${result.error}">${errorMessage}</td>
          `;
    } else {
      // Get highest probability class
      let highestProb = 0;
      let confidence = 0;

      if (result.probabilities) {
        for (const [className, probability] of Object.entries(result.probabilities)) {
          if (probability > highestProb) {
            highestProb = probability;
            confidence = Math.round(probability * 100);
          }
        }
      }

      // Determine status class
      let statusClass = "status-unknown";
      if (result.class_name) {
        const className = result.class_name.toLowerCase();
        if (className === "legitimate") {
          statusClass = "status-clean";
        } else if (className === "phishing" || className === "malware" || className === "malware distribution") {
          statusClass = "status-phishing";
        }
      }

      // Determine display name
      let displayName = result.class_name || "Unknown";
      let statusDisplay = result.class_name === "legitimate" ? "Clean" : result.class_name || "Unknown";

      row.innerHTML = `
              <td>${result.url}</td>
              <td>${displayName}</td>
              <td>${confidence}%</td>
              <td class="${statusClass}">${statusDisplay}</td>
          `;
    }

    tbody.appendChild(row);
  });

  batchResultsContainer.appendChild(table);

  // Scroll to results
  resultsSection.scrollIntoView({ behavior: "smooth" });
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
