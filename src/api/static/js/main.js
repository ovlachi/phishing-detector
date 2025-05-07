// Wait for DOM to be fully loaded
document.addEventListener("DOMContentLoaded", () => {
  // Get elements from the DOM
  const scanForm = document.getElementById("scan-form");
  const urlInput = document.getElementById("url-input");
  const scanButton = document.getElementById("scan-button");
  const resultsSection = document.getElementById("results-section");
  const resultsContainer = document.getElementById("results-container");
  const loadingSpinner = document.getElementById("loading-spinner");

  // Hide results section initially
  if (resultsSection) {
    resultsSection.style.display = "none";
  }

  // Handle form submission
  if (scanForm) {
    scanForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      // Get URL from input
      const url = urlInput.value.trim();

      // Validate URL
      if (!url) {
        showError("Please enter a URL");
        return;
      }

      try {
        new URL(url); // This will throw an error if URL is invalid
      } catch (err) {
        showError("Please enter a valid URL (including http:// or https://)");
        return;
      }

      // Show loading state
      if (scanButton) scanButton.disabled = true;
      if (loadingSpinner) loadingSpinner.style.display = "block";
      if (resultsContainer) resultsContainer.innerHTML = "";

      try {
        // Call API to scan URL
        const response = await fetch("/classify", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        // Display results
        displayResults(data);
      } catch (error) {
        showError("An error occurred while scanning the URL");
        console.error("Error scanning URL:", error);
      } finally {
        // Hide loading state
        if (scanButton) scanButton.disabled = false;
        if (loadingSpinner) loadingSpinner.style.display = "none";
      }
    });
  }

  // Function to display scan results
  function displayResults(data) {
    if (!resultsSection || !resultsContainer) return;

    // Show results section
    resultsSection.style.display = "block";

    // Clear previous results
    resultsContainer.innerHTML = "";

    if (data.error) {
      // Handle error
      const errorElement = document.createElement("div");
      errorElement.className = "result-error";
      errorElement.textContent = `Error: ${data.error}`;
      resultsContainer.appendChild(errorElement);
      return;
    }

    // Create result card
    const resultCard = document.createElement("div");
    resultCard.className = "result-card";

    // Determine result styling based on class - CASE INSENSITIVE COMPARISON
    let resultClass = "neutral";
    let resultIcon = "❓";
    let resultMessage = "Unknown";

    // Convert to lowercase for case-insensitive comparison
    const className = data.class_name ? data.class_name.toLowerCase() : "";

    if (className === "legitimate") {
      resultClass = "safe";
      resultIcon = "✅";
      resultMessage = "This URL appears to be legitimate";
    } else if (className === "credential phishing") {
      resultClass = "dangerous";
      resultIcon = "⚠️";
      resultMessage = "Warning: This URL may be a credential phishing attempt";
    } else if (className === "malware distribution") {
      resultClass = "dangerous";
      resultIcon = "🛑";
      resultMessage = "Danger: This URL may contain drive-by-download malware distribution";
    }

    // Add class to card
    resultCard.classList.add(resultClass);

    // Create HTML for result
    resultCard.innerHTML = `
          <div class="result-header">
              <span class="result-icon">${resultIcon}</span>
              <h3 class="result-title">${resultMessage}</h3>
          </div>
          <div class="result-details">
              <p class="result-url"><strong>URL:</strong> ${data.url}</p>
              <p class="result-classification"><strong>Classification:</strong> ${data.class_name}</p>
              <div class="result-probabilities">
                  <p><strong>Confidence:</strong></p>
                  ${createProbabilityBars(data.probabilities)}
              </div>
          </div>
      `;

    // Add to results container
    resultsContainer.appendChild(resultCard);

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: "smooth" });
  }

  // Function to create probability bars
  function createProbabilityBars(probabilities) {
    if (!probabilities) return "<p>No probability data available</p>";

    let barsHtml = "";

    for (const [className, probability] of Object.entries(probabilities)) {
      const percentage = Math.round(probability * 100);

      barsHtml += `
          <div class="probability-item">
              <div class="probability-label">${className}</div>
              <div class="probability-bar-container">
                  <div class="probability-bar" style="width: ${percentage}%"></div>
                  <div class="probability-value">${percentage}%</div>
              </div>
          </div>
          `;
    }

    return barsHtml;
  }

  // Function to show error messages
  function showError(message) {
    if (!resultsSection || !resultsContainer) return;

    // Show results section
    resultsSection.style.display = "block";

    // Display error
    resultsContainer.innerHTML = `
      <div class="error-message">
          <p>${message}</p>
      </div>
      `;
  }
});

// Batch URL Scanning and History functionality
document.addEventListener("DOMContentLoaded", () => {
  // Initialize scan history from localStorage
  const scanHistory = JSON.parse(localStorage.getItem("scanHistory") || "[]");

  // Elements for batch scanning
  const batchScanForm = document.getElementById("batch-scan-form");
  const batchUrlInput = document.getElementById("batch-url-input");
  const batchScanButton = document.getElementById("batch-scan-button");
  const csvUploadForm = document.getElementById("csv-upload-form");
  const csvFileInput = document.getElementById("csv-file-input");

  // Elements for scan history
  const scanHistoryBody = document.getElementById("scan-history-body");

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

  // Initialize batch scan functionality
  if (batchScanForm && batchUrlInput && batchScanButton) {
    // Setup URL count updating
    batchUrlInput.addEventListener("input", updateUrlCount);

    // Handle form submission
    batchScanForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      // Get URLs from input
      const urlLines = batchUrlInput.value
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);

      if (urlLines.length === 0) {
        alert("Please enter at least one URL");
        return;
      }

      if (urlLines.length > 10) {
        alert("Please enter no more than 10 URLs");
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
        alert(`The following URLs are invalid:\n${invalidUrls.join("\n")}\n\nPlease fix them and try again.`);
        return;
      }

      // Disable button and show loading state
      batchScanButton.disabled = true;
      batchScanButton.textContent = "Scanning...";

      try {
        // Call API for batch scanning
        const response = await fetch("/classify-batch", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: getCookie("access_token") // Get auth token from cookie
          },
          body: JSON.stringify({ urls: urlLines })
        });

        if (!response.ok) {
          throw new Error(`API error: ${response.status}`);
        }

        const data = await response.json();

        // Process and display results
        processBatchResults(data.results);

        // Add to scan history
        addToScanHistory(data.results);

        // Clear input
        batchUrlInput.value = "";
        updateUrlCount();
      } catch (error) {
        console.error("Error in batch scan:", error);
        alert("An error occurred during batch scanning. Please try again.");
      } finally {
        // Reset button state
        batchScanButton.disabled = false;
        batchScanButton.textContent = "SCAN";
      }
    });
  }

  // CSV upload functionality
  if (csvUploadForm && csvFileInput) {
    csvUploadForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const file = csvFileInput.files[0];
      if (!file) {
        alert("Please select a CSV file");
        return;
      }

      if (file.type !== "text/csv" && !file.name.endsWith(".csv")) {
        alert("Please upload a valid CSV file");
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
          alert("No URLs found in the CSV file");
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
          alert(`The following URLs in the CSV are invalid:\n${invalidUrls.join("\n")}\n\nPlease fix them and try again.`);
          return;
        }

        const submitButton = csvUploadForm.querySelector("button");
        submitButton.disabled = true;
        submitButton.textContent = "Scanning...";

        try {
          // Call API for batch scanning
          const response = await fetch("/classify-batch", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: getCookie("access_token")
            },
            body: JSON.stringify({ urls })
          });

          if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
          }

          const data = await response.json();

          // Process and display results
          processBatchResults(data.results);

          // Add to scan history
          addToScanHistory(data.results);

          // Clear input
          csvFileInput.value = "";
        } catch (error) {
          console.error("Error in CSV scan:", error);
          alert("An error occurred during CSV scanning. Please try again.");
        } finally {
          // Reset button state
          submitButton.disabled = false;
          submitButton.textContent = "Upload & Scan";
        }
      };

      reader.readAsText(file);
    });
  }

  // Process batch results and display them
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
        row.innerHTML = `
                  <td>${result.url}</td>
                  <td colspan="2">Error</td>
                  <td class="status-error">${result.error}</td>
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
          } else if (className === "phishing" || className === "malware") {
            statusClass = "status-phishing";
          }
        }

        row.innerHTML = `
                  <td>${result.url}</td>
                  <td>${result.class_name || "Unknown"}</td>
                  <td>${confidence}%</td>
                  <td class="${statusClass}">${result.class_name === "legitimate" ? "Clean" : result.class_name || "Unknown"}</td>
              `;
      }

      tbody.appendChild(row);
    });

    batchResultsContainer.appendChild(table);

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: "smooth" });
  }

  // Add results to scan history
  function addToScanHistory(results) {
    const timestamp = new Date().toISOString();
    const date = new Date().toLocaleDateString("en-US", {
      day: "2-digit",
      month: "short",
      year: "numeric"
    });

    // Process each result and add to history
    results.forEach((result) => {
      // Skip entries with errors
      if (result.error) return;

      // Create history entry
      const historyEntry = {
        url: result.url,
        ipAddress: generateRandomIP(), // In a real app, get from API
        hostingProvider: getRandomProvider(), // In a real app, get from API
        disposition: result.class_name === "legitimate" ? "Clean" : result.class_name || "Unknown",
        detectionDate: date,
        timestamp: timestamp,
        brand: "Unknown",
        source: "Batch Scan"
      };

      // Add to history array
      scanHistory.unshift(historyEntry);
    });

    // Limit history to 100 entries
    if (scanHistory.length > 100) {
      scanHistory.length = 100;
    }

    // Save to localStorage
    localStorage.setItem("scanHistory", JSON.stringify(scanHistory));

    // Update history display
    displayScanHistory();
  }

  // Display scan history
  function displayScanHistory() {
    if (!scanHistoryBody) return;

    // Clear existing rows
    scanHistoryBody.innerHTML = "";

    if (scanHistory.length === 0) {
      const emptyRow = document.createElement("tr");
      emptyRow.innerHTML = `<td colspan="7" class="empty-history">No scan history available yet</td>`;
      scanHistoryBody.appendChild(emptyRow);
      return;
    }

    // Add history entries
    scanHistory.forEach((entry) => {
      const row = document.createElement("tr");

      // Determine status class
      let statusClass = "status-unknown";
      if (entry.disposition) {
        const disposition = entry.disposition.toLowerCase();
        if (disposition === "clean") {
          statusClass = "status-clean";
        } else if (disposition === "phishing" || disposition === "malware") {
          statusClass = "status-phishing";
        }
      }

      row.innerHTML = `
              <td><a href="${entry.url}" target="_blank">${entry.url}</a></td>
              <td>${entry.ipAddress || "--"}</td>
              <td>${entry.hostingProvider || "--"}</td>
              <td class="${statusClass}">${entry.disposition}</td>
              <td>${entry.detectionDate}</td>
              <td>${entry.brand}</td>
              <td>${entry.source}</td>
          `;

      scanHistoryBody.appendChild(row);
    });
  }

  // Helper function to get cookie value
  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(";").shift();
    return null;
  }

  // Helper function to generate random IPs for demo purposes
  function generateRandomIP() {
    return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
  }

  // Helper function to get random provider for demo purposes
  function getRandomProvider() {
    const providers = ["Cloudflare, Inc.", "Microsoft Corporation", "Amazon Web Services", "DigitalOcean, LLC", "Google Cloud", "SEDO GmbH", "OVH SAS"];
    return providers[Math.floor(Math.random() * providers.length)];
  }

  // Initialize the URL count display
  if (batchUrlInput) {
    updateUrlCount();
  }

  // Initialize scan history display
  displayScanHistory();

  // Add sorting functionality to the history table
  const sortableHeaders = document.querySelectorAll(".sortable");
  if (sortableHeaders) {
    sortableHeaders.forEach((header) => {
      header.addEventListener("click", () => {
        const column = header.textContent.trim().replace("▼", "").replace("▲", "").trim();
        const isAscending = header.querySelector(".sort-icon").textContent === "▲";

        // Update sort icons
        document.querySelectorAll(".sort-icon").forEach((icon) => {
          icon.textContent = "▼";
        });

        header.querySelector(".sort-icon").textContent = isAscending ? "▼" : "▲";

        // Sort the history array
        scanHistory.sort((a, b) => {
          let valueA, valueB;

          if (column === "Detection Date") {
            valueA = new Date(a.timestamp);
            valueB = new Date(b.timestamp);
          } else {
            return 0; // Only sorting by date for now
          }

          if (isAscending) {
            return valueA > valueB ? -1 : 1;
          } else {
            return valueA < valueB ? -1 : 1;
          }
        });

        // Update display
        displayScanHistory();
      });
    });
  }

  // Also add single URL to history when using the main scan form
  const singleScanForm = document.getElementById("scan-form");
  const urlInput = document.getElementById("url-input");

  if (singleScanForm && urlInput) {
    const originalSubmit = singleScanForm.onsubmit;

    singleScanForm.addEventListener("submit", async function (e) {
      // Let the original handler run first
      if (originalSubmit) {
        const shouldPreventDefault = originalSubmit.call(this, e);
        if (shouldPreventDefault === false) {
          return;
        }
      }

      const url = urlInput.value.trim();

      try {
        const response = await fetch("/classify", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url })
        });

        if (response.ok) {
          const data = await response.json();

          // Add to history after a slight delay to ensure the main result display completes
          setTimeout(() => {
            const results = [data];
            addToScanHistory(results);
          }, 500);
        }
      } catch (error) {
        console.error("Error adding single URL to history:", error);
      }
    });
  }
});
