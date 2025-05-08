// Wait for DOM to be fully loaded
document.addEventListener("DOMContentLoaded", () => {
  // Single URL scanner elements
  const scanForm = document.getElementById("scan-form");
  const urlInput = document.getElementById("url-input");
  const scanButton = document.getElementById("scan-button");
  const resultsSection = document.getElementById("results-section");
  const resultsContainer = document.getElementById("results-container");
  const loadingSpinner = document.getElementById("loading-spinner");

  // Batch scanner elements
  const batchScanForm = document.getElementById("batch-scan-form");
  const batchUrlInput = document.getElementById("batch-url-input");
  const batchScanButton = document.getElementById("batch-scan-button");
  const csvUploadForm = document.getElementById("csv-upload-form");
  const csvFileInput = document.getElementById("csv-file-input");

  // Scan history elements
  const scanHistoryBody = document.getElementById("scan-history-body");

  // Hide results section initially
  if (resultsSection) {
    resultsSection.style.display = "none";
  }

  // Initialize the UI based on authentication state
  function initializeUI() {
    // Check if user is logged in
    const isLoggedIn = !!getCookie("access_token");

    // Show/hide elements based on login state
    const authElements = document.querySelectorAll(".auth-only");
    authElements.forEach((el) => {
      el.style.display = isLoggedIn ? "block" : "none";
    });

    // If logged in and on the dashboard, load scan history
    if (isLoggedIn && window.location.pathname.includes("dashboard")) {
      loadScanHistory();
    }
  }

  // Handle form submission for single URL scanner
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
      if (resultsSection) resultsSection.style.display = "block";

      try {
        // Call API to scan URL
        const response = await fetch("/classify", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(getCookie("access_token") ? { Authorization: getCookie("access_token") } : {})
          },
          body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        // Display results
        displayResults(data);

        // If we're on the dashboard, reload history
        if (window.location.pathname.includes("dashboard")) {
          // Wait a bit for the database to update
          setTimeout(() => {
            loadScanHistory();
          }, 1000);
        }
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
    // Handle form submission for batch scanning
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

        // Clear input
        batchUrlInput.value = "";
        updateUrlCount();

        // Reload scan history
        setTimeout(() => {
          loadScanHistory();
        }, 1000);
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

          // Clear input
          csvFileInput.value = "";

          // Reload scan history
          setTimeout(() => {
            loadScanHistory();
          }, 1000);
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

  // Function to display single URL scan results
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
    } else if (className === "phishing") {
      resultClass = "dangerous";
      resultIcon = "⚠️";
      resultMessage = "Warning: This URL may be a phishing attempt";
    } else if (className === "malware") {
      resultClass = "dangerous";
      resultIcon = "🛑";
      resultMessage = "Danger: This URL may contain malware";
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

  // Load scan history from the API
  async function loadScanHistory() {
    if (!scanHistoryBody) return;

    try {
      // Call the API to get history
      const response = await fetch("/scan-history", {
        headers: {
          Authorization: getCookie("access_token")
        }
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      const data = await response.json();
      displayScanHistory(data.history || []);
    } catch (error) {
      console.error("Error loading scan history:", error);
      // Show error message in history table
      scanHistoryBody.innerHTML = `
            <tr>
                <td colspan="7" class="empty-history">
                    Error loading scan history. Please try refreshing the page.
                </td>
            </tr>
        `;
    }
  }

  // Display scan history
  function displayScanHistory(history) {
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

  // Helper function to get cookie value
  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(";").shift();
    return null;
  }

  // Initialize the URL count display
  if (batchUrlInput) {
    updateUrlCount();
  }

  // Add sorting functionality to the history table
  const sortableHeaders = document.querySelectorAll(".sortable");
  if (sortableHeaders) {
    sortableHeaders.forEach((header) => {
      header.addEventListener("click", async () => {
        const column = header.textContent.trim().replace("▼", "").replace("▲", "").trim();
        const isAscending = header.querySelector(".sort-icon").textContent === "▲";

        // Update sort icons
        document.querySelectorAll(".sort-icon").forEach((icon) => {
          icon.textContent = "▼";
        });

        header.querySelector(".sort-icon").textContent = isAscending ? "▼" : "▲";

        // Reload history - server-side sorting would be implemented here
        await loadScanHistory();
      });
    });
  }

  // Initialize the UI
  initializeUI();

  // If on dashboard page, load history
  if (window.location.pathname.includes("dashboard")) {
    loadScanHistory();
  }
});
