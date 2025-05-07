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
