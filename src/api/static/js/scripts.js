/**
 * PhishR - Modern Phishing & Malware Detection Application
 * Main JavaScript File
 */

// Global State
let isAuthenticated = false;
let currentUser = null;

// Document ready function
document.addEventListener("DOMContentLoaded", function () {
  // Initialize authentication
  checkAuth();

  // Set up event listeners
  setupEventListeners();
});

/**
 * Set up various event listeners
 */
function setupEventListeners() {
  // User dropdown toggle
  const userDropdown = document.getElementById("user-dropdown");
  if (userDropdown) {
    userDropdown.addEventListener("click", function (e) {
      e.stopPropagation();
      toggleUserMenu();
    });
  }

  // Close dropdown when clicking outside
  document.addEventListener("click", function () {
    const userMenu = document.getElementById("user-menu");
    if (userMenu && userMenu.style.display === "block") {
      userMenu.style.display = "none";
    }
  });
}

/**
 * Toggle user dropdown menu
 */
function toggleUserMenu() {
  const userMenu = document.getElementById("user-menu");
  if (userMenu) {
    userMenu.style.display = userMenu.style.display === "block" ? "none" : "block";
  }
}

/**
 * Check authentication status via API
 */
function checkAuth() {
  fetch("/auth-status", {
    method: "GET",
    credentials: "include"
  })
    .then((response) => {
      if (response.status === 200) {
        return response.json().then((data) => {
          isAuthenticated = true;
          currentUser = data;
          updateAuthUI(true, data);
        });
      } else {
        isAuthenticated = false;
        currentUser = null;
        updateAuthUI(false);
        return Promise.reject("Not authenticated");
      }
    })
    .catch((error) => {
      console.log("Authentication check failed:", error);
    });
}

/**
 * Update UI based on authentication status
 */
function updateAuthUI(authenticated, userData = null) {
  const loginSection = document.getElementById("login-section");
  const userSection = document.getElementById("user-section");
  const batchAuthNote = document.getElementById("batch-auth-note");
  const batchButton = document.getElementById("batch-button");

  if (authenticated && userData) {
    // Show user section, hide login button
    if (loginSection) loginSection.style.display = "none";
    if (userSection) userSection.style.display = "flex";

    // Update user information
    const usernameElement = document.getElementById("username");
    const userAvatar = document.getElementById("user-avatar");

    if (usernameElement) usernameElement.textContent = userData.username;
    if (userAvatar) userAvatar.textContent = userData.username.charAt(0).toUpperCase();

    // Enable batch URL analysis
    if (batchAuthNote) batchAuthNote.style.display = "none";
    if (batchButton) batchButton.disabled = false;
  } else {
    // Show login button, hide user section
    if (loginSection) loginSection.style.display = "flex";
    if (userSection) userSection.style.display = "none";

    // Disable batch URL analysis
    if (batchAuthNote) batchAuthNote.style.display = "block";
    if (batchButton) batchButton.disabled = true;
  }
}

/**
 * Switch between tabs
 */
function switchTab(tabName) {
  // Get tabs and tab content elements
  const tabs = document.querySelectorAll(".tab");
  const tabContents = document.querySelectorAll(".tab-content");

  // Remove active class from all tabs and contents
  tabs.forEach((tab) => tab.classList.remove("active"));
  tabContents.forEach((content) => content.classList.remove("active"));

  // Add active class to selected tab and content
  if (tabName === "single") {
    tabs[0].classList.add("active");
    document.getElementById("single-tab").classList.add("active");
  } else if (tabName === "batch") {
    tabs[1].classList.add("active");
    document.getElementById("batch-tab").classList.add("active");
  }
}

/**
 * Show loader animation
 */
function showLoader(type) {
  const loader = document.getElementById(`${type}-loader`);
  if (loader) loader.style.display = "inline-block";
}

/**
 * Hide loader animation
 */
function hideLoader(type) {
  const loader = document.getElementById(`${type}-loader`);
  if (loader) loader.style.display = "none";
}

/**
 * Analyze a single URL
 */
function analyzeSingleUrl() {
  const urlInput = document.getElementById("url-input");
  const url = urlInput.value.trim();

  if (!url) {
    alert("Please enter a URL to analyze");
    return;
  }

  showLoader("single");

  fetch("/classify", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url })
  })
    .then((response) => response.json())
    .then((data) => {
      hideLoader("single");
      displayResults([data]);
    })
    .catch((error) => {
      hideLoader("single");
      console.error("Error analyzing URL:", error);
      alert("An error occurred while analyzing the URL. Please try again.");
    });
}

/**
 * Analyze multiple URLs
 */
function analyzeBatchUrls() {
  if (!isAuthenticated) {
    alert("Please log in to use batch URL analysis");
    window.location.href = "/login";
    return;
  }

  const urlsInput = document.getElementById("urls-input");
  const urlsText = urlsInput.value.trim();

  if (!urlsText) {
    alert("Please enter at least one URL to analyze");
    return;
  }

  const urls = urlsText
    .split("\n")
    .map((url) => url.trim())
    .filter((url) => url !== "");

  if (urls.length === 0) {
    alert("Please enter at least one valid URL");
    return;
  }

  showLoader("batch");

  fetch("/classify-batch", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + getAuthToken()
    },
    body: JSON.stringify({ urls })
  })
    .then((response) => {
      if (response.status === 401) {
        // Unauthorized - token expired or invalid
        isAuthenticated = false;
        updateAuthUI(false);
        alert("Your session has expired. Please log in again.");
        window.location.href = "/login";
        throw new Error("Unauthorized");
      }
      return response.json();
    })
    .then((data) => {
      hideLoader("batch");
      displayResults(data.results);
      console.log(`Processing time: ${data.processing_time.toFixed(2)} seconds`);
    })
    .catch((error) => {
      hideLoader("batch");
      if (error.message !== "Unauthorized") {
        console.error("Error analyzing URLs:", error);
        alert("An error occurred while analyzing the URLs. Please try again.");
      }
    });
}

/**
 * Get auth token from cookies
 */
function getAuthToken() {
  const cookies = document.cookie.split(";");
  for (let cookie of cookies) {
    const [name, value] = cookie.trim().split("=");
    if (name === "access_token") {
      return value.replace("Bearer ", "");
    }
  }
  return "";
}

/**
 * Display analysis results in the UI
 */
function displayResults(results) {
  const resultsContainer = document.getElementById("results-container");
  const resultsSection = document.getElementById("results");

  if (!resultsContainer || !resultsSection) return;

  // Clear previous results
  resultsContainer.innerHTML = "";

  // Show results section
  resultsSection.style.display = "block";

  // Process each result
  results.forEach((result) => {
    const resultItem = document.createElement("div");
    resultItem.className = "result-item";

    if (result.error) {
      // Display error
      resultItem.innerHTML = `
                <div class="result-url">${result.url}</div>
                <div class="error">
                    <i class="fa-solid fa-circle-exclamation"></i>
                    Error: ${result.error}
                </div>
            `;
    } else {
      // Determine classification style
      let badgeClass = "";
      let icon = "";

      if (result.class_name === "Legitimate") {
        badgeClass = "legitimate";
        icon = "fa-shield-check";
      } else if (result.class_name === "Credential Phishing") {
        badgeClass = "phishing";
        icon = "fa-fishing-hook";
      } else if (result.class_name === "Malware Distribution") {
        badgeClass = "malware";
        icon = "fa-virus";
      }

      // Create probability bar segments
      let probabilityBars = "";
      let probabilityDetails = "";

      if (result.probabilities) {
        const barColors = {
          Legitimate: "#22c55e",
          "Credential Phishing": "#ef4444",
          "Malware Distribution": "#f59e0b"
        };

        probabilityBars = '<div class="probability-bar">';
        probabilityDetails = '<div class="probability-details">';

        for (const [className, prob] of Object.entries(result.probabilities)) {
          const color = barColors[className] || "#6b7280";
          const percentage = (prob * 100).toFixed(1);

          probabilityBars += `
                        <div class="probability-segment" 
                             style="width: ${percentage}%; background-color: ${color};"
                             title="${className}: ${percentage}%">
                        </div>
                    `;

          probabilityDetails += `
                        <div class="probability-item">
                            <div class="probability-color" style="background-color: ${color};"></div>
                            ${className}: ${percentage}%
                        </div>
                    `;
        }

        probabilityBars += "</div>";
        probabilityDetails += "</div>";
      }

      // Create result HTML
      resultItem.innerHTML = `
                <div class="result-url">${result.url}</div>
                <div class="result-classification">
                    <span class="classification-badge ${badgeClass}">
                        <i class="fa-solid ${icon}"></i>
                        ${result.class_name}
                    </span>
                </div>
                ${probabilityBars}
                ${probabilityDetails}
            `;
    }

    resultsContainer.appendChild(resultItem);
  });

  // Scroll to results
  resultsSection.scrollIntoView({ behavior: "smooth" });
}
