/**
 * Phishing & Malware Detection - Main JavaScript
 * Handles UI interactions, authentication, and URL analysis
 */

// Authentication state
let isAuthenticated = false;

// Document ready function
document.addEventListener("DOMContentLoaded", function () {
  // Check authentication status
  checkAuth();

  // Initialize tabs if they exist
  if (document.querySelector(".tabs")) {
    initTabs();
  }
});

/**
 * Check authentication status
 */
function checkAuth() {
  // Check authentication status via API
  fetch("/auth-status", {
    method: "GET",
    credentials: "include"
  })
    .then((response) => {
      if (response.status === 200) {
        // User is authenticated
        isAuthenticated = true;
        return response.json();
      } else {
        // User is not authenticated
        isAuthenticated = false;
        throw new Error("Not authenticated");
      }
    })
    .then((data) => {
      // Update UI for authenticated user
      document.getElementById("user-status").textContent = `Logged in as ${data.username}`;
      document.getElementById("login-link").style.display = "none";
      document.getElementById("logout-link").style.display = "inline";

      // Update batch URL section if it exists
      if (document.getElementById("batch-auth-note")) {
        document.getElementById("batch-auth-note").style.display = "none";
        document.getElementById("batch-button").disabled = false;
      }
    })
    .catch((error) => {
      // Update UI for unauthenticated user
      document.getElementById("user-status").textContent = "Not logged in";
      document.getElementById("login-link").style.display = "inline";
      document.getElementById("logout-link").style.display = "none";

      // Update batch URL section if it exists
      if (document.getElementById("batch-auth-note")) {
        document.getElementById("batch-auth-note").style.display = "block";
        document.getElementById("batch-button").disabled = true;
      }
    });
}

/**
 * Initialize tab functionality
 */
function initTabs() {
  const tabs = document.querySelectorAll(".tab");

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => switchTab(index === 0 ? "single" : "batch"));
  });
}

/**
 * Switch between tabs
 */
function switchTab(tabName) {
  // Hide all tabs
  document.querySelectorAll(".tab-content").forEach((tab) => {
    tab.classList.remove("active");
  });
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.remove("active");
  });

  // Show selected tab
  document.getElementById(`${tabName}-tab`).classList.add("active");
  document.querySelector(`.tab:nth-child(${tabName === "single" ? 1 : 2})`).classList.add("active");
}

/**
 * Show loading spinner
 */
function showLoader(type) {
  document.getElementById(`${type}-loader`).style.display = "inline-block";
}

/**
 * Hide loading spinner
 */
function hideLoader(type) {
  document.getElementById(`${type}-loader`).style.display = "none";
}

/**
 * Analyze a single URL
 */
function analyzeSingleUrl() {
  const url = document.getElementById("url-input").value.trim();
  if (!url) {
    alert("Please enter a URL");
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
      console.error("Error:", error);
      alert("An error occurred. Please try again.");
    });
}

/**
 * Analyze multiple URLs
 */
function analyzeBatchUrls() {
  if (!isAuthenticated) {
    alert("Please login to use batch URL analysis");
    window.location.href = "/login";
    return;
  }

  const urlsText = document.getElementById("urls-input").value.trim();
  if (!urlsText) {
    alert("Please enter at least one URL");
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

  // Get token from cookie
  let token = "";
  const cookies = document.cookie.split(";");
  for (let cookie of cookies) {
    const [name, value] = cookie.trim().split("=");
    if (name === "access_token") {
      token = value.replace("Bearer ", "");
      break;
    }
  }

  fetch("/classify-batch", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify({ urls })
  })
    .then((response) => {
      if (response.status === 401) {
        // Unauthorized - token expired or invalid
        isAuthenticated = false;
        checkAuth();
        alert("Your session has expired. Please login again.");
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
        console.error("Error:", error);
        alert("An error occurred. Please try again.");
      }
    });
}

/**
 * Display classification results
 */
function displayResults(results) {
  const resultsDiv = document.getElementById("results");
  resultsDiv.style.display = "block";
  resultsDiv.innerHTML = "<h2>Results</h2>";

  results.forEach((result) => {
    const resultItem = document.createElement("div");
    resultItem.className = "result-item";

    if (result.error) {
      resultItem.innerHTML = `
                <div><strong>URL:</strong> ${result.url}</div>
                <div class="error">Error: ${result.error}</div>
            `;
    } else {
      let classStyle = "";
      if (result.class_name === "Legitimate") classStyle = "legitimate";
      else if (result.class_name === "Credential Phishing") classStyle = "phishing";
      else if (result.class_name === "Malware Distribution") classStyle = "malware";

      let probabilityBars = "";
      if (result.probabilities) {
        const barColors = {
          Legitimate: "#2ecc71",
          "Credential Phishing": "#e74c3c",
          "Malware Distribution": "#c0392b"
        };

        probabilityBars = '<div class="probability-bar">';
        for (const [className, prob] of Object.entries(result.probabilities)) {
          probabilityBars += `
                        <div class="probability-segment" 
                             style="width: ${prob * 100}%; background-color: ${barColors[className] || "#999"};"
                             title="${className}: ${(prob * 100).toFixed(1)}%">
                        </div>
                    `;
        }
        probabilityBars += "</div>";
      }

      resultItem.innerHTML = `
                <div><strong>URL:</strong> ${result.url}</div>
                <div><strong>Classification:</strong> <span class="${classStyle}">${result.class_name}</span></div>
                ${probabilityBars}
                <div style="margin-top: 5px;">
                    <strong>Probabilities:</strong>
                    ${Object.entries(result.probabilities || {})
                      .map(([className, prob]) => `${className}: ${(prob * 100).toFixed(1)}%`)
                      .join(", ")}
                </div>
            `;
    }

    resultsDiv.appendChild(resultItem);
  });
}
/**
 * Logout function
 */
