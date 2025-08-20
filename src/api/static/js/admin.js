/**
 * PhishR Admin Dashboard
 * Handles all admin functionality including:
 * - Dashboard statistics and charts
 * - User management
 * - Scan history
 * - Analytics
 */

// Global state
const state = {
  currentSection: "dashboard-section",
  usersList: {
    page: 1,
    pageSize: 10,
    search: "",
    filter: "all",
    totalPages: 1
  },
  scansList: {
    page: 1,
    pageSize: 10,
    risk: "all",
    totalPages: 1
  }
};

// Define fetchWithAuth at the global scope so it can be used everywhere
function fetchWithAuth(url, options = {}) {
  // Get token from cookie
  const getCookie = (name) => {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(";").shift();
    return null;
  };

  const token = getCookie("access_token");
  console.log(`Fetching ${url} with token: ${token ? token.substring(0, 20) + "..." : "missing"}`);

  // Set up headers with authentication
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  // Add Authorization header if token exists
  if (token) {
    headers["Authorization"] = token;
    console.log("Added Authorization header");
  } else {
    console.warn("No token found in cookies!");
  }

  console.log("Request headers:", headers);

  // Return the fetch with auth headers
  return fetch(url, {
    ...options,
    headers,
    credentials: "include" // Important: include credentials to send cookies
  });
}

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", function () {
  //Test check authentication
  testAuth().then((result) => console.log("Auth test result:", result));

  // Check authentication
  checkAuth()
    .then((isAuthenticated) => {
      if (!isAuthenticated) {
        window.location.href = "/login?redirect=admin";
        return;
      }

      // Set up navigation
      setupNavigation();

      // Load initial data
      loadDashboardData();

      // Set up event listeners
      setupEventListeners();
    })
    .catch((error) => {
      console.error("Authentication check failed:", error);
      window.location.href = "/login?redirect=admin";
    });
});

/**
 * Check if the user is authenticated and has admin privileges
 */
async function checkAuth() {
  try {
    // Use fetchWithAuth for consistency
    const response = await fetchWithAuth("/api/admin/check-auth", {
      method: "GET"
    });

    console.log("Auth check response:", response.status);

    if (!response.ok) {
      console.error("Auth check failed with status:", response.status);
      return false;
    }

    const data = await response.json();
    console.log("Auth check data:", data);

    if (!data.is_admin) {
      console.error("User is not an admin:", data.username);
    }

    return data.authenticated && data.is_admin;
  } catch (error) {
    console.error("Auth check error:", error);
    return false;
  }
}

/**
 * Set up section navigation
 */
function setupNavigation() {
  const navLinks = document.querySelectorAll(".sidebar-nav a[data-section]");

  navLinks.forEach((link) => {
    link.addEventListener("click", function (e) {
      e.preventDefault();

      // Get section id
      const sectionId = this.getAttribute("data-section");

      // Update active link
      navLinks.forEach((link) => link.classList.remove("active"));
      this.classList.add("active");

      // Show corresponding section
      document.querySelectorAll(".content-section").forEach((section) => {
        section.classList.remove("active");
      });
      document.getElementById(sectionId).classList.add("active");

      // Update current section
      state.currentSection = sectionId;

      // Load section data if needed
      if (sectionId === "users-section") {
        loadUsersList();
      } else if (sectionId === "scans-section") {
        loadScansList();
      } else if (sectionId === "analytics-section") {
        loadAnalyticsCharts();
      }
    });
  });
}

/**
 * Set up event listeners for various elements
 */
function setupEventListeners() {
  // User management
  document.getElementById("create-user-btn").addEventListener("click", showCreateUserModal);
  document.getElementById("user-form").addEventListener("submit", handleUserFormSubmit);
  document.getElementById("user-search").addEventListener("input", debounce(handleUserSearch, 500));
  document.getElementById("user-filter").addEventListener("change", handleUserFilter);

  // User pagination
  document.getElementById("prev-page").addEventListener("click", () => {
    if (state.usersList.page > 1) {
      state.usersList.page--;
      loadUsersList();
    }
  });

  document.getElementById("next-page").addEventListener("click", () => {
    if (state.usersList.page < state.usersList.totalPages) {
      state.usersList.page++;
      loadUsersList();
    }
  });

  // Scan pagination
  document.getElementById("scans-prev-page").addEventListener("click", () => {
    if (state.scansList.page > 1) {
      state.scansList.page--;
      loadScansList();
    }
  });

  document.getElementById("scans-next-page").addEventListener("click", () => {
    if (state.scansList.page < state.scansList.totalPages) {
      state.scansList.page++;
      loadScansList();
    }
  });

  // Risk filter
  document.getElementById("risk-filter").addEventListener("change", handleRiskFilter);

  // Modal close buttons
  document.querySelectorAll(".close-modal, .close-btn").forEach((button) => {
    button.addEventListener("click", function () {
      document.querySelectorAll(".modal").forEach((modal) => {
        modal.style.display = "none";
      });
    });
  });

  // Close modal when clicking outside
  window.addEventListener("click", function (event) {
    document.querySelectorAll(".modal").forEach((modal) => {
      if (event.target === modal) {
        modal.style.display = "none";
      }
    });
  });
}

/**
 * Load dashboard data and initialize charts
 */
async function loadDashboardData() {
  try {
    // Change this fetch call
    const response = await fetchWithAuth("/api/admin/dashboard", {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error("Failed to fetch dashboard data");
    }

    const data = await response.json();

    // Update summary stats
    document.getElementById("total-users").textContent = data.user_stats.total_users.toLocaleString();
    document.getElementById("new-users").textContent = data.user_stats.new_users_24h.toLocaleString();
    document.getElementById("premium-users").textContent = data.user_stats.premium_users.toLocaleString();
    document.getElementById("total-scans").textContent = data.scan_stats.total_scans.toLocaleString();

    // Load charts
    loadUserGrowthChart();
    loadScanResultsChart(data.scan_stats.risk_distribution);
  } catch (error) {
    console.error("Error loading dashboard data:", error);
    showNotification("Failed to load dashboard data", "error");
  }
}

/**
 * Load user growth chart
 */
async function loadUserGrowthChart() {
  try {
    const response = await fetchWithAuth("/api/admin/users/analytics", {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error("Failed to fetch user analytics");
    }

    const data = await response.json();

    // Create chart
    const ctx = document.getElementById("user-growth-chart").getContext("2d");

    // Destroy existing chart if it exists
    if (window.userGrowthChart) {
      window.userGrowthChart.destroy();
    }

    window.userGrowthChart = new Chart(ctx, {
      type: "line",
      data: {
        labels: data.user_growth.map((item) => item._id),
        datasets: [
          {
            label: "New Users",
            data: data.user_growth.map((item) => item.count),
            backgroundColor: "rgba(59, 130, 246, 0.2)",
            borderColor: "rgba(59, 130, 246, 1)",
            borderWidth: 2,
            tension: 0.3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            ticks: {
              precision: 0
            }
          }
        }
      }
    });
  } catch (error) {
    console.error("Error loading user growth chart:", error);
  }
}

/**
 * Load scan results chart
 */
function loadScanResultsChart(riskDistribution) {
  // Create chart
  const ctx = document.getElementById("scan-results-chart").getContext("2d");

  // Extract data
  const labels = riskDistribution.map((item) => item._id || "Unknown");
  const data = riskDistribution.map((item) => item.count);

  // Updated color mapping
  const backgroundColors = labels.map((label) => {
    const lowerLabel = (label || "").toLowerCase();

    if (lowerLabel.includes("legitimate") || lowerLabel.includes("clean") || lowerLabel.includes("safe")) {
      return "rgba(22, 163, 74, 0.8)"; // Green for Legitimate
    }
    if (lowerLabel.includes("credential phishing") || lowerLabel.includes("phishing")) {
      return "rgba(234, 88, 12, 0.8)"; // Orange for Credential Phishing
    }
    if (lowerLabel.includes("malware distribution") || lowerLabel.includes("malware")) {
      return "rgba(220, 38, 38, 0.8)"; // Red for Malware Distribution
    }
    if (lowerLabel.includes("suspicious") || lowerLabel.includes("unknown")) {
      // Added "unknown" for backward compatibility
      return "rgba(107, 114, 128, 0.8)"; // Grey for Suspicious
    }

    return "rgba(107, 114, 128, 0.8)"; // Grey for unrecognized categories
  });

  // Border colors
  const borderColors = labels.map((label) => {
    const lowerLabel = (label || "").toLowerCase();

    if (lowerLabel.includes("legitimate") || lowerLabel.includes("clean") || lowerLabel.includes("safe")) {
      return "rgba(22, 163, 74, 1)";
    }
    if (lowerLabel.includes("credential phishing") || lowerLabel.includes("phishing")) {
      return "rgba(234, 88, 12, 1)";
    }
    if (lowerLabel.includes("malware distribution") || lowerLabel.includes("malware")) {
      return "rgba(220, 38, 38, 1)";
    }
    if (lowerLabel.includes("suspicious") || lowerLabel.includes("unknown")) {
      return "rgba(107, 114, 128, 1)"; // Grey border for Suspicious
    }

    return "rgba(107, 114, 128, 1)";
  });

  // Destroy existing chart if it exists
  if (window.scanResultsChart) {
    window.scanResultsChart.destroy();
  }

  window.scanResultsChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: labels,
      datasets: [
        {
          data: data,
          backgroundColor: backgroundColors,
          borderColor: borderColors,
          borderWidth: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "right",
          labels: {
            usePointStyle: true,
            padding: 15
          }
        },
        tooltip: {
          callbacks: {
            label: function (context) {
              const label = context.label || "";
              const value = context.parsed || 0;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = Math.round((value / total) * 100);
              return `${label}: ${value} (${percentage}%)`;
            }
          }
        }
      }
    }
  });
}

/**
 * Load analytics charts
 */
async function loadAnalyticsCharts() {
  try {
    // Fetch user analytics
    const userResponse = await fetchWithAuth("/api/admin/users/analytics", {
      method: "GET"
    });

    if (!userResponse.ok) {
      throw new Error("Failed to fetch user analytics");
    }

    const userData = await userResponse.json();

    // Fetch scan analytics
    const scanResponse = await fetchWithAuth("/api/admin/scans/analytics", {
      method: "GET"
    });

    if (!scanResponse.ok) {
      throw new Error("Failed to fetch scan analytics");
    }

    const scanData = await scanResponse.json();

    // Load individual charts
    loadUserTrendsChart(userData.user_growth);
    loadPremiumConversionsChart(userData.premium_conversions);
    loadScanVolumeChart(scanData.scan_volume);
    loadRiskTrendsChart(scanData.risk_trends);
  } catch (error) {
    console.error("Error loading analytics charts:", error);
    showNotification("Failed to load analytics data", "error");
  }
}

/**
 * Load user trends chart
 */
function loadUserTrendsChart(userData) {
  const ctx = document.getElementById("user-trends-chart").getContext("2d");

  // Destroy existing chart if it exists
  if (window.userTrendsChart) {
    window.userTrendsChart.destroy();
  }

  window.userTrendsChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: userData.map((item) => item._id),
      datasets: [
        {
          label: "New Users",
          data: userData.map((item) => item.count),
          backgroundColor: "rgba(59, 130, 246, 0.2)",
          borderColor: "rgba(59, 130, 246, 1)",
          borderWidth: 2,
          tension: 0.3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            precision: 0
          }
        }
      }
    }
  });
}

/**
 * Load premium conversions chart
 */
function loadPremiumConversionsChart(conversionData) {
  const ctx = document.getElementById("premium-conversions-chart").getContext("2d");

  // Destroy existing chart if it exists
  if (window.premiumConversionsChart) {
    window.premiumConversionsChart.destroy();
  }

  window.premiumConversionsChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: conversionData.map((item) => item._id),
      datasets: [
        {
          label: "Premium Conversions",
          data: conversionData.map((item) => item.count),
          backgroundColor: "rgba(16, 185, 129, 0.7)",
          borderWidth: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            precision: 0
          }
        }
      }
    }
  });
}

/**
 * Load scan volume chart
 */
function loadScanVolumeChart(scanData) {
  const ctx = document.getElementById("scan-volume-chart").getContext("2d");

  // Destroy existing chart if it exists
  if (window.scanVolumeChart) {
    window.scanVolumeChart.destroy();
  }

  window.scanVolumeChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: scanData.map((item) => item._id),
      datasets: [
        {
          label: "Scan Volume",
          data: scanData.map((item) => item.count),
          backgroundColor: "rgba(124, 58, 237, 0.2)",
          borderColor: "rgba(124, 58, 237, 1)",
          borderWidth: 2,
          tension: 0.3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            precision: 0
          }
        }
      }
    }
  });
}

/**
 * Load risk trends chart
 */
function loadRiskTrendsChart(riskData) {
  // Process data - group by date and risk level
  const dates = [...new Set(riskData.map((item) => item._id.date))].sort();

  // Get unique risk levels
  const riskLevels = [...new Set(riskData.map((item) => item._id.risk))];

  // Create datasets for each risk level
  const datasets = riskLevels.map((risk) => {
    const color = risk === "High" ? "rgba(220, 38, 38, 1)" : risk === "Medium" ? "rgba(234, 88, 12, 1)" : "rgba(22, 163, 74, 1)";

    const bgColor = risk === "High" ? "rgba(220, 38, 38, 0.2)" : risk === "Medium" ? "rgba(234, 88, 12, 0.2)" : "rgba(22, 163, 74, 0.2)";

    return {
      label: `${risk} Risk`,
      data: dates.map((date) => {
        const match = riskData.find((item) => item._id.date === date && item._id.risk === risk);
        return match ? match.count : 0;
      }),
      backgroundColor: bgColor,
      borderColor: color,
      borderWidth: 2,
      tension: 0.3
    };
  });

  const ctx = document.getElementById("risk-trends-chart").getContext("2d");

  // Destroy existing chart if it exists
  if (window.riskTrendsChart) {
    window.riskTrendsChart.destroy();
  }

  window.riskTrendsChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: dates,
      datasets: datasets
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            precision: 0
          }
        }
      }
    }
  });
}

/**
 * Load users list with pagination and filtering
 */
async function loadUsersList() {
  try {
    const { page, pageSize, search, filter } = state.usersList;

    let url = `/api/admin/users?page=${page}&page_size=${pageSize}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (filter !== "all") url += `&filter=${encodeURIComponent(filter)}`;

    const response = await fetchWithAuth(url, {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error("Failed to fetch users");
    }

    const data = await response.json();

    // Update state
    state.usersList.totalPages = Math.ceil(data.total / data.page_size);

    // Update pagination info
    document.getElementById("page-info").textContent = `Page ${data.page} of ${state.usersList.totalPages}`;
    document.getElementById("prev-page").disabled = data.page <= 1;
    document.getElementById("next-page").disabled = data.page >= state.usersList.totalPages;

    // Render users table
    renderUsersTable(data.users);
  } catch (error) {
    console.error("Error loading users:", error);
    showNotification("Failed to load users", "error");
  }
}

/**
 * Render users table with data
 */
function renderUsersTable(users) {
  const tableBody = document.querySelector("#users-table tbody");
  tableBody.innerHTML = "";

  if (users.length === 0) {
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan="6" class="text-center">No users found</td>`;
    tableBody.appendChild(row);
    return;
  }

  users.forEach((user) => {
    const row = document.createElement("tr");

    // Format dates
    const registeredDate = user.created_at ? new Date(user.created_at).toLocaleDateString() : "N/A";

    // Determine status
    let statusClass = "";
    let statusText = "";

    if (!user.is_active) {
      statusClass = "status-inactive";
      statusText = "Inactive";
    } else if (user.premium) {
      statusClass = "status-premium";
      statusText = "Admin";
    } else {
      statusClass = "status-free";
      statusText = "Free";
    }

    row.innerHTML = `
      <td>${user.username || "N/A"}</td>
      <td>${user.email || "N/A"}</td>
      <td>${user.full_name || "N/A"}</td>
      <td>${registeredDate}</td>
      <td><span class="status-badge ${statusClass}">${statusText}</span></td>
      <td>
        <button class="action-btn view-btn" data-id="${user._id}">View</button>
        <button class="action-btn edit-btn" data-id="${user._id}">Edit</button>
        ${!user.is_admin ? `<button class="action-btn delete-btn" data-id="${user._id}">Deactivate</button>` : ""}
      </td>
    `;

    // Add event listeners
    row.querySelector(".view-btn").addEventListener("click", () => viewUser(user._id));
    row.querySelector(".edit-btn").addEventListener("click", () => editUser(user._id));

    if (!user.is_admin) {
      row.querySelector(".delete-btn").addEventListener("click", () => deactivateUser(user._id));
    }

    tableBody.appendChild(row);
  });
}

/**
 * Load scans list with pagination and filtering
 */
async function loadScansList() {
  try {
    const { page, pageSize, risk } = state.scansList;

    let url = `/api/admin/scans?page=${page}&page_size=${pageSize}`;
    if (risk !== "all") url += `&risk=${encodeURIComponent(risk)}`;

    console.log("Loading scans from URL:", url);

    const response = await fetchWithAuth(url, {
      method: "GET"
    });

    console.log("Scans response status:", response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Scans response error:", errorText);
      throw new Error("Failed to fetch scans");
    }

    const data = await response.json();
    console.log("Scans data received:", data);

    // Update state
    state.scansList.totalPages = Math.ceil(data.total / data.page_size);

    // Update pagination info
    document.getElementById("scans-page-info").textContent = `Page ${data.page} of ${state.scansList.totalPages}`;
    document.getElementById("scans-prev-page").disabled = data.page <= 1;
    document.getElementById("scans-next-page").disabled = data.page >= state.scansList.totalPages;

    // Render scans table
    renderScansTable(data.scans);
  } catch (error) {
    console.error("Error loading scans:", error);
    showNotification("Failed to load scans", "error");
  }
}

/**
 * Render scans table with data
 */
function renderScansTable(scans) {
  const tableBody = document.querySelector("#scans-table tbody");
  tableBody.innerHTML = "";

  if (scans.length === 0) {
    const row = document.createElement("tr");
    row.innerHTML = `<td colspan="6" class="text-center">No scans found</td>`;
    tableBody.appendChild(row);
    return;
  }

  scans.forEach((scan) => {
    const row = document.createElement("tr");

    // Format dates
    const scanDate = scan.scan_date ? new Date(scan.scan_date).toLocaleString() : "N/A";

    // Determine risk class based on your new mapping
    let riskClass = "";
    const riskType = scan.risk || "Unknown";

    // Updated risk class mapping
    switch (riskType.toLowerCase()) {
      case "legitimate":
      case "clean":
      case "safe":
        riskClass = "risk-low";
        break;
      case "credential phishing":
      case "phishing":
        riskClass = "risk-medium";
        break;
      case "malware distribution":
      case "malware":
        riskClass = "risk-high";
        break;
      case "suspicious":
      case "unknown": // Keep for backward compatibility
      default:
        riskClass = "risk-suspicious"; // Updated class name
        break;
    }

    // Format URL by truncating if too long
    const url = scan.url || "N/A";
    const displayUrl = url.length > 40 ? url.substring(0, 37) + "..." : url;

    row.innerHTML = `
      <td title="${url}">${displayUrl}</td>
      <td>${scan.username || "Anonymous"}</td>
      <td>${scanDate}</td>
      <td><span class="status-badge ${riskClass}">${scan.risk || "Suspicious"}</span></td>
      <td>${scan.confidence || "N/A"}%</td>
      <td>
        <button class="action-btn view-btn" data-id="${scan._id}">View</button>
      </td>
    `;

    // Add event listeners
    row.querySelector(".view-btn").addEventListener("click", () => viewScanDetails(scan._id));

    tableBody.appendChild(row);
  });
}

/**
 * View user details
 */
async function viewUser(userId) {
  try {
    const response = await fetchWithAuth(`/api/admin/users/${userId}`, {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error("Failed to fetch user details");
    }

    const data = await response.json();

    // Show user details in the modal
    const modal = document.getElementById("user-modal");
    const title = document.getElementById("user-modal-title");

    title.textContent = `User Details: ${data.user_details.username}`;

    // Disable form fields for view mode
    document.getElementById("username").value = data.user_details.username || "";
    document.getElementById("username").disabled = true;

    document.getElementById("email").value = data.user_details.email || "";
    document.getElementById("email").disabled = true;

    document.getElementById("full_name").value = data.user_details.full_name || "";
    document.getElementById("full_name").disabled = true;

    document.getElementById("password").value = "";
    document.getElementById("password").disabled = true;

    document.getElementById("premium").checked = data.user_details.premium || false;
    document.getElementById("premium").disabled = true;

    document.getElementById("is_active").checked = data.user_details.is_active !== false;
    document.getElementById("is_active").disabled = true;

    // Hide save button
    document.getElementById("save-user-btn").style.display = "none";

    // Show modal
    modal.style.display = "block";
  } catch (error) {
    console.error("Error fetching user details:", error);
    showNotification("Failed to fetch user details", "error");
  }
}

/**
 * Edit user
 */
async function editUser(userId) {
  try {
    const response = await fetchWithAuth(`/api/admin/users/${userId}`, {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error("Failed to fetch user details");
    }

    const data = await response.json();

    // Show user details in the modal
    const modal = document.getElementById("user-modal");
    const title = document.getElementById("user-modal-title");

    title.textContent = `Edit User: ${data.user_details.username}`;

    // Enable form fields for edit mode
    document.getElementById("user-id").value = data.user_details._id;

    document.getElementById("username").value = data.user_details.username || "";
    document.getElementById("username").disabled = false;

    document.getElementById("email").value = data.user_details.email || "";
    document.getElementById("email").disabled = false;

    document.getElementById("full_name").value = data.user_details.full_name || "";
    document.getElementById("full_name").disabled = false;

    document.getElementById("password").value = "";
    document.getElementById("password").disabled = false;

    document.getElementById("premium").checked = data.user_details.premium || false;
    document.getElementById("premium").disabled = false;

    document.getElementById("is_active").checked = data.user_details.is_active !== false;
    document.getElementById("is_active").disabled = false;

    // Show save button
    document.getElementById("save-user-btn").style.display = "block";

    // Show modal
    modal.style.display = "block";
  } catch (error) {
    console.error("Error fetching user details:", error);
    showNotification("Failed to fetch user details", "error");
  }
}

/**
 * Show create user modal
 */
function showCreateUserModal() {
  // Reset form
  document.getElementById("user-form").reset();
  document.getElementById("user-id").value = "";

  // Enable all fields
  document.getElementById("username").disabled = false;
  document.getElementById("email").disabled = false;
  document.getElementById("full_name").disabled = false;
  document.getElementById("password").disabled = false;
  document.getElementById("premium").disabled = false;
  document.getElementById("is_active").disabled = false;

  // Set modal title
  document.getElementById("user-modal-title").textContent = "Create New User";

  // Show save button
  document.getElementById("save-user-btn").style.display = "block";

  // Show modal
  document.getElementById("user-modal").style.display = "block";
}

/**
 * Handle user form submission (create or update)
 */
async function handleUserFormSubmit(e) {
  e.preventDefault();

  const userId = document.getElementById("user-id").value;
  const isCreate = !userId;

  // Get form data
  const formData = {
    username: document.getElementById("username").value,
    email: document.getElementById("email").value,
    full_name: document.getElementById("full_name").value,
    password: document.getElementById("password").value || undefined,
    premium: document.getElementById("premium").checked,
    is_active: document.getElementById("is_active").checked
  };

  // Remove empty password for updates
  if (!isCreate && !formData.password) {
    delete formData.password;
  }

  try {
    let response;

    if (isCreate) {
      // Create new user
      response = await fetchWithAuth("/api/admin/users/create", {
        method: "POST",
        body: JSON.stringify(formData)
      });
    } else {
      // Update existing user
      response = await fetchWithAuth(`/api/admin/users/${userId}`, {
        method: "PUT",
        body: JSON.stringify(formData)
      });
    }

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || "Operation failed");
    }

    // Show success message
    showNotification(isCreate ? "User created successfully" : "User updated successfully", "success");

    // Close modal
    document.getElementById("user-modal").style.display = "none";

    // Reload users list
    loadUsersList();
  } catch (error) {
    console.error("Error saving user:", error);
    showNotification(error.message || "Failed to save user", "error");
  }
}

/**
 * Deactivate a user
 */
async function deactivateUser(userId) {
  // Confirm deactivation
  if (!confirm("Are you sure you want to deactivate this user?")) {
    return;
  }

  try {
    const response = await fetchWithAuth(`/api/admin/users/${userId}`, {
      method: "DELETE"
    });

    if (!response.ok) {
      throw new Error("Failed to deactivate user");
    }

    // Show success message
    showNotification("User deactivated successfully", "success");

    // Reload users list
    loadUsersList();
  } catch (error) {
    console.error("Error deactivating user:", error);
    showNotification("Failed to deactivate user", "error");
  }
}

/**
 * View scan details
 */
async function viewScanDetails(scanId) {
  try {
    const response = await fetchWithAuth(`/api/admin/scans/${scanId}`, {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error("Failed to fetch scan details");
    }

    const scan = await response.json();

    // Show scan details in modal
    const scanDetails = document.getElementById("scan-details");

    // Format scan date
    const scanDate = scan.scan_date ? new Date(scan.scan_date).toLocaleString() : "N/A";

    // Format risk class
    const riskClass = scan.risk === "High" ? "risk-high" : scan.risk === "Medium" ? "risk-medium" : "risk-low";

    scanDetails.innerHTML = `
      <div class="scan-detail-group">
        <div class="scan-detail-label">URL</div>
        <div class="scan-detail-value">${scan.url || "N/A"}</div>
      </div>
      <div class="scan-detail-group">
        <div class="scan-detail-label">Scan Date</div>
        <div class="scan-detail-value">${scanDate}</div>
      </div>
      <div class="scan-detail-group">
        <div class="scan-detail-label">User</div>
        <div class="scan-detail-value">${scan.username || "Anonymous"}</div>
      </div>
      <div class="scan-detail-group">
        <div class="scan-detail-label">Risk Level</div>
        <div class="scan-detail-value">
          <span class="status-badge ${riskClass}">${scan.risk || "Unknown"}</span>
        </div>
      </div>
      <div class="scan-detail-group">
        <div class="scan-detail-label">Confidence</div>
        <div class="scan-detail-value">
          ${scan.confidence || "N/A"}%
          <div class="confidence-meter">
            <div class="confidence-fill" style="width: ${scan.confidence || 0}%"></div>
          </div>
        </div>
      </div>
    `;

    // Add detailed results if available
    if (scan.details) {
      scanDetails.innerHTML += `
        <div class="scan-detail-group">
          <div class="scan-detail-label">Classification</div>
          <div class="scan-detail-value">${scan.details.classification || "Unknown"}</div>
        </div>
        <div class="scan-detail-group">
          <div class="scan-detail-label">Features</div>
          <div class="scan-detail-value">
            <ul class="feature-list">
              ${Object.entries(scan.details.features || {})
                .map(([key, value]) => `<li><strong>${key}:</strong> ${value}</li>`)
                .join("")}
            </ul>
          </div>
        </div>
      `;
    }

    // Show modal
    document.getElementById("scan-modal").style.display = "block";
  } catch (error) {
    console.error("Error fetching scan details:", error);
    showNotification("Failed to fetch scan details", "error");
  }
}

/**
 * Handle user search
 */
function handleUserSearch() {
  state.usersList.search = document.getElementById("user-search").value;
  state.usersList.page = 1;
  loadUsersList();
}

/**
 * Handle user filter change
 */
function handleUserFilter() {
  state.usersList.filter = document.getElementById("user-filter").value;
  state.usersList.page = 1;
  loadUsersList();
}

/**
 * Handle risk filter change
 */
function handleRiskFilter() {
  state.scansList.risk = document.getElementById("risk-filter").value;
  state.scansList.page = 1;
  loadScansList();
}

/**
 * Show notification
 */
function showNotification(message, type = "info") {
  // Create notification element if it doesn't exist
  let notification = document.getElementById("notification");

  if (!notification) {
    notification = document.createElement("div");
    notification.id = "notification";
    document.body.appendChild(notification);

    // Add styles
    notification.style.position = "fixed";
    notification.style.bottom = "20px";
    notification.style.right = "20px";
    notification.style.padding = "12px 20px";
    notification.style.borderRadius = "4px";
    notification.style.color = "white";
    notification.style.fontWeight = "500";
    notification.style.boxShadow = "0 4px 12px rgba(0, 0, 0, 0.15)";
    notification.style.zIndex = "2000";
    notification.style.transition = "transform 0.3s ease-out, opacity 0.3s ease-out";
    notification.style.transform = "translateY(20px)";
    notification.style.opacity = "0";
  }

  // Set type-specific styles
  if (type === "success") {
    notification.style.backgroundColor = "#10b981";
  } else if (type === "error") {
    notification.style.backgroundColor = "#ef4444";
  } else {
    notification.style.backgroundColor = "#3b82f6";
  }

  // Set message
  notification.textContent = message;

  // Show notification
  notification.style.transform = "translateY(0)";
  notification.style.opacity = "1";

  // Hide after 3 seconds
  setTimeout(() => {
    notification.style.transform = "translateY(20px)";
    notification.style.opacity = "0";
  }, 3000);
}

/**
 * Test authentication to diagnose issues
 */
async function testAuth() {
  try {
    const response = await fetchWithAuth("/api/admin/simple-check", {
      method: "GET"
    });

    const data = await response.json();
    console.log("Simple check response:", data);

    return data;
  } catch (error) {
    console.error("Test auth error:", error);
    return { status: "error", error: error.message };
  }
}

/**
 * Helper function to debounce search input
 */
function debounce(func, wait) {
  let timeout;
  return function (...args) {
    clearTimeout(timeout);
    timeout = setTimeout(() => func.apply(this, args), wait);
  };
}
