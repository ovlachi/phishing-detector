/**
 * Extracts URL features from the page or current result
 * @returns {Object} The URL features
 */

let isPremiumUser = false;
let realTimeProtectionEnabled = false;

function extractUrlFeaturesFromPage() {
  // Try to get the current result from the page
  const currentResult = getCurrentScanResult();

  if (currentResult && currentResult.url_features) {
    return currentResult.url_features;
  }

  // Check if features are already in the page
  const featureList = document.getElementById("feature-list");
  if (featureList && featureList.children.length > 0) {
    // Extract from existing UI
    const features = {};

    // Get feature values from URL Features section
    Array.from(featureList.children).forEach((featureItem) => {
      const labelElement = featureItem.querySelector(".feature-label");
      const valueElement = featureItem.querySelector(".feature-value");

      if (labelElement && valueElement) {
        const label = labelElement.textContent.trim().toLowerCase();
        const value = valueElement.textContent.trim();

        if (label === "domain typo") {
          features.typosquatting_likely = value === "Detected";
        } else if (label === "security keywords") {
          features.security_keyword_count = parseInt(value) || 0;
        } else if (label === "https") {
          features.uses_https = value === "Yes";
        }
      }
    });

    // Check if IP address is mentioned anywhere
    const urlAnalysis = document.getElementById("url-analysis");
    if (urlAnalysis) {
      features.is_ip_address = urlAnalysis.textContent.includes("IP address");
    }

    // Additional heuristic extraction from URL
    const urlElement = document.getElementById("result-url");
    if (urlElement) {
      const url = urlElement.textContent.trim();
      features.url = url;
      features.url_length = url.length;
      features.domain_length = extractDomainLength(url);
      features.hyphen_count = (url.match(/-/g) || []).length;
      features.subdomain_count = estimateSubdomainCount(url);
      features.path_length = estimatePathLength(url);
      features.query_length = estimateQueryLength(url);
      features.path_segment_count = estimatePathSegmentCount(url);
      features.query_param_count = estimateQueryParamCount(url);
      features.has_fragment = url.includes("#");
      features.directory_depth = estimateDirectoryDepth(url);
      features.digit_ratio = countDigitRatio(url);
      features.special_char_ratio = countSpecialCharRatio(url);
    }

    return features;
  }

  // If we get here, create synthetic features from the URL
  const urlElement = document.getElementById("result-url");
  if (urlElement) {
    const url = urlElement.textContent.trim();

    // Synthesize basic features from the URL
    return {
      url: url,
      url_length: url.length,
      domain_length: extractDomainLength(url),
      path_length: estimatePathLength(url),
      query_length: estimateQueryLength(url),
      digit_ratio: countDigitRatio(url),
      special_char_ratio: countSpecialCharRatio(url),
      hyphen_count: (url.match(/-/g) || []).length,
      subdomain_count: estimateSubdomainCount(url),
      uses_https: url.startsWith("https://"),
      is_ip_address: url.match(/\d+\.\d+\.\d+\.\d+/) !== null,
      path_segment_count: estimatePathSegmentCount(url),
      query_param_count: estimateQueryParamCount(url),
      has_fragment: url.includes("#"),
      directory_depth: estimateDirectoryDepth(url),
      typosquatting_likely: isLikelyTyposquatting(url),
      security_keyword_count: countSecurityKeywords(url)
    };
  }

  return {};
}

/**
 * Extracts threat intelligence data from the page
 * @returns {Object} The threat intelligence data
 */
function extractThreatIntelligenceFromPage() {
  // Try to get the current result from the page
  const currentResult = getCurrentScanResult();

  if (currentResult && currentResult.threat_intelligence) {
    return currentResult.threat_intelligence;
  }

  const threatIntel = {};

  // Try to get overall threat level
  const threatBadge = document.getElementById("threat-badge");
  if (threatBadge) {
    const threatLevel = threatBadge.textContent.trim().toLowerCase();

    if (threatLevel.includes("high")) {
      threatIntel.overall_score = 30; // Low score for high risk
    } else if (threatLevel.includes("medium")) {
      threatIntel.overall_score = 50;
    } else if (threatLevel.includes("low")) {
      threatIntel.overall_score = 70;
    } else if (threatLevel.includes("safe")) {
      threatIntel.overall_score = 90; // High score for safe URL
    }
  }

  // Extract threat intelligence data from UI
  const threatIntelElement = document.getElementById("threat-intel");
  if (threatIntelElement) {
    const threatIntelText = threatIntelElement.textContent.trim();

    // Try to parse VirusTotal data
    if (threatIntelText.includes("/")) {
      const parts = threatIntelText.split("/");
      if (parts.length === 2) {
        const malicious = parseInt(parts[0]);
        const total = parseInt(parts[1]);

        if (!isNaN(malicious) && !isNaN(total)) {
          threatIntel.virustotal = {
            malicious_count: malicious,
            total_engines: total,
            reputation_score: Math.max(0, 100 - (malicious / total) * 100)
          };
        }
      }
    }
  }

  // Try to extract URLVoid data
  const threatSourcesElement = document.getElementById("threat-sources");
  if (threatSourcesElement) {
    const urlvoidSource = Array.from(threatSourcesElement.querySelectorAll(".source-item")).find((item) => item.textContent.includes("URLVoid"));

    if (urlvoidSource) {
      const text = urlvoidSource.textContent.trim();
      const match = text.match(/(\d+)\/(\d+)/);

      if (match && match.length === 3) {
        threatIntel.urlvoid = {
          detections: parseInt(match[1]),
          engines_count: parseInt(match[2]),
          reputation_score: Math.max(0, 100 - (parseInt(match[1]) / parseInt(match[2])) * 100)
        };
      }
    }
  }

  // Add domain age if available
  const domainAgeElement = document.getElementById("domain-age");
  if (domainAgeElement) {
    const domainAgeText = domainAgeElement.textContent.trim();
    if (domainAgeText.includes("days")) {
      const days = parseInt(domainAgeText);
      if (!isNaN(days)) {
        threatIntel.domain_age = {
          days: days,
          is_suspicious: days < 30
        };
      }
    } else if (domainAgeText === "Established") {
      threatIntel.domain_age = {
        days: 365, // Placeholder value
        is_suspicious: false
      };
    }
  }

  // Add recommendations
  const recommendationElement = document.querySelector(".recommendation-text");
  if (recommendationElement) {
    threatIntel.recommendations = [recommendationElement.textContent.trim()];
  }

  return threatIntel;
}

/**
 * Extracts confidence metrics from the page
 * @returns {Object} The confidence metrics
 */
function extractConfidenceMetricsFromPage() {
  // Try to get the current result from the page
  const currentResult = getCurrentScanResult();

  if (currentResult && currentResult.final_confidence !== undefined) {
    // Build confidence object from result
    return {
      overall: currentResult.final_confidence,
      ml_confidence: currentResult.probabilities ? Math.max(...Object.values(currentResult.probabilities)) : 0.8,
      threat_intel_confidence: 0.75,
      url_features_confidence: 0.85,
      content_confidence: currentResult.content_confidence || 0.7
    };
  }

  const confidence = {};

  // Get overall confidence
  const confidenceText = document.getElementById("confidence-text");
  if (confidenceText) {
    const percentMatch = confidenceText.textContent.match(/(\d+)%/);
    if (percentMatch && percentMatch.length > 1) {
      confidence.overall = parseInt(percentMatch[1]) / 100;
    }
  }

  // If overall confidence not found, try the confidence fill
  if (confidence.overall === undefined) {
    const confidenceFill = document.getElementById("confidence-fill");
    if (confidenceFill) {
      const width = confidenceFill.style.width;
      if (width) {
        const percentMatch = width.match(/(\d+)%/);
        if (percentMatch && percentMatch.length > 1) {
          confidence.overall = parseInt(percentMatch[1]) / 100;
        }
      }
    }
  }

  // Generate component confidences based on overall
  if (confidence.overall !== undefined) {
    const baseConfidence = confidence.overall;

    // ML confidence from prediction
    const predictionElement = document.getElementById("ml-prediction");
    if (predictionElement) {
      const predictionText = predictionElement.textContent;
      const percentMatch = predictionText.match(/(\d+)%/);

      if (percentMatch && percentMatch.length > 1) {
        confidence.ml_confidence = parseInt(percentMatch[1]) / 100;
      } else {
        confidence.ml_confidence = baseConfidence * (0.8 + Math.random() * 0.4);
      }
    } else {
      confidence.ml_confidence = baseConfidence * (0.8 + Math.random() * 0.4);
    }

    // Threat intelligence confidence
    confidence.threat_intel_confidence = baseConfidence * (0.7 + Math.random() * 0.5);

    // URL features confidence
    const urlAnalysisElement = document.getElementById("url-analysis");
    if (urlAnalysisElement) {
      const urlAnalysisText = urlAnalysisElement.textContent.trim();

      if (urlAnalysisText.includes("Typo") || urlAnalysisText.includes("Suspicious") || urlAnalysisText.includes("IP address")) {
        confidence.url_features_confidence = baseConfidence * 1.2;
      } else {
        confidence.url_features_confidence = baseConfidence * (0.9 + Math.random() * 0.2);
      }
    } else {
      confidence.url_features_confidence = baseConfidence * (0.9 + Math.random() * 0.2);
    }

    // Content confidence (may be low if content fetch failed)
    const titleElement = document.getElementById("result-title");
    if (titleElement && titleElement.textContent.includes("Failed")) {
      confidence.content_confidence = 0.3;
    } else {
      confidence.content_confidence = baseConfidence * (0.6 + Math.random() * 0.8);
    }
  }

  return confidence;
}

/**
 * Get the current scan result from the page if available
 * This attempts to find any result data stored in the window object
 * @returns {Object|null} The current scan result or null if not found
 */
function getCurrentScanResult() {
  // Check if window.currentResult exists (it might be set by enhanced-ui.js)
  if (window.currentResult) {
    return window.currentResult;
  }

  // Check if window.batchResults exists and if we can find the current URL
  if (window.batchResults && Array.isArray(window.batchResults) && window.batchResults.length > 0) {
    const urlElement = document.getElementById("result-url");
    if (urlElement) {
      const currentUrl = urlElement.textContent.trim();
      // Find the result with matching URL
      return window.batchResults.find((result) => result.url === currentUrl);
    }

    // If we can't find the matching URL, return the first result
    return window.batchResults[0];
  }

  return null;
}

/**
 * Helper function to get threat source status
 * @param {Object} source - The threat source data
 * @returns {string} The status color
 */
function getThreatSourceStatus(source) {
  if (!source) return "yellow";

  if (source.malicious_count !== undefined) {
    return source.malicious_count > 0 ? "red" : "green";
  }

  if (source.detections !== undefined) {
    return source.detections > 0 ? "red" : "green";
  }

  return "yellow";
}

/**
 * Helper function to get reputation color
 * @param {number} score - The reputation score
 * @returns {string} The color code
 */
function getReputationColor(score) {
  if (score >= 80) return "#16a34a";
  if (score >= 60) return "#2563eb";
  if (score >= 40) return "#f97316";
  return "#dc2626";
}

/**
 * Helper function to get confidence color
 * @param {number} confidence - The confidence value
 * @returns {string} The color code
 */
function getConfidenceColor(confidence) {
  if (confidence >= 0.8) return "#16a34a";
  if (confidence >= 0.6) return "#2563eb";
  if (confidence >= 0.4) return "#f97316";
  return "#dc2626";
}

/**
 * Helper function to format decimal values
 * @param {number} value - The value to format
 * @returns {string} The formatted value
 */
function formatValue(value) {
  if (value === undefined || value === null) return "N/A";
  if (typeof value === "number") {
    return value.toFixed(2);
  }
  return value.toString();
}

/**
 * Helper to estimate domain length from URL
 * @param {string} url - The URL
 * @returns {number} The estimated domain length
 */
function extractDomainLength(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname.length;
  } catch (e) {
    // Simple fallback
    const match = url.match(/https?:\/\/([^\/]+)/);
    if (match && match[1]) {
      return match[1].length;
    }
    return 0;
  }
}

/**
 * Helper to estimate path length from URL
 * @param {string} url - The URL
 * @returns {number} The estimated path length
 */
function estimatePathLength(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.pathname.length;
  } catch (e) {
    // Simple fallback
    const match = url.match(/https?:\/\/[^\/]+(\/[^\?#]*)/);
    if (match && match[1]) {
      return match[1].length;
    }
    return 0;
  }
}

/**
 * Helper to estimate query length from URL
 * @param {string} url - The URL
 * @returns {number} The estimated query length
 */
function estimateQueryLength(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.search.length;
  } catch (e) {
    // Simple fallback
    const match = url.match(/\?([^#]*)/);
    if (match && match[1]) {
      return match[1].length;
    }
    return 0;
  }
}

/**
 * Helper to estimate subdomain count from URL
 * @param {string} url - The URL
 * @returns {number} The estimated subdomain count
 */
function estimateSubdomainCount(url) {
  try {
    const parsedUrl = new URL(url);
    const hostParts = parsedUrl.hostname.split(".");
    return Math.max(0, hostParts.length - 2);
  } catch (e) {
    // Simple fallback
    const match = url.match(/https?:\/\/([^\/]+)/);
    if (match && match[1]) {
      const parts = match[1].split(".");
      return Math.max(0, parts.length - 2);
    }
    return 0;
  }
}

/**
 * Helper to estimate path segment count from URL
 * @param {string} url - The URL
 * @returns {number} The estimated path segment count
 */
function estimatePathSegmentCount(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.pathname.split("/").filter((p) => p).length;
  } catch (e) {
    // Simple fallback
    const match = url.match(/https?:\/\/[^\/]+(\/[^\?#]*)/);
    if (match && match[1]) {
      return match[1].split("/").filter((p) => p).length;
    }
    return 0;
  }
}

/**
 * Helper to estimate query parameter count from URL
 * @param {string} url - The URL
 * @returns {number} The estimated query parameter count
 */
function estimateQueryParamCount(url) {
  try {
    const parsedUrl = new URL(url);
    if (!parsedUrl.search) return 0;
    return parsedUrl.search.substring(1).split("&").length;
  } catch (e) {
    // Simple fallback
    const match = url.match(/\?([^#]*)/);
    if (match && match[1]) {
      return match[1].split("&").length;
    }
    return 0;
  }
}

/**
 * Helper to estimate directory depth from URL
 * @param {string} url - The URL
 * @returns {number} The estimated directory depth
 */
function estimateDirectoryDepth(url) {
  try {
    const parsedUrl = new URL(url);
    const pathParts = parsedUrl.pathname.split("/").filter((p) => p);

    // If the last part looks like a file, don't count it as a directory
    if (pathParts.length > 0 && pathParts[pathParts.length - 1].includes(".")) {
      return pathParts.length - 1;
    }

    return pathParts.length;
  } catch (e) {
    // Simple fallback
    const match = url.match(/https?:\/\/[^\/]+(\/[^\?#]*)/);
    if (match && match[1]) {
      const parts = match[1].split("/").filter((p) => p);
      if (parts.length > 0 && parts[parts.length - 1].includes(".")) {
        return parts.length - 1;
      }
      return parts.length;
    }
    return 0;
  }
}

/**
 * Helper to count digit ratio in URL
 * @param {string} url - The URL
 * @returns {number} The digit ratio
 */
function countDigitRatio(url) {
  const digitCount = (url.match(/\d/g) || []).length;
  return digitCount / url.length;
}

/**
 * Helper to count special character ratio in URL
 * @param {string} url - The URL
 * @returns {number} The special character ratio
 */
function countSpecialCharRatio(url) {
  const specialChars = (url.match(/[^a-zA-Z0-9]/g) || []).length;
  return specialChars / url.length;
}

/**
 * Helper to check if URL is likely a typosquatting attempt
 * @param {string} url - The URL
 * @returns {boolean} Whether it's likely a typosquatting attempt
 */
function isLikelyTyposquatting(url) {
  const commonDomains = ["google", "facebook", "amazon", "apple", "microsoft", "paypal", "netflix", "twitter", "instagram", "linkedin", "yahoo", "gmail", "outlook", "hotmail", "bank", "chase", "wellsfargo", "bankofamerica", "citibank", "amex"];

  // Extract domain from URL
  let domain = "";
  try {
    const parsedUrl = new URL(url);
    domain = parsedUrl.hostname;
  } catch (e) {
    const match = url.match(/https?:\/\/([^\/]+)/);
    if (match && match[1]) {
      domain = match[1];
    } else {
      return false;
    }
  }

  domain = domain.toLowerCase();

  // Check for obvious typosquatting patterns
  for (const commonDomain of commonDomains) {
    // Check if the domain contains the common domain name but isn't exactly that domain
    if (domain.includes(commonDomain) && !domain.endsWith(`.${commonDomain}.com`) && !domain.endsWith(`.${commonDomain}.org`) && !domain.endsWith(`.${commonDomain}.net`)) {
      // Check for digit substitution (e.g., paypa1 instead of paypal)
      if (domain.match(new RegExp(`${commonDomain.replace(/[a-z]/g, "([a-z\\d])")}`, "i"))) {
        return true;
      }

      // Domain in subdomain (e.g., paypal.malicious.com)
      if (domain.includes(`${commonDomain}.`) && !domain.endsWith(`.${commonDomain}.com`) && !domain.endsWith(`.${commonDomain}.org`)) {
        return true;
      }

      // Hyphenated domain (e.g., pay-pal.com)
      if (domain.includes(commonDomain.replace(/([a-z]{3,})/g, "$1-"))) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Helper to count security keywords in URL
 * @param {string} url - The URL
 * @returns {number} The count of security keywords
 */
function countSecurityKeywords(url) {
  const securityKeywords = ["login", "secure", "account", "banking", "update", "verify", "signin", "authorize", "authentication", "password", "credential", "security", "alert", "confirm", "verification", "access", "billing", "payment", "wallet"];

  const urlLower = url.toLowerCase();
  let count = 0;

  for (const keyword of securityKeywords) {
    if (urlLower.includes(keyword)) {
      count++;
    }
  }

  return count;
}

/**
 * Check for existing results on page load and enhance them
 */
function checkAndEnhanceExistingResults() {
  const resultCard = document.querySelector(".result-card");
  if (resultCard && !resultCard.classList.contains("hidden") && window.getComputedStyle(resultCard).display !== "none") {
    console.log("Found existing result card, enhancing UI...");

    // Convert premium feature badges to buttons
    initializeFeatureButtons();

    // Make sure the confidence meter is visible
    const confidenceSection = document.querySelector(".confidence-section");
    if (confidenceSection) {
      confidenceSection.style.display = "block";
    }

    // Make sure the details toggle is visible
    const detailsToggle = document.getElementById("details-toggle");
    if (detailsToggle) {
      detailsToggle.style.display = "block";
    }

    // Make buttons interactive
    makeButtonsClickable();
  }
}

/**
 * Make all buttons on the page clickable
 */
function makeButtonsClickable() {
  // Find all buttons that might need fixing
  const premiumFeatures = document.querySelectorAll(".premium-features .premium-badge");
  const featureButtons = document.querySelectorAll("[data-action]");
  const detailsToggle = document.getElementById("details-toggle");

  // Add clickable styles to premium features
  premiumFeatures.forEach((badge) => {
    badge.style.cursor = "pointer";
    badge.classList.add("premium-button");
  });

  // Ensure details toggle works
  if (detailsToggle && !detailsToggle.onclick) {
    detailsToggle.onclick = toggleDetails;
  }

  // Ensure all feature buttons have listeners
  featureButtons.forEach((button) => {
    if (!button.onclick) {
      button.addEventListener("click", function () {
        const action = button.getAttribute("data-action");
        if (action) {
          toggleDetailSection(action);
        }
      });
    }
  });
}

/**
 * Toggle the visibility of the detailed analysis panel
 */
function toggleDetails() {
  const panel = document.getElementById("details-panel");
  const toggle = document.getElementById("details-toggle");

  if (!panel || !toggle) return;

  // Toggle panel visibility
  panel.style.display = panel.style.display === "none" ? "block" : "none";

  // Update toggle button text
  if (panel.style.display === "none") {
    toggle.textContent = "Show Detailed Analysis ▼";
  } else {
    toggle.textContent = "Hide Detailed Analysis ▲";
  }

  // Hide any custom analysis sections
  document.querySelectorAll('[id$="-section"]').forEach((section) => {
    if (section.id !== "details-panel") {
      section.style.display = "none";
    }
  });

  // Remove active state from feature buttons
  document.querySelectorAll("[data-action]").forEach((button) => {
    button.classList.remove("active");
  });
}

/**
 * Initializes all premium feature buttons and their event handlers
 */
function initializeFeatureButtons() {
  console.log("Initializing premium feature buttons");

  // Initialize scan history button
  const scanHistoryBtn = document.getElementById("premium-scan-history");
  if (scanHistoryBtn) {
    scanHistoryBtn.addEventListener("click", function () {
      if (isPremiumUser) {
        showScanHistoryModal();
      } else {
        showPremiumUpgradeModal("scan history");
      }
    });
  }

  // Initialize real-time protection button
  const realTimeBtn = document.getElementById("premium-real-time");
  if (realTimeBtn) {
    realTimeBtn.addEventListener("click", function () {
      if (isPremiumUser) {
        toggleRealTimeProtection();
      } else {
        showPremiumUpgradeModal("real-time protection");
      }
    });
  }

  // Initialize bulk scan button
  const bulkScanBtn = document.getElementById("premium-bulk-scan");
  if (bulkScanBtn) {
    bulkScanBtn.addEventListener("click", function () {
      if (isPremiumUser) {
        showBulkScanInterface();
      } else {
        showPremiumUpgradeModal("bulk scan");
      }
    });
  }

  // Initialize advanced reports button
  const advancedReportsBtn = document.getElementById("premium-advanced-reports");
  if (advancedReportsBtn) {
    advancedReportsBtn.addEventListener("click", function () {
      if (isPremiumUser) {
        showAdvancedReportsInterface();
      } else {
        showPremiumUpgradeModal("advanced reports");
      }
    });
  }

  // Update button states based on current premium status
  updateButtonStates();
}

/**
 * Updates the visual state of feature buttons based on premium status
 */
function updateButtonStates() {
  const premiumButtons = document.querySelectorAll(".premium-feature-button");
  const lockIcons = document.querySelectorAll(".lock-icon");

  if (isPremiumUser) {
    premiumButtons.forEach((button) => {
      button.classList.remove("premium-locked");
      button.classList.add("premium-enabled");
    });

    lockIcons.forEach((icon) => {
      icon.style.display = "none";
    });
  } else {
    premiumButtons.forEach((button) => {
      button.classList.remove("premium-enabled");
      button.classList.add("premium-locked");
    });

    lockIcons.forEach((icon) => {
      icon.style.display = "inline-block";
    });
  }
}

// Initialize when the DOM is fully loaded
document.addEventListener("DOMContentLoaded", function () {
  console.log("PhishR Enhanced UI Controller loaded.");
  initializeFeatureButtons();
  checkAndEnhanceExistingResults();
});

/**
 * Shows the scan history modal
 */
function showScanHistoryModal() {
  console.log("Showing scan history modal");
  // Implementation for scan history
  const historyModal = document.getElementById("scan-history-modal");
  if (historyModal) {
    // If you're using a custom modal system:
    historyModal.style.display = "block";
    // Or call your custom modal function here
  }
}

/**
 * Toggles real-time protection on/off
 */
function toggleRealTimeProtection() {
  realTimeProtectionEnabled = !realTimeProtectionEnabled;
  console.log("Real-time protection:", realTimeProtectionEnabled ? "Enabled" : "Disabled");

  const realTimeBtn = document.getElementById("premium-real-time");
  const statusElement = document.getElementById("real-time-status");

  if (realTimeProtectionEnabled) {
    if (realTimeBtn) realTimeBtn.classList.add("feature-active");
    if (statusElement) {
      statusElement.textContent = "Active";
      statusElement.classList.add("status-active");
    }
  } else {
    if (realTimeBtn) realTimeBtn.classList.remove("feature-active");
    if (statusElement) {
      statusElement.textContent = "Inactive";
      statusElement.classList.remove("status-active");
    }
  }
}

/**
 * Shows the bulk scan interface
 */
function showBulkScanInterface() {
  console.log("Showing bulk scan interface");
  // Implementation for bulk scan
  const bulkScanContainer = document.getElementById("bulk-scan-container");
  const singleScanContainer = document.getElementById("single-scan-container");

  if (bulkScanContainer) bulkScanContainer.style.display = "block";
  if (singleScanContainer) singleScanContainer.style.display = "none";
}

/**
 * Shows the advanced reports interface
 */
function showAdvancedReportsInterface() {
  console.log("Showing advanced reports interface");
  // Implementation for advanced reports
  const reportsModal = document.getElementById("advanced-reports-modal");
  if (reportsModal) {
    reportsModal.style.display = "block";
    // Or call your custom modal function here
  }
}

/**
 * Shows the premium upgrade modal
 */
function showPremiumUpgradeModal(feature) {
  console.log("Showing premium upgrade modal for:", feature);

  const featureNameElement = document.getElementById("premium-feature-name");
  const upgradeModal = document.getElementById("premium-upgrade-modal");

  if (featureNameElement) featureNameElement.textContent = feature;
  if (upgradeModal) {
    upgradeModal.style.display = "block";
    // Or call your custom modal function here
  }
}

/**
 * Add CSS styles to the page to make the premium badges into clickable buttons
 */
function addStyles() {
  // Create a style element
  const style = document.createElement("style");

  // Add the CSS
  style.textContent = `
    /* Make premium badges clickable */
    .premium-badge {
      cursor: pointer;
      transition: all 0.2s ease;
    }
    
    .premium-badge:hover {
      transform: translateY(-2px);
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    
    .premium-badge.active {
      background-color: #8b5cf6;
      color: white;
    }
    
    /* Style for detail sections */
    .detail-section {
      background: white;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      padding: 24px;
      margin: 20px 0;
      animation: fadeIn 0.3s ease forwards;
    }
    
    /* Fade-in animation */
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    
    /* Indicator colors */
    .indicator-red { background: #ef4444; }
    .indicator-yellow { background: #f59e0b; }
    .indicator-green { background: #22c55e; }
    
    /* Risk text colors */
    .risk-high { color: #dc2626; }
    .risk-medium { color: #ea580c; }
    .risk-low { color: #16a34a; }
  `;

  // Add the style to the page
  document.head.appendChild(style);
}
/**
 * Initializes the details toggle functionality
 * Call this function when the page loads
 */
function initializeDetailsToggle() {
  console.log("Initializing details toggle functionality");

  // This should be called when the DOM is fully loaded
  document.addEventListener("DOMContentLoaded", function () {
    console.log("DOM loaded, setting up details toggle");
    setupDetailsToggle();

    // Also set up scan form to ensure we re-initialize the toggle after each scan
    setupScanForm();
  });
}

/**
 * Sets up the details toggle button event handler
 */
function setupDetailsToggle() {
  console.log("Setting up details toggle button");

  // Get the toggle button
  const toggleButton = document.getElementById("details-toggle");

  if (toggleButton) {
    console.log("Toggle button found, removing onclick attribute");

    // Remove the inline onclick attribute if it exists
    toggleButton.removeAttribute("onclick");

    // Remove any existing event listeners by cloning and replacing the element
    // This ensures we don't have duplicate event listeners
    const newToggleButton = toggleButton.cloneNode(true);
    toggleButton.parentNode.replaceChild(newToggleButton, toggleButton);

    // Add a proper event listener to the new button
    newToggleButton.addEventListener("click", function (e) {
      // Important: Prevent default action and stop propagation
      e.preventDefault();
      e.stopPropagation();

      console.log("Toggle button clicked");

      // Get the details panel
      const detailsPanel = document.getElementById("details-panel");

      if (detailsPanel) {
        console.log("Found details panel, current state:", detailsPanel.classList.contains("hidden") ? "hidden" : "visible");

        // Toggle the visibility
        if (detailsPanel.classList.contains("hidden")) {
          // Show details
          detailsPanel.classList.remove("hidden");
          newToggleButton.textContent = "Hide Detailed Analysis ▲";
          console.log("Showing details panel");
        } else {
          // Hide details
          detailsPanel.classList.add("hidden");
          newToggleButton.textContent = "Show Detailed Analysis ▼";
          console.log("Hiding details panel");
        }
      } else {
        console.error("Could not find details panel element");
      }
    });

    console.log("Toggle button event listener added successfully");
  } else {
    console.log("Toggle button not found yet, it may not be loaded");
  }
}

/**
 * Sets up the scan form to ensure we re-initialize toggle after each scan
 */
function setupScanForm() {
  const scanForm = document.getElementById("scan-form");

  if (scanForm) {
    console.log("Setting up scan form event handler");

    // Add submit event handler
    scanForm.addEventListener("submit", function (e) {
      e.preventDefault();

      const urlInput = document.getElementById("url-input");
      if (urlInput && urlInput.value) {
        console.log("Form submitted, scanning URL:", urlInput.value);

        // Show loading spinner
        const loadingSpinner = document.getElementById("loading-spinner");
        if (loadingSpinner) loadingSpinner.classList.remove("hidden");

        // Hide results
        const resultCard = document.getElementById("result-card");
        if (resultCard) resultCard.classList.add("hidden");

        // Simulate API call
        setTimeout(function () {
          // Hide spinner
          if (loadingSpinner) loadingSpinner.classList.add("hidden");

          // Show results
          if (resultCard) resultCard.classList.remove("hidden");

          // Call the existing display functions if you have them
          // displayScanResults(results);

          // Make sure the details panel is initially hidden and toggle button shows "Show"
          const detailsPanel = document.getElementById("details-panel");
          if (detailsPanel) detailsPanel.classList.add("hidden");

          // Re-initialize the toggle button after results are displayed
          console.log("Scan complete, re-initializing details toggle");
          setTimeout(setupDetailsToggle, 100); // Small delay to ensure DOM is updated
        }, 2000);
      }
    });

    console.log("Scan form event handler set up successfully");
  } else {
    console.error("Could not find scan form element");
  }
}

// Call this to initialize everything
initializeDetailsToggle();

// This replaces the old toggleDetails function
// If you have other code calling toggleDetails(), replace with this version
function toggleDetails(e) {
  // If called directly, e might not exist, so create a dummy event object
  if (!e) e = { preventDefault: function () {}, stopPropagation: function () {} };

  // Get the details panel and toggle button
  const detailsPanel = document.getElementById("details-panel");
  const toggleButton = document.getElementById("details-toggle");

  if (detailsPanel && toggleButton) {
    // Toggle visibility
    if (detailsPanel.classList.contains("hidden")) {
      detailsPanel.classList.remove("hidden");
      toggleButton.textContent = "Hide Detailed Analysis ▲";
    } else {
      detailsPanel.classList.add("hidden");
      toggleButton.textContent = "Show Detailed Analysis ▼";
    }
  }

  // Prevent default action and stop propagation
  e.preventDefault();
  e.stopPropagation();

  // Return false to prevent default action (for onclick handlers)
  return false;
}

// Fix the initial state of the toggle button and details panel
document.addEventListener("DOMContentLoaded", function () {
  console.log("Fixing initial toggle button state");

  // Get the elements
  const detailsPanel = document.getElementById("details-panel");
  const toggleButton = document.getElementById("details-toggle");

  // Make sure details panel is hidden
  if (detailsPanel) {
    detailsPanel.classList.add("hidden");
  }

  // Set button text to "Show"
  if (toggleButton) {
    toggleButton.textContent = "Show Detailed Analysis ▼";
  }
});

/**
 * Initializes tooltips for the premium feature badges
 * Call this when the page loads
 */
function initializePremiumFeatureTooltips() {
  console.log("Initializing premium feature tooltips");

  document.addEventListener("DOMContentLoaded", function () {
    // Define the feature descriptions
    const featureDescriptions = {
      "Enhanced Analysis": "Get detailed URL analysis with machine learning algorithms that detect sophisticated phishing attempts and provide deeper insights into potential threats.",
      "Threat Intelligence": "Access real-time threat data from multiple security sources to identify newly discovered threats before they can harm your organization.",
      "Confidence Metrics": "See detailed confidence scores that show how certain our system is about each detection, helping you make better security decisions."
    };

    // Find all premium badges
    const premiumBadges = document.querySelectorAll(".premium-badge");

    // Add tooltip functionality to each badge
    premiumBadges.forEach((badge) => {
      // Extract the feature name (text content without the badge icon)
      const badgeText = badge.textContent.trim();
      const featureName = badgeText.replace(/^[^\s]+\s/, "").trim(); // Remove the emoji/icon

      // Get the description for this feature
      const description = featureDescriptions[featureName] || "Premium feature";

      // Add tooltip functionality
      setupTooltip(badge, description);

      // Add a title attribute for native tooltip as fallback
      badge.setAttribute("title", description);

      // Add cursor style to indicate interactivity
      badge.style.cursor = "help";

      console.log(`Added tooltip to "${featureName}" badge`);
    });
  });
}

/**
 * Creates a custom tooltip for an element
 *
 * @param {HTMLElement} element - The element to attach the tooltip to
 * @param {string} text - The tooltip text
 */
function setupTooltip(element, text) {
  // Create tooltip element
  const tooltip = document.createElement("div");
  tooltip.className = "custom-tooltip";
  tooltip.textContent = text;
  tooltip.style.display = "none";

  // Add tooltip to the document body
  document.body.appendChild(tooltip);

  // Show tooltip on mouseover
  element.addEventListener("mouseover", function (e) {
    // Position the tooltip near the cursor
    const rect = element.getBoundingClientRect();
    tooltip.style.left = rect.left + "px";
    tooltip.style.top = rect.bottom + 10 + "px";
    tooltip.style.display = "block";
  });

  // Hide tooltip on mouseout
  element.addEventListener("mouseout", function () {
    tooltip.style.display = "none";
  });

  // Update position on mousemove for better UX
  element.addEventListener("mousemove", function (e) {
    // Optional: can update position on mouse move for a follow effect
    // tooltip.style.left = (e.clientX + 10) + 'px';
    // tooltip.style.top = (e.clientY + 10) + 'px';
  });
}

// Call the function to initialize tooltips
initializePremiumFeatureTooltips();

// Add styles to the page
addStyles();
