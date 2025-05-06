/**
 * PhishR - Main JavaScript file
 * This file provides basic UI interaction for demonstration purposes.
 * Further functionality would be implemented as needed.
 */

// Wait for DOM to be fully loaded
document.addEventListener("DOMContentLoaded", function () {
  // Get form elements
  const scanForm = document.getElementById("scan-form");
  const urlInput = document.getElementById("url-input");
  const scanButton = document.getElementById("scan-button");
  const scanProgress = document.getElementById("scan-progress");
  const progressStatus = document.getElementById("progress-status");

  // Set initial state
  scanButton.textContent = "SCAN NOW";
  scanProgress.style.width = "100%";

  // Handle form submission
  scanForm.addEventListener("submit", function (event) {
    event.preventDefault();

    // Get URL input value
    const url = urlInput.value.trim();

    // Basic validation
    if (!url) {
      alert("Please enter a valid URL");
      return;
    }

    // Simulate scan process
    simulateScan();
  });

  // Simulate a scan process with progress updates
  function simulateScan() {
    // Reset UI
    scanProgress.style.width = "0%";
    progressStatus.textContent = "Initializing scan...";
    scanButton.textContent = "LOADING...";
    scanButton.disabled = true;

    // Simulate progress steps
    const steps = [
      { progress: 20, message: "20% Analyzing URL structure..." },
      { progress: 40, message: "40% Checking for malicious patterns..." },
      { progress: 60, message: "60% Validating content..." },
      { progress: 80, message: "80% Applying ML model..." },
      { progress: 100, message: "100% Detection Finished..." }
    ];

    let currentStep = 0;

    // Start progress simulation
    const progressInterval = setInterval(function () {
      if (currentStep < steps.length) {
        const step = steps[currentStep];
        scanProgress.style.width = step.progress + "%";
        progressStatus.textContent = step.message;
        currentStep++;
      } else {
        // Scan completed
        clearInterval(progressInterval);

        // Show results (already visible in the design)
        scanButton.textContent = "SCAN AGAIN";
        scanButton.disabled = false;

        // Reset would happen on a new scan
      }
    }, 800); // Update progress every 800ms for demo
  }
});
