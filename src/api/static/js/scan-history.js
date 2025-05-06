/**
 * PhishR - Scan History JavaScript
 * Handles interactions and functionality for the scan history page
 */

document.addEventListener("DOMContentLoaded", function () {
  // Elements
  const historyItems = document.querySelectorAll(".history-item");
  const prevBtn = document.querySelector(".prev-btn");
  const nextBtn = document.querySelector(".next-btn");
  const currentPageEl = document.querySelector(".current-page");

  // Make table rows clickable - redirect to the details page
  historyItems.forEach((item) => {
    item.addEventListener("click", function () {
      const url = this.querySelector(".url-link").textContent;

      // In a real app, this would navigate to a details page for the specific URL
      // For now, just redirect to authenticated.html as a placeholder
      window.location.href = "authenticated.html";
    });

    // Add cursor style to indicate clickable
    item.style.cursor = "pointer";

    // Randomly assign different probability types for demo purposes
    // This would be determined by the server in a real application
    const probabilityTypes = [
      { class: "probability-legitimate", text: "Legitimate" },
      { class: "probability-credential-phishing", text: "Credential Phishing" },
      { class: "probability-malware-distribution", text: "Malware Distribution" }
    ];

    // Apply to only a few entries for demonstration
    // The first few entries remain "Legitimate" as already set in the HTML
    if (Math.random() > 0.85 && item.querySelector(".probability-legitimate")) {
      const randomType = probabilityTypes[Math.floor(Math.random() * 3)];
      const probabilityElement = item.querySelector(".probability-legitimate");

      if (probabilityElement && randomType.class !== "probability-legitimate") {
        probabilityElement.className = randomType.class;
        probabilityElement.textContent = randomType.text;
      }
    }
  });

  // Pagination functionality - simulated for demo
  let currentPage = 1;
  const totalPages = 2;

  // Update pagination buttons state
  function updatePaginationState() {
    prevBtn.disabled = currentPage === 1;
    nextBtn.disabled = currentPage === totalPages;
    currentPageEl.textContent = currentPage;
  }

  // Handle previous button click
  prevBtn.addEventListener("click", function () {
    if (currentPage > 1) {
      currentPage--;
      updatePaginationState();
      // In a real app, you would load the previous page data here
    }
  });

  // Handle next button click
  nextBtn.addEventListener("click", function () {
    if (currentPage < totalPages) {
      currentPage++;
      updatePaginationState();
      // In a real app, you would load the next page data here

      // For demo: If on page 2, hide current items to simulate page change
      if (currentPage === 2) {
        // Show different data or hide current elements
        // In a real implementation, this would fetch new data from an API
        document.querySelector(".pagination-info").textContent = "Showing 16 - 17 of 17";
      }
    }
  });

  // Help Center Functionality
  const closeHelpBtn = document.querySelector(".close-help");
  const helpCenter = document.querySelector(".help-center");
  const helpItems = document.querySelectorAll(".help-item");

  // Close help center (in a real app this would toggle visibility)
  closeHelpBtn.addEventListener("click", function () {
    // For demo purposes, we'll just add a class
    helpCenter.classList.toggle("closed");

    // In a real app, this might also resize the main content
    document.querySelector(".dashboard-main").classList.toggle("full-width");
  });

  // Toggle help items
  helpItems.forEach((item) => {
    item.addEventListener("click", function () {
      this.classList.toggle("open");
    });
  });
});
