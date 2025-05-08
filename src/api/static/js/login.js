/**
 * PhishR - Login Page JavaScript
 * Handles form validation and submission for the login page
 */

// Wait for DOM to be fully loaded
document.addEventListener("DOMContentLoaded", function () {
  // Get form elements
  const loginForm = document.getElementById("login-form");
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");
  const rememberCheckbox = document.getElementById("remember");

  // Handle form submission
  loginForm.addEventListener("submit", function (event) {
    event.preventDefault();

    // Validate form fields
    const isValid = validateForm();

    if (isValid) {
      // Simulate login process
      simulateLogin();
    }
  });

  // Validate form fields
  function validateForm() {
    let isValid = true;

    // Check email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailInput.value)) {
      emailInput.classList.add("invalid");
      isValid = false;
    } else {
      emailInput.classList.remove("invalid");
    }

    // Check password is not empty
    if (!passwordInput.value) {
      passwordInput.classList.add("invalid");
      isValid = false;
    } else {
      passwordInput.classList.remove("invalid");
    }

    return isValid;
  }

  // Simulate login process
  function simulateLogin() {
    // Disable form inputs during "submission"
    const formElements = loginForm.elements;
    for (let i = 0; i < formElements.length; i++) {
      formElements[i].disabled = true;
    }

    // Get submit button and show loading state
    const submitButton = loginForm.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    submitButton.textContent = "Logging In...";

    // Simulate server response delay
    setTimeout(function () {
      // Redirect to authenticated dashboard
      window.location.href = "/dashboard";

      // For demo purposes, just reset the form
      // In real implementation, this code would not run due to the redirect
      submitButton.textContent = originalText;
      for (let i = 0; i < formElements.length; i++) {
        formElements[i].disabled = false;
      }
    }, 2000);
  }

  // Add styles for validation
  const style = document.createElement("style");
  style.textContent = `
      .form-group input.invalid {
          border-color: #FF3B30;
          background-color: rgba(255, 59, 48, 0.05);
      }
  `;
  document.head.appendChild(style);
});
