/**
 * PhishR - Login Page JavaScript
 * Handles form validation and submission for the login page
 */

// Wait for DOM to be fully loaded
document.addEventListener("DOMContentLoaded", function () {
  // Get form elements
  const loginForm = document.getElementById("login-form");

  // Check if we're on the login page
  if (!loginForm) {
    console.log("Login form not found, not on login page");
    return;
  }

  console.log("Login form found, initializing login page");

  // Get the input elements - updated to match your HTML
  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");
  const rememberCheckbox = document.getElementById("remember");

  // Debug - log what we found
  console.log("Username input:", usernameInput);
  console.log("Password input:", passwordInput);

  // Add error message container if it doesn't exist
  let errorContainer = document.querySelector(".login-error");
  if (!errorContainer) {
    errorContainer = document.createElement("div");
    errorContainer.className = "login-error";
    errorContainer.style.display = "none";
    errorContainer.style.color = "#FF3B30";
    errorContainer.style.marginBottom = "15px";
    loginForm.prepend(errorContainer);
  }

  // Handle form submission
  loginForm.addEventListener("submit", function (event) {
    // Since we're using a regular form submission now with action="/login" method="post",
    // we don't need to prevent the default behavior
    // event.preventDefault();

    console.log("Form submission detected");

    // Validate form fields
    const isValid = validateForm();

    if (!isValid) {
      event.preventDefault(); // Only prevent submission if validation fails
      console.log("Validation failed, stopping submission");
    } else {
      console.log("Form submission proceeding");
    }
  });

  // Validate form fields
  function validateForm() {
    let isValid = true;

    // Check if username input exists before validating
    if (usernameInput) {
      // Check username is not empty
      if (!usernameInput.value) {
        usernameInput.classList.add("invalid");
        showError("Please enter your username or email");
        isValid = false;
      } else {
        usernameInput.classList.remove("invalid");
      }
    } else {
      console.error("Username input not found");
      isValid = false;
    }

    // Check if password input exists before validating
    if (passwordInput) {
      // Check password is not empty
      if (!passwordInput.value) {
        passwordInput.classList.add("invalid");
        showError("Please enter your password");
        isValid = false;
      } else {
        passwordInput.classList.remove("invalid");
      }
    } else {
      console.error("Password input not found");
      isValid = false;
    }

    return isValid;
  }

  // Show error message
  function showError(message) {
    errorContainer.textContent = message;
    errorContainer.style.display = "block";
  }

  // Hide error message
  function hideError() {
    errorContainer.style.display = "none";
  }

  // Add styles for validation
  const style = document.createElement("style");
  style.textContent = `
      .form-group input.invalid {
          border-color: #FF3B30;
          background-color: rgba(255, 59, 48, 0.05);
      }
      
      .login-error {
          padding: 10px;
          background-color: rgba(255, 59, 48, 0.1);
          border-radius: 4px;
          margin-bottom: 15px;
      }
  `;
  document.head.appendChild(style);

  console.log("Login page initialization complete");
});
