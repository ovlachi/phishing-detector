/**
 * PhishR - Registration Page JavaScript
 * Handles form validation for the registration page
 */

// Wait for DOM to be fully loaded
document.addEventListener("DOMContentLoaded", function () {
  // Get form elements
  const registerForm = document.getElementById("register-form");
  const usernameInput = document.getElementById("username");
  const emailInput = document.getElementById("email");
  const fullNameInput = document.getElementById("full_name");
  const passwordInput = document.getElementById("password");
  const confirmPasswordInput = document.getElementById("confirm-password");
  const termsCheckbox = document.getElementById("terms");

  // Check if we're on the registration page
  if (!registerForm) {
    console.log("Register form not found, not on registration page");
    return;
  }

  console.log("Register form found, initializing registration page");

  // Get password requirement elements
  const lengthCheck = document.getElementById("length-check");
  const uppercaseCheck = document.getElementById("uppercase-check");
  const numberCheck = document.getElementById("number-check");
  const specialCheck = document.getElementById("special-check");

  // Add error message container if it doesn't exist
  let errorContainer = document.querySelector(".register-error");
  if (!errorContainer) {
    errorContainer = document.createElement("div");
    errorContainer.className = "register-error";
    errorContainer.style.display = "none";
    errorContainer.style.color = "#FF3B30";
    errorContainer.style.marginBottom = "15px";
    registerForm.prepend(errorContainer);
  }

  // Add event listener for password input
  if (passwordInput) {
    passwordInput.addEventListener("input", function () {
      validatePassword(this.value);
    });
  }

  // Add event listener for confirm password input
  if (confirmPasswordInput) {
    confirmPasswordInput.addEventListener("input", function () {
      validatePasswordMatch();
    });
  }

  // Handle form submission
  registerForm.addEventListener("submit", function (event) {
    // Validate all fields before submitting
    const isValid = validateForm();

    if (!isValid) {
      event.preventDefault(); // Only prevent submission if validation fails
      console.log("Validation failed, stopping submission");
    } else {
      console.log("Form submission proceeding to server");
      // Let the form submit naturally to the server - no preventDefault()
    }
  });

  // Validate password requirements
  function validatePassword(password) {
    // Check length (8+ characters)
    if (password.length >= 8) {
      lengthCheck.classList.add("valid");
    } else {
      lengthCheck.classList.remove("valid");
    }

    // Check for uppercase letter
    if (/[A-Z]/.test(password)) {
      uppercaseCheck.classList.add("valid");
    } else {
      uppercaseCheck.classList.remove("valid");
    }

    // Check for number
    if (/[0-9]/.test(password)) {
      numberCheck.classList.add("valid");
    } else {
      numberCheck.classList.remove("valid");
    }

    // Check for special character
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      specialCheck.classList.add("valid");
    } else {
      specialCheck.classList.remove("valid");
    }

    // Check confirm password if it has a value
    if (confirmPasswordInput && confirmPasswordInput.value) {
      validatePasswordMatch();
    }
  }

  // Validate that passwords match
  function validatePasswordMatch() {
    if (!confirmPasswordInput || !passwordInput) return false;

    if (passwordInput.value === confirmPasswordInput.value) {
      confirmPasswordInput.classList.remove("invalid");
      return true;
    } else {
      confirmPasswordInput.classList.add("invalid");
      return false;
    }
  }

  // Validate all form fields
  function validateForm() {
    let isValid = true;
    hideError();

    // Check username (at least 3 characters)
    if (usernameInput && usernameInput.value.length < 3) {
      usernameInput.classList.add("invalid");
      showError("Username must be at least 3 characters");
      isValid = false;
    } else if (usernameInput) {
      usernameInput.classList.remove("invalid");
    }

    // Check full name is present
    if (fullNameInput && !fullNameInput.value.trim()) {
      fullNameInput.classList.add("invalid");
      showError("Please enter your full name");
      isValid = false;
    } else if (fullNameInput) {
      fullNameInput.classList.remove("invalid");
    }

    // Check email format
    if (emailInput) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(emailInput.value)) {
        emailInput.classList.add("invalid");
        showError("Please enter a valid email address");
        isValid = false;
      } else {
        emailInput.classList.remove("invalid");
      }
    }

    // Check password meets all requirements
    if (lengthCheck && uppercaseCheck && numberCheck && specialCheck) {
      const passwordValid = lengthCheck.classList.contains("valid") && uppercaseCheck.classList.contains("valid") && numberCheck.classList.contains("valid") && specialCheck.classList.contains("valid");

      if (!passwordValid && passwordInput) {
        passwordInput.classList.add("invalid");
        showError("Password does not meet all requirements");
        isValid = false;
      } else if (passwordInput) {
        passwordInput.classList.remove("invalid");
      }
    }

    // Check passwords match
    if (!validatePasswordMatch()) {
      showError("Passwords do not match");
      isValid = false;
    }

    // Check terms checkbox
    if (termsCheckbox && !termsCheckbox.checked) {
      termsCheckbox.parentElement.classList.add("invalid");
      showError("You must agree to the Terms of Service and Privacy Policy");
      isValid = false;
    } else if (termsCheckbox) {
      termsCheckbox.parentElement.classList.remove("invalid");
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
      
      .form-group.checkbox-group.invalid {
          color: #FF3B30;
      }
      
      .password-requirements li.valid {
          color: #00C853;
      }
      
      .register-error {
          padding: 10px;
          background-color: rgba(255, 59, 48, 0.1);
          border-radius: 4px;
          margin-bottom: 15px;
      }
      
      .auth-success {
          text-align: center;
          padding: var(--spacing-xl) 0;
      }
      
      .auth-success h2 {
          color: #00C853;
          margin-bottom: var(--spacing-md);
      }
      
      .auth-success p {
          margin-bottom: var(--spacing-xl);
          color: var(--text-medium);
      }
  `;
  document.head.appendChild(style);

  console.log("Registration page initialization complete");
});
// This code is for the registration page of the PhishR application.
// It handles form validation, password requirements, and error messages.
// The code is executed when the DOM is fully loaded and checks for the presence of the registration form.
// It validates the username, email, full name, password, and terms checkbox.
// It also provides visual feedback for password requirements and error messages.
// The code is designed to enhance user experience by providing real-time validation feedback.
// The styles for validation and error messages are dynamically added to the document.
// The code is modular and can be easily integrated into the existing registration page.
