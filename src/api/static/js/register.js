/**
 * PhishR - Registration Page JavaScript
 * Handles form validation and submission for the registration page
 */

// Wait for DOM to be fully loaded
document.addEventListener("DOMContentLoaded", function () {
  // Get form elements
  const registerForm = document.getElementById("register-form");
  const usernameInput = document.getElementById("username");
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");
  const confirmPasswordInput = document.getElementById("confirm-password");
  const termsCheckbox = document.getElementById("terms");

  // Get password requirement elements
  const lengthCheck = document.getElementById("length-check");
  const uppercaseCheck = document.getElementById("uppercase-check");
  const numberCheck = document.getElementById("number-check");
  const specialCheck = document.getElementById("special-check");

  // Add event listener for password input
  passwordInput.addEventListener("input", function () {
    validatePassword(this.value);
  });

  // Add event listener for confirm password input
  confirmPasswordInput.addEventListener("input", function () {
    validatePasswordMatch();
  });

  // Handle form submission
  registerForm.addEventListener("submit", function (event) {
    event.preventDefault();

    // Validate all fields
    const isValid = validateForm();

    if (isValid) {
      // Simulate form submission
      simulateRegistration();
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
    if (confirmPasswordInput.value) {
      validatePasswordMatch();
    }
  }

  // Validate that passwords match
  function validatePasswordMatch() {
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

    // Check username (at least 3 characters)
    if (usernameInput.value.length < 3) {
      usernameInput.classList.add("invalid");
      isValid = false;
    } else {
      usernameInput.classList.remove("invalid");
    }

    // Check email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(emailInput.value)) {
      emailInput.classList.add("invalid");
      isValid = false;
    } else {
      emailInput.classList.remove("invalid");
    }

    // Check password meets all requirements
    const passwordValid = lengthCheck.classList.contains("valid") && uppercaseCheck.classList.contains("valid") && numberCheck.classList.contains("valid") && specialCheck.classList.contains("valid");

    if (!passwordValid) {
      passwordInput.classList.add("invalid");
      isValid = false;
    } else {
      passwordInput.classList.remove("invalid");
    }

    // Check passwords match
    if (!validatePasswordMatch()) {
      isValid = false;
    }

    // Check terms checkbox
    if (!termsCheckbox.checked) {
      termsCheckbox.parentElement.classList.add("invalid");
      isValid = false;
    } else {
      termsCheckbox.parentElement.classList.remove("invalid");
    }

    return isValid;
  }

  // Simulate successful registration
  function simulateRegistration() {
    // Disable form inputs during "submission"
    const formElements = registerForm.elements;
    for (let i = 0; i < formElements.length; i++) {
      formElements[i].disabled = true;
    }

    // Get submit button and show loading state
    const submitButton = registerForm.querySelector('button[type="submit"]');
    const originalText = submitButton.textContent;
    submitButton.textContent = "Creating Account...";

    // Simulate server response delay
    setTimeout(function () {
      // Show success message
      const authContainer = document.querySelector(".auth-container");
      authContainer.innerHTML = `
              <div class="auth-success">
                  <h2>Account Created Successfully!</h2>
                  <p>Welcome to PhishR. You can now log in to access advanced phishing detection features.</p>
                  <a href="/login" class="btn btn-primary btn-block">Log In</a>
              </div>
          `;
    }, 2000);
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
});
