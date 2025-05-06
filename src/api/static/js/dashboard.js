/**
 * PhishR - Dashboard JavaScript
 * Handles interactions and functionality for the authenticated dashboard
 */

document.addEventListener('DOMContentLoaded', function() {
    // Model Dropdown Functionality
    const modelDropdown = document.querySelector('.model-dropdown');
    const dropdownToggle = modelDropdown.querySelector('.dropdown-toggle');
    const dropdownContent = modelDropdown.querySelector('.dropdown-content');
    const dropdownItems = modelDropdown.querySelectorAll('.dropdown-item');
    const selectedModelText = dropdownToggle.querySelector('span');
    
    // Toggle dropdown on click
    dropdownToggle.addEventListener('click', function() {
        modelDropdown.classList.toggle('active');
    });
    
    // Close dropdown when clicking outside
    document.addEventListener('click', function(event) {
        if (!modelDropdown.contains(event.target)) {
            modelDropdown.classList.remove('active');
        }
    });
    
    // Handle dropdown item selection
    dropdownItems.forEach(item => {
        item.addEventListener('click', function() {
            // Update selected text
            selectedModelText.textContent = this.textContent;
            
            // Update selected item
            dropdownItems.forEach(i => i.classList.remove('selected'));
            this.classList.add('selected');
            
            // Close dropdown
            modelDropdown.classList.remove('active');
        });
    });
    
    // URL Scan Functionality
    const urlInput = document.getElementById('url-input');
    const scanButton = document.querySelector('.scan-button');
    const rescanButton = document.querySelector('.rescan-btn');
    const progressFill = document.querySelector('.progress-fill');
    const progressText = document.querySelector('.progress-text');
    
    // Initialize progress state
    let scanInProgress = false;
    
    // Handle scan button click
    scanButton.addEventListener('click', function() {
        if (scanInProgress) return;
        
        const url = urlInput.value.trim();
        if (!url) {
            alert('Please enter a valid URL to scan');
            return;
        }
        
        // Start scan animation
        startScanAnimation();
    });
    
    // Handle rescan button click
    rescanButton.addEventListener('click', function() {
        if (scanInProgress) return;
        
        // Start scan animation
        startScanAnimation();
    });
    
    // Simulate scan process
    function startScanAnimation() {
        scanInProgress = true;
        scanButton.disabled = true;
        rescanButton.disabled = true;
        
        // Reset progress
        progressFill.style.width = '0%';
        progressText.textContent = 'Initializing scan...';
        
        // Define scan steps
        const steps = [
            { progress: 20, message: '20% Analyzing URL structure...' },
            { progress: 40, message: '40% Checking for malicious patterns...' },
            { progress: 60, message: '60% Validating content...' },
            { progress: 80, message: '80% Applying ML model...' },
            { progress: 100, message: '100% Detection Finished...' }
        ];
        
        let currentStep = 0;
        
        // Start progress simulation
        const progressInterval = setInterval(function() {
            if (currentStep < steps.length) {
                const step = steps[currentStep];
                progressFill.style.width = step.progress + '%';
                progressText.textContent = step.message;
                currentStep++;
            } else {
                // Scan completed
                clearInterval(progressInterval);
                scanInProgress = false;
                scanButton.disabled = false;
                rescanButton.disabled = false;
            }
        }, 800); // Update progress every 800ms for demo
    }
    
    // Copy URL functionality
    const copyBtn = document.querySelector('.copy-btn');
    const urlLink = document.querySelector('.url-link');
    
    copyBtn.addEventListener('click', function() {
        // Get URL text
        const url = urlLink.textContent;
        
        // Create temporary textarea to copy from
        const textarea = document.createElement('textarea');
        textarea.value = url;
        document.body.appendChild(textarea);
        textarea.select();
        
        // Copy text and remove textarea
        document.execCommand('copy');
        document.body.removeChild(textarea);
        
        // Show feedback
        const originalTitle = this.getAttribute('title');
        this.setAttribute('title', 'Copied!');
        
        // Reset title after 2 seconds
        setTimeout(() => {
            this.setAttribute('title', originalTitle);
        }, 2000);
    });
    
    // Help Center Functionality
    const closeHelpBtn = document.querySelector('.close-help');
    const helpCenter = document.querySelector('.help-center');
    const helpItems = document.querySelectorAll('.help-item');
    
    // Close help center (in a real app this would toggle visibility)
    closeHelpBtn.addEventListener('click', function() {
        // For demo purposes, we'll just add a class
        helpCenter.classList.toggle('closed');
    });
    
    // Toggle help items
    helpItems.forEach(item => {
        item.addEventListener('click', function() {
            this.classList.toggle('open');
        });
    });
});