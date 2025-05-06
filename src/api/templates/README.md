# PhishR Website

## Project Structure

This repository contains the implementation of the PhishR website - a phishing detection tool using machine learning.

```
phishr-website/
├── index.html              # Main HTML file
├── css/
│   ├── normalize.css       # CSS reset/normalize
│   ├── styles.css          # Main stylesheet
│   └── responsive.css      # Responsive design rules
├── js/
│   └── main.js             # JavaScript functionality
├── img/
│   ├── logo-placeholder.svg    # Placeholder logo (to be replaced)
│   └── phishing-illustration.svg # Main illustration
└── README.md               # This file
```

## Features

- Responsive design that works on mobile, tablet, and desktop
- Modern, clean UI with a focus on usability
- Interactive scanning animation
- Semantically structured HTML5 markup
- Modular CSS with responsive breakpoints

## Implementation Notes

### HTML Structure

The HTML follows semantic markup practices with:

- Proper heading structure (h1, h2, etc.)
- Semantic sectioning elements (header, main, section, footer)
- Accessible form elements
- Meaningful class names

### CSS Architecture

CSS is organized into three main files:

1. `normalize.css` - Provides a consistent base across browsers
2. `styles.css` - Main styles using CSS variables for theming
3. `responsive.css` - Breakpoint-specific rules for responsive design

### JavaScript

The JavaScript provides basic interactivity for demonstration purposes:

- Form submission handling
- Scan simulation with progress updates
- UI state management

### Logo Replacement

The current SVG logo is a placeholder. It should be replaced with the final vector logo file while maintaining the same dimensions and integration.

## Future Enhancements

- Add user authentication functionality
- Implement the actual scanning API integration
- Add detailed results view with more metrics
- Add history of past scans for logged-in users
- Implement dark mode toggle
