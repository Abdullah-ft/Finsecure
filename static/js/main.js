// Main JavaScript for Finsecure Toolkit

// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips if needed
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

// Utility function to show notifications
function showNotification(message, type = 'info') {
    // This can be enhanced with a better notification system
    console.log(`[${type.toUpperCase()}] ${message}`);
}

// Auto-refresh results every 30 seconds on results page
if (window.location.pathname === '/results') {
    setInterval(() => {
        if (typeof loadResults === 'function') {
            loadResults();
        }
    }, 30000);
}

