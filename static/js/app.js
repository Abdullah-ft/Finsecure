// Finsecure Toolkit - Modern App JavaScript

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Initialize form handlers
    setupFormHandlers();
    
    // Initialize Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Auto-refresh status every 30 seconds
    setInterval(refreshStatus, 30000);
}

function setupFormHandlers() {
    // Port Scanner
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (validateForm(scanForm)) {
                const formData = new FormData(scanForm);
                const data = Object.fromEntries(formData);
                await submitOperation('scan', '/api/scan', data, 'Port scan', scanForm);
            }
        });
    }
    
    // Password Test
    const passwordForm = document.getElementById('passwordForm');
    if (passwordForm) {
        passwordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (validateForm(passwordForm)) {
                const formData = new FormData(passwordForm);
                await submitOperationFile('password', '/api/password-test', formData, 'Password test', passwordForm);
            }
        });
    }
    
    // Stress Test
    const stressForm = document.getElementById('stressForm');
    if (stressForm) {
        stressForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (validateForm(stressForm)) {
                const formData = new FormData(stressForm);
                const data = Object.fromEntries(formData);
                await submitOperation('stress', '/api/stress-test', data, 'Stress test', stressForm);
            }
        });
    }
    
    // Web Discovery
    const footprintForm = document.getElementById('footprintForm');
    if (footprintForm) {
        footprintForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (validateForm(footprintForm)) {
                const formData = new FormData(footprintForm);
                const data = Object.fromEntries(formData);
                await submitOperation('footprint', '/api/footprint', data, 'Web discovery', footprintForm);
            }
        });
    }
    
    // Packet Capture
    const pcapForm = document.getElementById('pcapForm');
    if (pcapForm) {
        pcapForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (validateForm(pcapForm)) {
                const formData = new FormData(pcapForm);
                const data = Object.fromEntries(formData);
                await submitOperation('pcap', '/api/pcap', data, 'Packet capture', pcapForm);
            }
        });
    }
    
    // Report Generator
    const reportForm = document.getElementById('reportForm');
    if (reportForm) {
        reportForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (validateForm(reportForm)) {
                const formData = new FormData(reportForm);
                const data = Object.fromEntries(formData);
                await submitOperation('report', '/api/generate-report', data, 'Report generation', reportForm);
            }
        });
    }
}

function validateForm(form) {
    if (!form.checkValidity()) {
        form.classList.add('was-validated');
        return false;
    }
    form.classList.add('was-validated');
    return true;
}

async function submitOperation(operationId, url, data, operationName, form) {
    const btn = form.querySelector('button[type="submit"]');
    const progressContainer = form.querySelector('.progress-container');
    const progressBar = progressContainer?.querySelector('.progress-bar');
    const statusDiv = form.querySelector('.operation-status');
    
    // Disable button and show progress
    if (btn) btn.disabled = true;
    if (progressContainer) progressContainer.style.display = 'block';
    if (progressBar) animateProgress(progressBar);
    if (statusDiv) {
        statusDiv.className = 'operation-status operation-info';
        statusDiv.innerHTML = `<i class="bi bi-info-circle me-2"></i>${operationName} started...`;
        statusDiv.style.display = 'block';
    }
    
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast(`${operationName} started successfully!`, 'success');
            if (statusDiv) {
                statusDiv.className = 'operation-status operation-success';
                statusDiv.innerHTML = `<i class="bi bi-check-circle me-2"></i>${operationName} started successfully!`;
            }
            
            // Poll for completion (simplified - in real app, use WebSockets)
            setTimeout(() => {
                if (progressBar) progressBar.style.width = '100%';
                setTimeout(() => {
                    if (progressContainer) progressContainer.style.display = 'none';
                    if (btn) btn.disabled = false;
                }, 1000);
            }, 2000);
        } else {
            showToast(`Error: ${result.message}`, 'danger');
            if (statusDiv) {
                statusDiv.className = 'operation-status operation-error';
                statusDiv.innerHTML = `<i class="bi bi-x-circle me-2"></i>Error: ${result.message}`;
            }
            if (progressContainer) progressContainer.style.display = 'none';
            if (btn) btn.disabled = false;
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
        if (statusDiv) {
            statusDiv.className = 'operation-status operation-error';
            statusDiv.innerHTML = `<i class="bi bi-x-circle me-2"></i>Error: ${error.message}`;
        }
        if (progressContainer) progressContainer.style.display = 'none';
        if (btn) btn.disabled = false;
    }
}

async function submitOperationFile(operationId, url, formData, operationName, form) {
    const btn = form.querySelector('button[type="submit"]');
    const progressContainer = form.querySelector('.progress-container');
    const progressBar = progressContainer?.querySelector('.progress-bar');
    const statusDiv = form.querySelector('.operation-status');
    
    // Disable button and show progress
    if (btn) btn.disabled = true;
    if (progressContainer) progressContainer.style.display = 'block';
    if (progressBar) animateProgress(progressBar);
    if (statusDiv) {
        statusDiv.className = 'operation-status operation-info';
        statusDiv.innerHTML = `<i class="bi bi-info-circle me-2"></i>${operationName} started...`;
        statusDiv.style.display = 'block';
    }
    
    try {
        const response = await fetch(url, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast(`${operationName} started successfully!`, 'success');
            if (statusDiv) {
                statusDiv.className = 'operation-status operation-success';
                statusDiv.innerHTML = `<i class="bi bi-check-circle me-2"></i>${operationName} started successfully!`;
            }
            
            setTimeout(() => {
                if (progressBar) progressBar.style.width = '100%';
                setTimeout(() => {
                    if (progressContainer) progressContainer.style.display = 'none';
                    if (btn) btn.disabled = false;
                }, 1000);
            }, 2000);
        } else {
            showToast(`Error: ${result.message}`, 'danger');
            if (statusDiv) {
                statusDiv.className = 'operation-status operation-error';
                statusDiv.innerHTML = `<i class="bi bi-x-circle me-2"></i>Error: ${result.message}`;
            }
            if (progressContainer) progressContainer.style.display = 'none';
            if (btn) btn.disabled = false;
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'danger');
        if (statusDiv) {
            statusDiv.className = 'operation-status operation-error';
            statusDiv.innerHTML = `<i class="bi bi-x-circle me-2"></i>Error: ${error.message}`;
        }
        if (progressContainer) progressContainer.style.display = 'none';
        if (btn) btn.disabled = false;
    }
}

function animateProgress(progressBar) {
    let width = 0;
    const interval = setInterval(() => {
        if (width >= 90) {
            clearInterval(interval);
        } else {
            width += Math.random() * 10;
            if (width > 90) width = 90;
            progressBar.style.width = width + '%';
        }
    }, 200);
}

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    if (!toast) return;
    
    const toastBody = toast.querySelector('.toast-body');
    const toastHeader = toast.querySelector('.toast-header');
    
    // Set color based on type
    toast.className = `toast bg-${type} text-white`;
    toastBody.textContent = message;
    
    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: 3000
    });
    bsToast.show();
}

function refreshStatus() {
    // Refresh page status if needed
    // This could fetch updated status from API
}

// Export for use in other scripts
window.FinsecureApp = {
    showToast,
    submitOperation,
    submitOperationFile
};

