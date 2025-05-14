// Main JavaScript for the Incident Response Tool

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    
    // Initialize popovers
    const popoverTriggerList = document.querySelectorAll('[data-bs-toggle="popover"]');
    const popoverList = [...popoverTriggerList].map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl));
    
    // Toggle password visibility
    const togglePasswordButtons = document.querySelectorAll('.toggle-password');
    togglePasswordButtons.forEach(button => {
        button.addEventListener('click', function() {
            const passwordField = document.querySelector(this.getAttribute('data-target'));
            const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordField.setAttribute('type', type);
            
            // Toggle icon
            const icon = this.querySelector('i');
            if (type === 'password') {
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            } else {
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            }
        });
    });
    
    // Password strength meter
    const passwordField = document.querySelector('#password');
    const strengthMeter = document.querySelector('#password-strength');
    
    if (passwordField && strengthMeter) {
        passwordField.addEventListener('input', function() {
            const password = this.value;
            let strength = 0;
            
            // Length check
            if (password.length >= 8) strength += 1;
            
            // Uppercase check
            if (/[A-Z]/.test(password)) strength += 1;
            
            // Lowercase check
            if (/[a-z]/.test(password)) strength += 1;
            
            // Number check
            if (/[0-9]/.test(password)) strength += 1;
            
            // Special character check
            if (/[^A-Za-z0-9]/.test(password)) strength += 1;
            
            // Update meter
            strengthMeter.value = strength;
            
            // Update color
            const strengthClasses = ['bg-danger', 'bg-warning', 'bg-info', 'bg-primary', 'bg-success'];
            strengthMeter.className = '';
            strengthMeter.classList.add('progress-bar');
            strengthMeter.classList.add(strengthClasses[strength - 1] || 'bg-danger');
            
            // Update text
            const strengthText = document.querySelector('#password-strength-text');
            if (strengthText) {
                const strengthLabels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
                strengthText.textContent = strengthLabels[strength - 1] || 'Very Weak';
            }
        });
    }
    
    // Handle incident type selection
    const incidentTypeSelect = document.querySelector('#incident_type');
    const templateSelect = document.querySelector('#template_id');
    
    if (incidentTypeSelect && templateSelect) {
        incidentTypeSelect.addEventListener('change', function() {
            const selectedType = this.value;
            
            // Filter templates by incident type
            Array.from(templateSelect.options).forEach(option => {
                const optionType = option.getAttribute('data-type');
                
                if (!optionType || optionType === selectedType) {
                    option.style.display = '';
                } else {
                    option.style.display = 'none';
                }
            });
            
            // Reset template selection
            templateSelect.value = '';
        });
    }
    
    // Step completion toggle
    const stepCompletionCheckboxes = document.querySelectorAll('.step-completion');
    stepCompletionCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            const stepId = this.getAttribute('data-step-id');
            const incidentId = this.getAttribute('data-incident-id');
            const stepTextElement = document.querySelector(`#step-text-${stepId}`);
            
            if (this.checked) {
                stepTextElement.classList.add('step-completed');
            } else {
                stepTextElement.classList.remove('step-completed');
            }
            
            // Submit form to update step
            const form = document.querySelector(`#step-form-${stepId}`);
            form.submit();
        });
    });
    
    // Handle copy to clipboard
    const clipboardButtons = document.querySelectorAll('.copy-to-clipboard');
    clipboardButtons.forEach(button => {
        button.addEventListener('click', function() {
            const textToCopy = this.getAttribute('data-clipboard-text');
            
            navigator.clipboard.writeText(textToCopy).then(() => {
                // Show success feedback
                const originalText = this.innerHTML;
                this.innerHTML = '<i class="fas fa-check"></i> Copied!';
                
                setTimeout(() => {
                    this.innerHTML = originalText;
                }, 2000);
            }).catch(err => {
                console.error('Could not copy text: ', err);
            });
        });
    });
    
    // Show loading spinner on form submit
    const forms = document.querySelectorAll('form:not(.no-spinner)');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitButton = this.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                const originalText = submitButton.innerHTML;
                submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Loading...';
                
                // Add a hidden input to keep track of submission
                const submissionInput = document.createElement('input');
                submissionInput.type = 'hidden';
                submissionInput.name = 'form_submitted';
                submissionInput.value = 'true';
                this.appendChild(submissionInput);
                
                // Re-enable button after timeout (in case of page load issues)
                setTimeout(() => {
                    submitButton.disabled = false;
                    submitButton.innerHTML = originalText;
                }, 10000);
            }
        });
    });
    
    // Confirmation dialog for dangerous actions
    const confirmationButtons = document.querySelectorAll('[data-confirm]');
    confirmationButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            const confirmMessage = this.getAttribute('data-confirm');
            if (!confirm(confirmMessage)) {
                e.preventDefault();
            }
        });
    });
});
