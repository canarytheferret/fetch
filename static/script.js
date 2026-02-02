document.addEventListener('DOMContentLoaded', function() {
    const uploadForm = document.getElementById('uploadForm');
    const fileInput = document.getElementById('fileInput');
    const fileNameDisplay = document.getElementById('fileNameDisplay');
    const submitButton = document.getElementById('submitButton');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const resultsContainer = document.getElementById('resultsContainer');
    const resultContent = document.getElementById('resultContent');
    const virusTotalCheckbox = document.getElementById('virusTotalCheckbox');

    // Update file name display when file is selected
    fileInput.addEventListener('change', function() {
        if (this.files && this.files[0]) {
            fileNameDisplay.textContent = this.files[0].name;
        } else {
            fileNameDisplay.textContent = 'Choose a file or drag it here';
        }
    });

    // Drag and drop functionality
    const fileLabel = document.querySelector('.file-label');
    
    fileLabel.addEventListener('dragover', function(e) {
        e.preventDefault();
        this.style.background = '#93ccea';
        this.style.borderColor = '#000000';
    });

    fileLabel.addEventListener('dragleave', function(e) {
        e.preventDefault();
        this.style.background = '#ffffff';
        this.style.borderColor = '#93ccea';
    });

    fileLabel.addEventListener('drop', function(e) {
        e.preventDefault();
        this.style.background = '#ffffff';
        this.style.borderColor = '#93ccea';
        
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            fileNameDisplay.textContent = e.dataTransfer.files[0].name;
        }
    });

    // Handle form submission
    uploadForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        // Validate file selection
        if (!fileInput.files || !fileInput.files[0]) {
            alert('Please select a file to analyze.');
            return;
        }

        // Prepare form data
        const formData = new FormData();
        formData.append('file', fileInput.files[0]);
        formData.append('virustotal', virusTotalCheckbox.checked ? 'true' : 'false');

        // Show loading; hide results
        loadingIndicator.classList.remove('hidden');
        resultsContainer.classList.add('hidden');
        resultsContainer.classList.remove('results-match', 'results-mismatch');
        submitButton.disabled = true;

        try {
            // Send request to server
            const response = await fetch('/check', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            // Hide loading
            loadingIndicator.classList.add('hidden');
            submitButton.disabled = false;

            if (response.ok) {
                displayResults(data);
            } else {
                displayError(data.error || 'An error occurred during analysis.');
            }

        } catch (error) {
            loadingIndicator.classList.add('hidden');
            submitButton.disabled = false;
            displayError('Failed to connect to server: ' + error.message);
        }
    });

function convertBackticksToCode(text) {
        return text.replace(/`([^`]+)`/g, '<code>$1</code>');
    }

    function displayResults(data) {
        // Add appropriate class based on mismatch status
        if (data.mismatch) {
            resultsContainer.classList.add('results-mismatch');
        } else {
            resultsContainer.classList.add('results-match');
        }

        let html = `
            <div class="result-item">
                <span class="result-label">Filename:</span>
                <span class="result-value">${escapeHtml(data.filename)}</span>
            </div>
            <div class="result-item">
                <span class="result-label">Claimed Extension:</span>
                <span class="result-value">${escapeHtml(data.extension)}</span>
            </div>
            <div class="result-item">
                <span class="result-label">Detected Type:</span>
                <span class="result-value">${escapeHtml(data.detected_type)}</span>
            </div>
            <div class="result-item">
                <span class="result-label">Description:</span>
                <span class="result-value">${escapeHtml(data.detected_description)}</span>
            </div>
            <div class="result-item">
                <span class="result-label">Status:</span>
                <span class="${data.mismatch ? 'status-mismatch' : 'status-match'}">
                    ${convertBackticksToCode(escapeHtml(data.message))}
                </span>
            </div>
        `;

        // Add VirusTotal results if available
        if (data.virustotal) {
            html += formatVirusTotalResults(data.virustotal);
        }

        resultContent.innerHTML = html;
        resultsContainer.classList.remove('hidden');

        // Scroll to results
        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function formatVirusTotalResults(virusTotal) {
        if (virusTotal.error) {
            return `
                <div class="virustotal-section">
                    <h4>VirusTotal Check</h4>
                    <p><strong>Error:</strong> ${escapeHtml(virusTotal.error)}</p>
                    <p>${escapeHtml(virusTotal.message || virusTotal.details || '')}</p>
                </div>
            `;
        }

        if (virusTotal.message) {
            // File not in database
            return `
                <div class="virustotal-section">
                    <h4>VirusTotal Check</h4>
                    <p>${escapeHtml(virusTotal.message)}</p>
                    <p><strong>File Hash:</strong> ${escapeHtml(virusTotal.file_hash)}</p>
                    <p><a href="${escapeHtml(virusTotal.upload_url)}" target="_blank">Upload to VirusTotal</a></p>
                </div>
            `;
        }

        // Full results available
        const isClean = virusTotal.status === 'clean';
        const virusTotalClass = isClean ? 'virustotal-clean' : 'virustotal-dirty';

        return `
            <div class="virustotal-section ${virusTotalClass}">
                <h4>VirusTotal Results</h4>
                <div class="result-item">
                    <span class="result-label">Status:</span>
                    <span class="result-value">
                        ${isClean ? 'Clean' : 'Threat Detected'}
                    </span>
                </div>
                <div class="result-item">
                    <span class="result-label">Malicious:</span>
                    <span class="result-value">${virusTotal.malicious}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">Suspicious:</span>
                    <span class="result-value">${virusTotal.suspicious}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">Undetected:</span>
                    <span class="result-value">${virusTotal.undetected}</span>
                </div>
                <div class="result-item">
                    <span class="result-label">File Hash:</span>
                    <span class="result-value" style="word-break: break-all; font-size: 0.9em;">${escapeHtml(virusTotal.file_hash)}</span>
                </div>
                <p style="margin-top: 10px;">
                    <a href="${escapeHtml(virusTotal.permalink)}" target="_blank">View full report on VirusTotal</a>
                </p>
            </div>
        `;
    }

    function displayError(message) {
        resultsContainer.classList.add('results-mismatch');
        resultContent.innerHTML = `
            <div class="result-item">
                <strong>Error:</strong> ${escapeHtml(message)}
            </div>
        `;
        resultsContainer.classList.remove('hidden');
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});