document.addEventListener('DOMContentLoaded', function() {
    
    const menuToggle = document.querySelector('.menu-toggle');

    if (menuToggle) {
        menuToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            document.body.classList.toggle('menu-open');
        });

        document.addEventListener('click', (e) => {
            if (document.body.classList.contains('menu-open')) {
                const navLinks = document.querySelector('.nav-links');
                if (navLinks && !navLinks.contains(e.target) && !menuToggle.contains(e.target)) {
                    document.body.classList.remove('menu-open');
                }
            }
        });
    }

    const uploadForm = document.getElementById('uploadForm');
    
    if (uploadForm) {
        const fileInput = document.getElementById('fileInput');
        const dropZone = document.getElementById('dropZone');
        const fileNameDisplay = document.getElementById('fileNameDisplay');
        const loadingIndicator = document.getElementById('loadingIndicator');
        const resultsContainer = document.getElementById('resultsContainer');
        const resultContent = document.getElementById('resultContent');

        fileInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                fileNameDisplay.textContent = this.files[0].name;
                fileNameDisplay.style.fontWeight = "bold";
            } else {
                fileNameDisplay.innerHTML = '<strong>Click to upload</strong> or drag and drop';
            }
        });

        if (dropZone) {
            dropZone.addEventListener('click', (e) => {
                if (e.target === dropZone) {
                    fileInput.click();
                }
            });

            ['dragenter', 'dragover'].forEach(eventName => {
                dropZone.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    dropZone.classList.add('dragover');
                }, false);
            });

            ['dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    dropZone.classList.remove('dragover');
                }, false);
            });

            dropZone.addEventListener('drop', (e) => {
                const dt = e.dataTransfer;
                const files = dt.files;
                if (files && files[0]) {
                    fileInput.files = files;
                    fileNameDisplay.textContent = files[0].name;
                    fileNameDisplay.style.fontWeight = "bold";
                }
            });
        }

        uploadForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            resultsContainer.style.display = 'none';
            loadingIndicator.style.display = 'block';

            const formData = new FormData(uploadForm);

            fetch('/check', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                loadingIndicator.style.display = 'none';
                if (data.error) {
                    displayError(data.error);
                } else {
                    displayResults(data);
                }
            })
            .catch(error => {
                loadingIndicator.style.display = 'none';
                displayError('An error occurred while connecting to the server.');
                console.error('Error:', error);
            });
        });
    }

    // ... existing code ...

    // --- THEME TOGGLE LOGIC ---
    const themeToggleBtn = document.getElementById('theme-toggle-link');
    const themeStylesheet = document.getElementById('current-theme');

    if (themeToggleBtn && themeStylesheet) {
        // 1. Check for saved theme preference on load
        const savedTheme = localStorage.getItem('theme') || 'light';
        applyTheme(savedTheme);

        // 2. Listen for clicks
        themeToggleBtn.addEventListener('click', (e) => {
            e.preventDefault(); // Prevent jumping to top of page
            
            // Check if we are currently using light mode
            const isLight = themeStylesheet.getAttribute('href').includes('light-mode.css');
            const newTheme = isLight ? 'night' : 'light';
            
            applyTheme(newTheme);
            localStorage.setItem('theme', newTheme);
        });

        // Helper function to update CSS and Text
        function applyTheme(theme) {
            if (theme === 'night') {
                // Switch CSS to Dark
                if (themeStylesheet.href.includes('light-mode')) {
                    themeStylesheet.href = themeStylesheet.href.replace('light-mode', 'night-mode');
                }
                // Update Link Text
                themeToggleBtn.textContent = "Switch to Light Mode";
            } else {
                // Switch CSS to Light
                if (themeStylesheet.href.includes('night-mode')) {
                    themeStylesheet.href = themeStylesheet.href.replace('night-mode', 'light-mode');
                }
                // Update Link Text
                themeToggleBtn.textContent = "Switch to Night Mode";
            }
        }
    }

    function displayResults(data) {
        const container = document.getElementById('resultsContainer');
        const content = document.getElementById('resultContent');
        if (!container || !content) return;

        container.style.display = 'block';
        
        let resultClass, title;
        if (data.filetype === 'UNKNOWN') {
            resultClass = 'unknown';
            title = 'Unknown File Type';
        } else if (data.mismatch) {
            resultClass = 'mismatch';
            title = 'Mismatch Detected';
        } else {
            resultClass = 'match';
            title = 'Extension Matches';
        }
        
        let html = `
            <div class="result-box ${resultClass}">
                <h3 style="margin-bottom: 1rem;">${title}</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem;">
                    <div><strong>Filename:</strong><br><span style="color: #4c4f69;">${escapeHtml(data.filename)}</span></div>
                    <div><strong>Claimed:</strong><br><span style="color: #4c4f69;">${escapeHtml(data.extension)}</span></div>
                    <div><strong>Detected:</strong><br><span style="color: #4c4f69;">${escapeHtml(data.filetype)}</span></div>
                    <div><strong>Type:</strong><br><span style="color: #4c4f69;">${escapeHtml(data.description)}</span></div>
                </div>
                <div style="margin-top: 1rem; border-top: 1px solid #e6e9ef; padding-top: 1rem;">
                    <strong>Analysis:</strong> ${escapeHtml(data.message)}
                </div>
            </div>
        `;

        if (data.virustotal) {
            html += formatVirusTotal(data.virustotal);
        }

        content.innerHTML = html;
    }

    function formatVirusTotal(vt) {
        if (vt.error) {
            return `<div class="result-box mismatch" style="margin-top: 1rem;"><h4>VirusTotal Error</h4><p>${escapeHtml(vt.message)}</p></div>`;
        }
        const isClean = vt.malicious === 0 && vt.suspicious === 0;
        const colorClass = isClean ? 'match' : 'mismatch';
        
        return `
            <div class="result-box ${colorClass}" style="margin-top: 1rem;">
                <h4 style="margin-bottom: 0.5rem;">VirusTotal Scan</h4>
                <div style="display: flex; gap: 15px; margin-bottom: 10px;">
                    <span style="font-weight: bold; color: #d20f39;">Malicious: ${vt.malicious}</span>
                    <span style="font-weight: bold; color: #df8e1d;">Suspicious: ${vt.suspicious}</span>
                    <span style="font-weight: bold; color: #40a02b;">Harmless: ${vt.harmless}</span>
                </div>
                <a href="${vt.permalink}" target="_blank" class="btn" style="font-size: 0.9rem; padding: 0.5rem 1rem;">View Full Report</a>
            </div>
        `;
    }

    function displayError(message) {
        const container = document.getElementById('resultsContainer');
        const content = document.getElementById('resultContent');
        if (container && content) {
            container.style.display = 'block';
            content.innerHTML = `<div class="result-box mismatch"><h3>Error</h3><p>${escapeHtml(message)}</p></div>`;
        }
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});