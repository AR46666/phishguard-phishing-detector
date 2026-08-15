// PhishGuard Frontend - Smart Phishing Detection System

const API_BASE = 'http://localhost:5000/api';
let stats = { total: 0, phishing: 0, safe: 0 };

// Check single URL
async function checkURL() {
    const input = document.getElementById('urlInput');
    const btn = document.getElementById('checkBtn');
    const spinner = btn.querySelector('.spinner');
    let url = input.value.trim();

    if (!url) {
        showToast('Please enter a URL', 'error');
        return;
    }

    // Add scheme if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'http://' + url;
        input.value = url;
    }

    // UI loading state
    btn.disabled = true;
    spinner.classList.remove('hidden');
    btn.querySelector('span:first-child').textContent = 'Analyzing...';
    input.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/check`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const result = await response.json();
        displayResult(result);
        updateStats(result.verdict);
        
    } catch (error) {
        console.error('Error:', error);
        showToast('Failed to analyze URL. Is the backend running?', 'error');
    } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
        btn.querySelector('span:first-child').textContent = 'Analyze';
        input.disabled = false;
    }
}

// Check batch URLs
async function checkBatch() {
    const textarea = document.getElementById('batchUrls');
    const urls = textarea.value.split('\n')
        .map(u => u.trim())
        .filter(u => u.length > 0);

    if (urls.length === 0) {
        showToast('Please enter at least one URL', 'error');
        return;
    }

    // Add scheme to URLs without one
    const normalizedUrls = urls.map(u => 
        u.startsWith('http://') || u.startsWith('https://') ? u : 'http://' + u
    );

    try {
        const response = await fetch(`${API_BASE}/check_batch`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls: normalizedUrls })
        });

        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        displayBatchResults(data.results);
        
        data.results.forEach(r => updateStats(r.verdict));
        
    } catch (error) {
        console.error('Error:', error);
        showToast('Failed to analyze batch URLs', 'error');
    }
}

// Display single result
function displayResult(result) {
    const section = document.getElementById('results');
    const card = document.getElementById('resultCard');
    const details = document.getElementById('detailsSection');
    
    section.classList.remove('hidden');
    document.getElementById('batchResults').classList.add('hidden');
    
    // Determine verdict class
    const verdictClass = result.verdict;
    
    // Build result card
    card.className = `result-card ${verdictClass}`;
    
    const severityColors = {
        'CRITICAL': '#ff0040',
        'HIGH': '#ff4400',
        'MEDIUM': '#ffaa00',
        'LOW': '#00cc66'
    };
    
    card.innerHTML = `
        <div class="result-verdict ${verdictClass}">
            ${verdictClass === 'safe' ? '✅' : verdictClass === 'suspicious' ? '⚠️' : '🚫'}
            ${verdictClass.toUpperCase()}
        </div>
        <div class="result-url">${escapeHtml(result.url)}</div>
        <div class="result-stats">
            <div class="result-stat">
                <span class="value ${verdictClass}">${(result.combined_score * 100).toFixed(1)}%</span>
                <span class="label">Risk Score</span>
            </div>
            <div class="result-stat">
                <span class="value ${verdictClass}">${result.severity}</span>
                <span class="label">Severity</span>
            </div>
            <div class="result-stat">
                <span class="value">${(result.confidence * 100).toFixed(0)}%</span>
                <span class="label">Confidence</span>
            </div>
        </div>
    `;
    
    // Populate details
    populateDetails(result);
    details.classList.remove('hidden');
    
    // Scroll to results
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Populate detailed analysis
function populateDetails(result) {
    // Heuristic details
    const heuristicDiv = document.getElementById('heuristicDetails');
    let heuristicHTML = `
        <div class="detail-item">
            <span>Score</span>
            <span>${result.heuristic.heuristic_score}/100</span>
        </div>
        <div class="detail-item">
            <span>Verdict</span>
            <span>${result.heuristic.heuristic_verdict.toUpperCase()}</span>
        </div>
    `;
    
    if (result.heuristic.heuristic_reasons.length > 0) {
        heuristicHTML += `<div style="margin-top: 8px; font-size: 0.85rem; color: #ffaa00;">Flags:</div>`;
        result.heuristic.heuristic_reasons.forEach(reason => {
            heuristicHTML += `<div class="flag-item">⚠ ${escapeHtml(reason)}</div>`;
        });
    } else {
        heuristicHTML += `<div class="detail-item"><span>Flags</span><span style="color: #00cc66;">None</span></div>`;
    }
    
    heuristicDiv.innerHTML = heuristicHTML;
    
    // ML details
    const mlDiv = document.getElementById('mlDetails');
    if (result.ml) {
        mlDiv.innerHTML = `
            <div class="detail-item">
                <span>Prediction</span>
                <span>${result.ml.ml_verdict.toUpperCase()}</span>
            </div>
            <div class="detail-item">
                <span>Probability</span>
                <span>${(result.ml.ml_probability * 100).toFixed(1)}%</span>
            </div>
            <div class="detail-item">
                <span>Confidence</span>
                <span>${(result.ml.ml_confidence * 100).toFixed(0)}%</span>
            </div>
            <div class="detail-item">
                <span>ML Weight</span>
                <span>${(result.ml_weight * 100).toFixed(0)}%</span>
            </div>
        `;
    } else {
        mlDiv.innerHTML = `
            <div class="detail-item">
                <span>Status</span>
                <span style="color: #ffaa00;">Not Available</span>
            </div>
            <div class="detail-item">
                <span>Fallback</span>
                <span>Heuristic Only</span>
            </div>
        `;
    }
    
    // Feature breakdown placeholder
    document.getElementById('featureBreakdown').innerHTML = `
        <div style="color: var(--text-dim); font-size: 0.9rem;">
            Feature-level analysis available via Admin Dashboard.
        </div>
    `;
}

// Display batch results
function displayBatchResults(results) {
    const section = document.getElementById('batchResults');
    const list = document.getElementById('batchResultList');
    
    section.classList.remove('hidden');
    document.getElementById('detailsSection').classList.add('hidden');
    
    list.innerHTML = results.map(r => `
        <div class="batch-item">
            <span class="url">${escapeHtml(r.url)}</span>
            <span class="badge ${r.verdict}">${r.verdict.toUpperCase()} (${(r.combined_score * 100).toFixed(0)}%)</span>
        </div>
    `).join('');
    
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Update statistics
function updateStats(verdict) {
    stats.total++;
    if (verdict === 'phishing' || verdict === 'suspicious') {
        stats.phishing++;
    } else {
        stats.safe++;
    }
    
    document.getElementById('totalChecked').textContent = stats.total;
    document.getElementById('phishingDetected').textContent = stats.phishing;
    document.getElementById('safeCount').textContent = stats.safe;
    
    if (stats.total > 0) {
        const accuracy = ((stats.total - stats.phishing) / stats.total * 100).toFixed(0);
        document.getElementById('accuracyRate').textContent = accuracy + '%';
    }
}

// Toggle batch input
function toggleBatch() {
    const el = document.getElementById('batchInput');
    const isHidden = el.classList.contains('hidden');
    el.classList.toggle('hidden');
    
    if (!isHidden) {
        document.getElementById('batchUrls').value = '';
    }
}

// Clear results
function clearResults() {
    document.getElementById('results').classList.add('hidden');
    document.getElementById('urlInput').value = '';
    document.getElementById('batchUrls').value = '';
}

// Toast notification
function showToast(message, type = 'info') {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    Object.assign(toast.style, {
        position: 'fixed',
        bottom: '30px',
        left: '50%',
        transform: 'translateX(-50%)',
        padding: '14px 28px',
        borderRadius: '10px',
        background: type === 'error' ? '#ff0040' : '#00cc66',
        color: '#fff',
        fontWeight: '600',
        zIndex: '1000',
        boxShadow: '0 8px 30px rgba(0,0,0,0.4)',
        animation: 'fadeIn 0.3s ease'
    });
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Escape HTML for security
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    // Add toast animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes fadeIn {
            from { opacity: 0; transform: translateX(-50%) translateY(20px); }
            to { opacity: 1; transform: translateX(-50%) translateY(0); }
        }
    `;
    document.head.appendChild(style);
    
    console.log('PhishGuard v2.0 — Ready');
    console.log(`API: ${API_BASE}`);
});