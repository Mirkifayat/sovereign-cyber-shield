async function startScan() {
    const targetInput = document.getElementById('target');
    const target = targetInput.value.trim();
    const btn = document.getElementById('scan-btn');
    const loader = document.getElementById('loader');
    const resultContainer = document.getElementById('result-container');

    if (!target) {
        alert('Please enter a business domain!');
        return;
    }

    // UI Reset
    btn.disabled = true;
    loader.classList.remove('hidden');
    resultContainer.classList.add('hidden');

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const data = await response.json();
        
        // Hide loader, show results
        loader.classList.add('hidden');
        resultContainer.classList.remove('hidden');

        // Update Score and Lists (Matches your Screenshot UI)
        document.getElementById('score-text').textContent = data.score;
        populateList('web-output', data.web_surface);
        populateList('brand-output', data.brand_protection);
        document.getElementById('output').textContent = data.nmap_results;
        
        // Render Chart (If Chart.js is loaded)
        if (typeof renderChart === "function") renderChart(data.score, data.score > 70 ? '#3fb950' : '#f85149');

    } catch (err) {
        loader.classList.add('hidden');
        btn.disabled = false;
        alert('BACKEND ERROR: The scan took too long or the server crashed. Try scanme.nmap.org for a faster test.');
        console.error(err);
    } finally {
        btn.disabled = false;
    }
}

// STOP PAGE RELOAD ON ENTER KEY
document.addEventListener('DOMContentLoaded', () => {
    const targetField = document.getElementById('target');
    if (targetField) {
        targetField.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault(); // This is the crucial line to stop reloads
                startScan();
            }
        });
    }
});

function populateList(id, items) {
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = items.map(i => `<li>${i}</li>`).join('');
}
