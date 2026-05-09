let scoreChartInstance = null;

async function startScan() {
    const target = document.getElementById('target').value;
    const btn = document.getElementById('scan-btn');
    const loader = document.getElementById('loader');
    const resultContainer = document.getElementById('result-container');
    
    // UI Elements
    const output = document.getElementById('output');
    const scoreText = document.getElementById('score-text');
    const scoreMessage = document.getElementById('score-message');
    const webOutput = document.getElementById('web-output');
    const brandOutput = document.getElementById('brand-output');

    if (!target) {
        alert("Please enter a target domain!");
        return;
    }

    // Reset UI
    btn.disabled = true;
    loader.classList.remove('hidden');
    resultContainer.classList.add('hidden');
    webOutput.innerHTML = '';
    brandOutput.innerHTML = '';

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target })
        });

        const data = await response.json();

        loader.classList.add('hidden');
        resultContainer.classList.remove('hidden');

        if (response.ok) {
            // 1. Determine Score Color & Message
            let color = '#ff4a4a'; // Default Red
            let statusClass = 'low';
            
            if (data.score >= 80) {
                color = '#3fb950'; // Green
                statusClass = 'high';
                scoreMessage.textContent = "✅ Excellent: Your digital storefront is highly resilient.";
                scoreMessage.style.color = color;
            } else if (data.score >= 50) {
                color = '#e3b341'; // Yellow
                statusClass = 'medium';
                scoreMessage.textContent = "⚠️ Warning: Multiple vulnerabilities found. Action required.";
                scoreMessage.style.color = color;
            } else {
                scoreMessage.textContent = "🚨 Critical Danger: Business infrastructure is severely compromised.";
                scoreMessage.style.color = color;
            }

            scoreText.textContent = data.score;
            scoreText.className = `score-overlay ${statusClass}`;

            // 2. Render Chart.js
            renderChart(data.score, color);

            // 3. Populate Web Surface List with Custom Styling
            data.web_surface.forEach(item => {
                const li = document.createElement('li');
                li.textContent = item;
                if(item.includes("CRITICAL")) li.className = "li-danger";
                else if(item.includes("WARNING")) li.className = "li-warning";
                else li.className = "li-success";
                webOutput.appendChild(li);
            });

            // 4. Populate Brand Protection List
            data.brand_protection.forEach(item => {
                const li = document.createElement('li');
                li.textContent = item;
                if(item.includes("DANGER")) li.className = "li-danger";
                else li.className = "li-success";
                brandOutput.appendChild(li);
            });

            // 5. Update Raw Terminal Output
            output.textContent = data.nmap_results;

        } else {
            alert(`Scan Failed: ${data.error}`);
            loader.classList.add('hidden');
            btn.disabled = false;
        }
    } catch (error) {
        alert("Could not connect to the scanning server. Please try again.");
    } finally {
        btn.disabled = false;
    }
}

// Function to draw and update the Chart.js Donut Chart
function renderChart(score, colorCode) {
    const ctx = document.getElementById('scoreChart').getContext('2d');
    
    // Destroy previous chart if it exists so we can draw a new one
    if (scoreChartInstance) {
        scoreChartInstance.destroy();
    }

    scoreChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [score, 100 - score],
                backgroundColor: [colorCode, 'rgba(255, 255, 255, 0.1)'],
                borderWidth: 0,
                cutout: '80%',
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { animateScale: true, animateRotate: true },
            plugins: { tooltip: { enabled: false } }
        }
    });
}
