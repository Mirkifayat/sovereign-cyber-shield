async function startScan() {
    const target = document.getElementById('target').value;
    const btn = document.getElementById('scan-btn');
    const loader = document.getElementById('loader');
    const resultContainer = document.getElementById('result-container');
    
    // UI Elements
    const output = document.getElementById('output');
    const scoreCircle = document.getElementById('score-circle');
    const scoreMessage = document.getElementById('score-message');
    const webOutput = document.getElementById('web-output');
    const brandOutput = document.getElementById('brand-output');

    if (!target) {
        alert("Please enter a target!");
        return;
    }

    btn.disabled = true;
    loader.classList.remove('hidden');
    resultContainer.classList.add('hidden');
    
    // Clear previous results
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
            // 1. Update Score
            scoreCircle.textContent = data.score + "/100";
            scoreCircle.className = "score"; // reset
            if (data.score >= 80) {
                scoreCircle.classList.add('high');
                scoreMessage.textContent = "Great! Your digital storefront is highly resilient.";
            } else if (data.score >= 50) {
                scoreCircle.classList.add('medium');
                scoreMessage.textContent = "Warning: Multiple vulnerabilities found. Action required.";
            } else {
                scoreCircle.classList.add('low');
                scoreMessage.textContent = "Critical Danger: Business infrastructure is severely compromised.";
            }

            // 2. Update Web Surface List
            data.web_surface.forEach(item => {
                const li = document.createElement('li');
                li.textContent = item;
                if(item.includes("CRITICAL")) li.style.color = "#f85149";
                if(item.includes("WARNING")) li.style.color = "#d29922";
                if(item.includes("SUCCESS")) li.style.color = "#3fb950";
                webOutput.appendChild(li);
            });

            // 3. Update Brand Protection List
            data.brand_protection.forEach(item => {
                const li = document.createElement('li');
                li.textContent = item;
                if(item.includes("DANGER")) li.style.color = "#f85149";
                if(item.includes("SAFE")) li.style.color = "#3fb950";
                brandOutput.appendChild(li);
            });

            // 4. Update Raw Nmap
            output.textContent = data.nmap_results;

        } else {
            output.textContent = `Error: ${data.error}\n${data.details || ''}`;
        }
    } catch (error) {
        alert("Could not connect to the backend server.");
    } finally {
        btn.disabled = false;
    }
}