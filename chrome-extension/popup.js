document.addEventListener("DOMContentLoaded", () => {
    const container = document.getElementById("emailResult");

    chrome.runtime.sendMessage({ type: "GET_LATEST_EMAIL" }, (response) => {
        const data = response?.payload;

        if (!data) {
            container.innerText = "Open an email to see phishing evaluation.";
            return;
        }

        let html = `<h3>Phishing Evaluation</h3>`;
        html += `<p><strong>Score:</strong> ${data.phishingScore}</p>`;
        html += `<p><strong>Category:</strong> ${data.phishingCategory}</p>`;
        html += `<p><strong>Reasons:</strong><ul>`;
        data.phishingReasons.forEach(r => { html += `<li>${r}</li>`; });
        html += `</ul></p>`;

        html += `<h4>Email Info</h4>`;
        html += `<p><strong>From:</strong> ${data.From}</p>`;
        html += `<p><strong>Reply-To:</strong> ${data["Reply-To"] || ""}</p>`;
        html += `<p><strong>Message-ID:</strong> ${data["Message-ID"]}</p>`;
        html += `<p><strong>Subject:</strong> ${data.subject || ""}</p>`;

       
        if (data.llmAnalysis) {
            html += `
                <h3 style="margin-top:15px;">Deep AI Analysis</h3>
                <p><strong>LLM Score:</strong> ${data.llmAnalysis.score}</p>
                <p><strong>Explanation:</strong> ${data.llmAnalysis.explanation}</p>
            `;
        }

        container.innerHTML = html;
    });
});
