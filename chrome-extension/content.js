// Observe Gmail DOM to detect opened emails
const observer = new MutationObserver(() => {
    const emailNode = document.querySelector('[data-legacy-message-id]');
    if(emailNode) {
        const messageId = emailNode.getAttribute('data-legacy-message-id');
        console.log("Detected Gmail API Message ID:", messageId);
        // Extract subject and body from DOM
        const subject = document.querySelector('h2.hP')?.innerText || "";
        const body = document.querySelector('.a3s.aiL')?.innerText || "";
        const bodyElement = document.querySelector('.a3s.aiL');
        const bodyHTML = bodyElement?.innerHTML || "";
        const linkElements = Array.from(bodyElement?.querySelectorAll("a") || []);
        const links = linkElements.map(a => ({
            anchor: a.innerText.trim(),
            href: a.href.trim()
        }));

        // Send the messageId to backend
        fetch('http://localhost:5000/getEmail', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ messageId })
        })
        .then(res => res.json())
        .then(data => {
    const headers = data.payload?.headers || [];

    // Helper to get header value
    const getHeader = (name) => headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value || null;

    const result = { //headers section
        "Authentication-Results": getHeader("Authentication-Results"),
        "ARC-Seal": getHeader("ARC-Seal"),
        "ARC-Authentication-Results": getHeader("ARC-Authentication-Results"),
        "Received-SPF": getHeader("Received-SPF"),
        "DKIM-Signature": getHeader("DKIM-Signature"),
        "X-Google-DKIM-Signature": getHeader("X-Google-DKIM-Signature"),
        "Return-Path": getHeader("Return-Path"),
        "From": getHeader("From"),
        "Reply-To": getHeader("Reply-To"),
        "Message-ID": getHeader("Message-ID"),
        "Received": headers.filter(h => h.name.toLowerCase() === "received").map(h => h.value),
        subject,
        body,
        bodyHTML,
        links
    };

            console.log("Phishing-relevant headers:", result);

            // Optionally, display in popup (if you have a <pre> or div)
            // Send JSON to background script
            chrome.runtime.sendMessage({ type: "EMAIL_JSON", payload: result });

        })
        .catch(err => console.error(err));
    }
});

// Observe the whole body for changes
observer.observe(document.body, { childList: true, subtree: true });
