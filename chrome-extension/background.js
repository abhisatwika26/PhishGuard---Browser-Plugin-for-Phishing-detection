let latestEmailJson = null;

// Trusted sender domains
const trustedDomains = [
    "google.com",
    "gmail.com",
    "amazon.com",
    "apple.com",
    "accounts.google.com",
    "paypal.com",
    "microsoft.com",
    "youtube.com",
    "outlook.com"
];

// Suspicious keywords for content scanning
const suspiciousKeywords = [
    "urgent", "immediately", "verify", "account", "login", "security alert",
    "password", "suspended", "restricted", "action required", "confirm", "update", "failed", "unusual activity"
];

// Helper functions
function getSenderDomain(fromValue) {
    if (!fromValue) return "";
    const emailMatch = fromValue.match(/<(.+?)>/);
    const email = emailMatch ? emailMatch[1] : fromValue;
    const parts = email.split("@");
    return parts.length > 1 ? parts[1].toLowerCase() : "";
}

function isSuspiciousDomain(domain, subject, body) {
    if (!domain) return false;
    if (domain.length > 25) return true;
    if (/\d/.test(domain)) return true;
    if (domain.includes('-secure') || domain.includes('verify')) return true;
    if (domain.includes('alert') || domain.includes('security')) return true;
    if (subject && subject.toLowerCase().includes("account") && !trustedDomains.includes(domain)) return true;
    return false;
}

function scoreDomainReputation(fromValue, subject, body) {
    const domain = getSenderDomain(fromValue);
    if (!domain) return { score: 10, reason: `Sender domain is missing or unparsable; medium risk.` };
    if (trustedDomains.includes(domain)) return { score: 0, reason: `Sender domain (${domain}) is trusted.` };
    if (isSuspiciousDomain(domain, subject, body)) return { score: 30, reason: `Domain (${domain}) has suspicious patterns or mismatched context.` };
    return { score: 10, reason: `Domain (${domain}) is unrecognized; medium risk.` };
}

function scoreContent(subject, body) {
    let score = 0;
    const reasons = [];
    const text = ((subject || "") + " " + (body || "")).toLowerCase();
    suspiciousKeywords.forEach(keyword => {
        if (text.includes(keyword)) {
            score += 10;
            reasons.push(`Suspicious keyword detected: "${keyword}"`);
        }
    });
    return { score, reasons };
}

function checkLinkMismatch(links) {
    let score = 0;
    const reasons = [];

    if (!links || !Array.isArray(links) || links.length === 0) {
        return { score, reasons };
    }

    const badPatterns = ["bit.ly", "tinyurl", "is.gd", "t.ly", "rb.gy", "rebrand.ly", "blogspot", "sites.google.com", "goo.gl", "ow.ly"];

    links.forEach(link => {
        const anchorRaw = (link.anchor || "").trim();
        const hrefRaw = (link.href || "").trim();

        const anchor = anchorRaw.toLowerCase();
        const href = hrefRaw.toLowerCase();
        if (!href) return;

        let hrefDomain = "";
        try {
            hrefDomain = new URL(href).hostname.replace(/^www\./, "");
        } catch (e) {
            score += 10;
            reasons.push(`Unparsable link href: "${hrefRaw}"`);
            return;
        }

        const anchorLooksLikeDomain = /^[a-z0-9.-]+\.[a-z]{2,}$/.test(anchor);
        if (anchorLooksLikeDomain) {
            const anchorDomain = anchor.replace(/^www\./, "");
            if (!hrefDomain.includes(anchorDomain)) {
                score += 15;
                reasons.push(`Anchor text "${anchorRaw}" suggests domain "${anchorDomain}" but actual link goes to "${hrefDomain}".`);
            }
        }

        if (/(?:\.com|\.net|\.org|\.io|\.co|\.in)/.test(anchor)) {
            const cleanedAnchor = anchor.replace(/^www\./, "");
            if (!hrefDomain.includes(cleanedAnchor)) {
                score += 10;
                reasons.push(`Displayed domain "${anchorRaw}" differs from actual link domain "${hrefDomain}".`);
            }
        }

        if (badPatterns.some(p => hrefDomain.includes(p))) {
            score += 5;
            reasons.push(`Suspicious redirect/shortener used in link: ${hrefDomain}.`);
        }

        if (/xn--/.test(hrefDomain)) {
            score += 8;
            reasons.push(`Punycode/IDN domain detected in link: ${hrefDomain}.`);
        }

        if (/[^a-z0-9.-]/.test(hrefDomain) || (hrefDomain.replace(/[^0-9]/g, "").length > 3 && /\d/.test(hrefDomain))) {
            score += 5;
            reasons.push(`Suspicious domain format in link: ${hrefDomain}.`);
        }
    });

    return { score, reasons };
}

chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
    if (message.type === "EMAIL_JSON") {
        const data = message.payload;
        latestEmailJson = data;

        let score = 0;
        const reasons = [];

        const auth = (data["Authentication-Results"] || "").toLowerCase();
        if (auth.includes("spf=fail")) { score += 30; reasons.push("SPF check failed"); }
        if (auth.includes("dkim=fail")) { score += 40; reasons.push("DKIM check failed"); }
        if (auth.includes("dmarc=fail")) { score += 40; reasons.push("DMARC check failed"); }

        if (!data["ARC-Seal"]) { score += 20; reasons.push("Missing ARC-Seal header"); }

        const from = data["From"] || "";
        const replyTo = data["Reply-To"] || from;
        if (from && replyTo && from.toLowerCase() !== replyTo.toLowerCase()) { 
            score += 30; 
            reasons.push("From and Reply-To addresses do not match"); 
        }

        const msgId = data["Message-ID"] || "";
        if (!msgId.includes("@")) { score += 20; reasons.push("Message-ID format suspicious"); }

        if (data["Received-SPF"] && data["Received-SPF"].toLowerCase().includes("fail")) { 
            score += 20; 
            reasons.push("Received-SPF check failed"); 
        }

        if (data["DKIM-Signature"] && data["DKIM-Signature"].toLowerCase().includes("fail")) { 
            score += 20; 
            reasons.push("DKIM-Signature check failed"); 
        }

        if (data["X-Google-DKIM-Signature"] && data["X-Google-DKIM-Signature"].toLowerCase().includes("fail")) { 
            score += 20; 
            reasons.push("X-Google-DKIM-Signature check failed"); 
        }

        const importantHeaders = ["Authentication-Results", "ARC-Seal", "From", "Message-ID"];
        importantHeaders.forEach(h => {
            if (!data[h]) { 
                score += 10; 
                reasons.push(`Missing important header: ${h}`); 
            }
        });

        const domainResult = scoreDomainReputation(data.From, data.subject, data.body);
        score += domainResult.score;
        reasons.push(domainResult.reason);

        const contentResult = scoreContent(data.subject, data.body);
        score += contentResult.score;
        reasons.push(...contentResult.reasons);

        const linkResult = checkLinkMismatch(data.links || []);
        score += linkResult.score;
        reasons.push(...linkResult.reasons);

        let category = "Safe";
        if (score > 80) category = "Risky";
        else if (score > 40) category = "Medium(Potential Risk)";

        latestEmailJson.phishingScore = score;
        latestEmailJson.phishingCategory = category;
        latestEmailJson.phishingReasons = reasons;

        console.log("Phishing evaluation:", latestEmailJson);

        // ==========================================================
        // =============== LLM CALL FOR MEDIUM RISK =================
        // ==========================================================
        if (category === "Medium(Potential Risk)") {

            const payload = {
                subject: data.subject || "",
                body_text: data.body || "",
                links: (data.links || []).map(l => l.href || "")
            };

            const promptText = `
You are an experienced email security analyst. I will give you structured information about an email.
Return only JSON:

{
  "score": 0-10,
  "explanation": "short reason"
}
Email:
${JSON.stringify(payload, null, 2)}
            `;

            try {
                console.log("LLM request payload:", {
                    model: "llama3.1:8b",
                    prompt: promptText
                });

                const response = await fetch("http://localhost:5001/llm", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        model: "llama3.1:8b",
                        prompt: promptText,
                        stream: false
                    })
                });

                console.log("LLM raw response:", response);

                if (!response.ok) {
                    throw new Error("HTTP " + response.status);
                }

                const result = await response.json();
                console.log("LLM parsed JSON:", result);

                latestEmailJson.llmAnalysis = result;

            } catch (err) {
                console.error("🔥 LLM CALL FAILED:", err);
                latestEmailJson.llmAnalysis = {
                    score: null,
                    explanation: "LLM analysis failed."
                };
            }
        }
        // ==========================================================

        return true; // listener finished
    }

    // Serve latest email to popup
    if (message.type === "GET_LATEST_EMAIL") {
        sendResponse({ payload: latestEmailJson });
        return true;
    }
});

