import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();
app.use(cors());
app.use(express.json());

app.post("/llm", async (req, res) => {
    try {
        const ollamaResponse = await fetch("http://localhost:11434/api/generate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(req.body)
        });

        const data = await ollamaResponse.json();
        res.json(data);

    } catch (err) {
        console.error("Proxy Error:", err);
        res.status(500).json({ error: err.message });
    }
});

app.listen(5001, () => {
    console.log("Ollama proxy running on http://localhost:5001");
});
