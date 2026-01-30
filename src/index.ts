import crypto from "crypto";
import express from "express";

const app = express();
app.use(express.json());
app.use((req, _res, next) => {
  console.log(`[Example-App-Server] ${req.method} ${req.url}`, req.body);
  next();
});

const backendUrl = process.env.UA_BACKEND_URL || "http://localhost:3001";
const backendId = process.env.UA_BACKEND_ID || "";
const apiSecret = process.env.UA_API_SECRET || "";
const blacklist = new Set((process.env.UA_BACKEND_BLACKLIST || "").split(",").map((s) => s.trim()).filter(Boolean));

function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(Buffer.from(input, "utf8")).digest("hex");
}

app.post("/select-backend", (req, res) => {
  const { projectId, canonicalRequest } = req.body || {};
  let { backendIds } = req.body || {};
  if (typeof backendIds === "string") {
    try {
      backendIds = JSON.parse(backendIds);
    } catch {
      backendIds = backendIds
        .replace(/^\[|\]$/g, "")
        .split(",")
        .map((s: string) => s.trim())
        .filter(Boolean);
    }
  }
  if (!projectId || !canonicalRequest || !Array.isArray(backendIds)) {
    res.status(400).json({
      error: "Invalid request",
      missing: {
        projectId: !projectId,
        canonicalRequest: !canonicalRequest,
        backendIds: !Array.isArray(backendIds)
      }
    });
    return;
  }
  let selected = backendIds.find((id: string) => id === backendId && !blacklist.has(id));
  if (!selected) {
    selected = backendIds.find((id: string) => !blacklist.has(id));
  }
  if (!selected) {
    res.status(400).json({ error: "No backend available" });
    return;
  }
  res.json({ backendId: selected, requestHash: sha256Hex(canonicalRequest) });
});

app.post("/verify", async (req, res) => {
  const { projectId, canonicalRequest, token } = req.body || {};
  if (!projectId || !canonicalRequest || !token) {
    res.status(400).json({
      error: "Invalid request",
      missing: {
        projectId: !projectId,
        canonicalRequest: !canonicalRequest,
        token: !token
      }
    });
    return;
  }
  if (!apiSecret) {
    res.status(500).json({ error: "Missing UA_API_SECRET" });
    return;
  }
  const requestHash = sha256Hex(canonicalRequest);
  const response = await fetch(`${backendUrl}/api/v1/app/decodeToken`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-ua-api-secret": apiSecret
    },
    body: JSON.stringify({ projectId, token, expectedRequestHash: requestHash })
  });
  const raw = await response.text();
  if (!response.ok) {
    res.status(400).json({ error: raw });
    return;
  }
  const payload = JSON.parse(raw);
  console.log(payload);
  const verdict = payload.verdict?.isTrusted ? "trusted" : "rejected";
  res.json({ verdict, reasonCodes: payload.verdict?.reasonCodes || [] });
});

app.listen(4000, () => {
  console.log("Example App Server running on http://localhost:4000");
});
