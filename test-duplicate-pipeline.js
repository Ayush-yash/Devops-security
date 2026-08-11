const crypto = require('crypto');

const SERVER_URL = "http://localhost:8080/api/v1/webhooks/github";
const WEBHOOK_SECRET = "test_webhook_secret";

async function testDuplicateGating() {
    console.log("=============================================================");
    console.log("🚀 Testing Concurrent Pipeline Duplicate Prevention...");
    console.log("=============================================================");

    const commitSha = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
    const payload = {
        ref: "refs/heads/feature/duplicate-test",
        after: commitSha,
        repository: {
            name: "payment-gateway",
            html_url: "https://github.com/shieldops/payment-gateway"
        },
        head_commit: {
            id: commitSha,
            message: "Test concurrent gating",
            author: { name: "Tester", username: "tester" }
        },
        pusher: { name: "tester" }
    };

    const bodyString = JSON.stringify(payload);
    
    // Generate signature
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const signature = hmac.update(bodyString).digest('hex');
    const signatureHeader = `sha256=${signature}`;

    const deliveryId1 = "dlv-dup-1-" + Math.random().toString(36).substring(2, 10);
    const deliveryId2 = "dlv-dup-2-" + Math.random().toString(36).substring(2, 10);

    try {
        console.log("Sending FIRST webhook push (should be Accepted)...");
        const res1 = await fetch(SERVER_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": deliveryId1,
                "X-Hub-Signature-256": signatureHeader
            },
            body: bodyString
        });

        console.log(`First Response: ${res1.status}`, await res1.json());

        console.log("\nSending SECOND webhook push with SAME commit/branch coordinates (should be Rejected with 409 Conflict)...");
        const res2 = await fetch(SERVER_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": deliveryId2,
                "X-Hub-Signature-256": signatureHeader
            },
            body: bodyString
        });

        const status2 = res2.status;
        const data2 = await res2.json();
        console.log(`Second Response: ${status2}`);
        console.log("Second Body:", data2);

        if (status2 === 409) {
            console.log("\n✅ SUCCESS: Orchestrator blocked duplicate concurrent pipeline execution with 409 Conflict!");
        } else {
            console.error("\n❌ FAILED: Duplicate concurrent pipeline was not blocked!");
        }

    } catch (err) {
        console.error("Connection Error:", err.message);
    }
}

testDuplicateGating();
