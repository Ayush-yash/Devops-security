const crypto = require('crypto');

const SERVER_URL = "http://localhost:8080/api/v1/webhooks/github";
const WEBHOOK_SECRET = "test_webhook_secret";

async function testWebhook() {
    console.log("=============================================================");
    console.log("🚀 Testing Production-style GitHub Webhook Integration...");
    console.log("=============================================================");

    const payload = {
        ref: "refs/heads/main",
        after: "9bf4c21000000000000000000000000000000000",
        repository: {
            name: "payment-gateway",
            html_url: "https://github.com/shieldops/payment-gateway"
        },
        head_commit: {
            id: "9bf4c21000000000000000000000000000000000",
            message: "Verify GitHub Webhook integration and OPA gates",
            author: {
                name: "Alex Dev",
                username: "alex-dev"
            }
        },
        pusher: {
            name: "alex-dev"
        }
    };

    const bodyString = JSON.stringify(payload);
    
    // Generate HMAC-SHA256 signature matching GitHub's security implementation
    const hmac = crypto.createHmac('sha256', WEBHOOK_SECRET);
    const signature = hmac.update(bodyString).digest('hex');
    const signatureHeader = `sha256=${signature}`;

    const deliveryId = "dlv-" + Math.random().toString(36).substring(2, 15);

    try {
        console.log(`Sending Webhook Request: X-GitHub-Delivery: ${deliveryId}`);
        const response = await fetch(SERVER_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": deliveryId,
                "X-Hub-Signature-256": signatureHeader
            },
            body: bodyString
        });

        const status = response.status;
        const data = await response.json();
        console.log(`Response Status: ${status}`);
        console.log("Response Body:", data);

        if (status === 202) {
            console.log("✅ SUCCESS: Webhook signature verified and pipeline run registered!");
        } else {
            console.error("❌ FAILED: Webhook rejected!");
        }

        // Test duplicate detection
        console.log("\n-------------------------------------------------------------");
        console.log("Testing duplicate delivery detection (Idempotency)...");
        const dupResponse = await fetch(SERVER_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": deliveryId, // same ID
                "X-Hub-Signature-256": signatureHeader
            },
            body: bodyString
        });
        
        const dupStatus = dupResponse.status;
        const dupData = await dupResponse.json();
        console.log(`Duplicate Response Status: ${dupStatus}`);
        console.log("Duplicate Response Body:", dupData);

        if (dupStatus === 200 && dupData.message.includes("Duplicate")) {
            console.log("✅ SUCCESS: Duplicate event was ignored correctly!");
        } else {
            console.error("❌ FAILED: Duplicate check did not trigger!");
        }

        // Test signature failure
        console.log("\n-------------------------------------------------------------");
        console.log("Testing signature failure detection...");
        const failResponse = await fetch(SERVER_URL, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": "dlv-fail-" + Math.random().toString(36).substring(2, 15),
                "X-Hub-Signature-256": "sha256=invalidsignature"
            },
            body: bodyString
        });
        
        const failStatus = failResponse.status;
        const failData = await failResponse.json();
        console.log(`Signature Fail Response Status: ${failStatus}`);
        console.log("Signature Fail Response Body:", failData);

        if (failStatus === 401) {
            console.log("✅ SUCCESS: Webhook with invalid signature was blocked!");
        } else {
            console.error("❌ FAILED: Webhook with invalid signature was processed!");
        }

    } catch (err) {
        console.error("Connection Error:", err.message);
    }
}

testWebhook();
