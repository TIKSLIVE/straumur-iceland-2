import express from "express";
import * as crypto from "crypto";
import bodyParser from "body-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

import "dotenv/config";

import {
  completePaymentRequest,
  getCheckoutById,
  getCheckoutDetails,
  getPaymentRequest,
  getTransactionById,
} from "./vivenu.js";

import { initDb, storePaymentRef, getPaymentRef } from "./db.js";

import {
  isValidId,
  timingSafeStringEqual,
  buildCompositeRef,
  parseCompositeRef,
  validateStraumurWebhookSignature,
  initializeTransaction,
  getStraumurCheckoutStatus,
  createStraumurRefund,
} from "./helpers.js";

const PORT = process.env.PORT || 8080;
const APP_URL = process.env.APP_URL;
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;

// HMAC keys for webhook validation — loaded exclusively from env vars.
// Use WEBHOOK_SECRETS (comma-separated) for key rotation, or WEBHOOK_SECRET for a single key.
const WEBHOOK_SECRETS_RAW =
  process.env.WEBHOOK_SECRETS || process.env.WEBHOOK_SECRET || "";
const HMAC_KEYS = WEBHOOK_SECRETS_RAW.split(",")
  .map((k) => k.trim())
  .filter((k) => k && /^[0-9a-fA-F]+$/.test(k));

const app = express();
app.set("trust proxy", 1);
app.use(
  bodyParser.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString();
    },
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(helmet());

app.use("/webhook", rateLimit({ windowMs: 60_000, max: 60 }));
app.use("/pay/callback", rateLimit({ windowMs: 60_000, max: 60 }));
app.use("/payment/refund", rateLimit({ windowMs: 60_000, max: 30 }));

async function resolveEventId(paymentRequest) {
  if (!paymentRequest.checkoutId || !paymentRequest.successReturnUrl) return "";
  try {
    const returnUrl = new URL(paymentRequest.successReturnUrl);
    const checkoutSecret = returnUrl.searchParams.get("secret");
    if (!checkoutSecret) return "";
    const checkoutDetails = await getCheckoutDetails(
      paymentRequest.checkoutId,
      checkoutSecret
    );
    return checkoutDetails.items?.[0]?.eventId || "";
  } catch (e) {
    console.warn("Could not extract eventId from checkout:", e.message);
    return "";
  }
}

app.get("/pay/callback", async (req, res) => {
  try {
    const { paymentId } = req.query;
    if (!isValidId(paymentId)) return res.status(400).send("Invalid paymentId");

    const paymentRequest = await getPaymentRequest(paymentId);

    if (paymentRequest?.status !== "NEW") {
      console.error("Payment request is already processed");
      return res.status(403).end();
    }

    if (process.env.NODE_ENV !== "production") {
      console.log("Payment Request Received:", paymentRequest);
    }

    const sellerId = paymentRequest.sellerId || "";
    const eventId = await resolveEventId(paymentRequest);
    const compositeRef = buildCompositeRef(sellerId, eventId, paymentId);
    const callbackUrl = `${APP_URL}/straumur/callback?paymentRequestId=${paymentId}`;

    const details = await initializeTransaction(
      paymentRequest.amount * 100,
      compositeRef,
      callbackUrl,
      paymentRequest.currency
    );

    if (details?.success) {
      return res.redirect(details.data);
    }
    return res.status(500).send("Payment processing error");
  } catch (error) {
    console.error("Error processing payment:", error);
    return res.status(500).send("Error processing payment");
  }
});

app.get("/straumur/callback", async (req, res) => {
  try {
    const { paymentRequestId: paymentId, checkoutReference } = req.query;

    if (!isValidId(paymentId))
      return res.status(400).send("Invalid paymentRequestId");
    if (checkoutReference && !isValidId(checkoutReference)) {
      return res.status(400).send("Invalid checkoutReference");
    }

    const paymentRequest = await getPaymentRequest(paymentId);

    if (paymentRequest.status !== "NEW") {
      console.error("Payment request is already processed");
      const redirectUrl =
        paymentRequest.status === "SUCCEEDED"
          ? paymentRequest.successReturnUrl
          : paymentRequest.failureReturnUrl;
      return res.redirect(redirectUrl);
    }

    const checkoutStatus = await getStraumurCheckoutStatus(checkoutReference);
    console.log(
      "Straumur checkout status:",
      checkoutStatus.status,
      "| paymentId:",
      paymentId
    );

    if (checkoutStatus.status === "Completed") {
      const sellerId = paymentRequest.sellerId || "";
      const eventId = await resolveEventId(paymentRequest);
      const compositeRef = buildCompositeRef(sellerId, eventId, paymentId);

      if (checkoutStatus.payfacReference) {
        await storePaymentRef(
          compositeRef,
          "straumur",
          checkoutStatus.payfacReference,
          checkoutReference
        );
        console.log("Stored payfacReference for composite ref:", compositeRef);
      }

      await completePaymentRequest(paymentId);
      return res.redirect(paymentRequest.successReturnUrl);
    }

    return res.redirect(paymentRequest.failureReturnUrl);
  } catch (e) {
    console.error("Error handling Straumur callback:", e);
    return res.status(500).send("Error handling Straumur callback");
  }
});

app.post("/webhook", async (req, res) => {
  try {
    const payload = req.body;
    const {
      checkoutReference,
      merchantReference,
      payfacReference,
      reason,
      success,
      hmacSignature,
      additionalData,
    } = payload;

    if (!hmacSignature) {
      console.error("Missing HMAC signature in webhook payload");
      return res.status(400).send("Missing HMAC signature");
    }

    if (!HMAC_KEYS.length) {
      console.error(
        "No HMAC keys configured (WEBHOOK_SECRET or WEBHOOK_SECRETS)"
      );
      return res.status(500).send("Webhook validation unavailable");
    }

    const signatureResult = validateStraumurWebhookSignature(
      payload,
      hmacSignature,
      HMAC_KEYS
    );

    if (!signatureResult.validated) {
      console.error(
        `Invalid HMAC signature (tried ${HMAC_KEYS.length} key(s))`
      );
      console.error("Received:", hmacSignature);
      if (signatureResult.lastCalculated) {
        console.error(
          "Last key - documented:",
          signatureResult.lastCalculated.documented.base64
        );
        console.error(
          "Last key - webhook order:",
          signatureResult.lastCalculated.webhookOrder.base64
        );
      }
      return res.status(403).send("Invalid HMAC signature");
    }

    if (signatureResult.matchedWebhookOrderOnly) {
      console.log(
        `HMAC matched using webhook field order (key index ${signatureResult.keyIndex})`
      );
    }

    const { paymentRequestId: parsedPaymentRequestId } = parseCompositeRef(
      merchantReference || ""
    );
    const eventType = additionalData?.eventType;
    const paymentId = parsedPaymentRequestId || checkoutReference;

    console.log(
      `Webhook received — event: ${eventType}, paymentId: ${paymentId}, success: ${success}`
    );

    if (!paymentId) {
      console.error("No payment reference found in webhook payload");
      return res.status(400).send("No payment reference found");
    }

    const paymentRequest = await getPaymentRequest(paymentId);
    if (!paymentRequest) {
      console.error(`Payment request not found for ID: ${paymentId}`);
      return res.status(404).send("Payment request not found");
    }

    if (paymentRequest.status === "SUCCEEDED") {
      console.log("Payment request already completed");
      return res.status(200).send("Payment request already completed");
    }

    switch (eventType) {
      case "Authorization":
        if (success === "true") {
          console.log(`Authorization successful for payment: ${paymentId}`);
          await completePaymentRequest(paymentId);
        }
        break;

      case "Capture":
        if (success === "true") {
          await completePaymentRequest(paymentId);
        } else {
          console.error(
            `Capture failed for payment: ${paymentId}, reason: ${reason}`
          );
        }
        break;

      default:
        console.warn(
          `Unknown event type: ${eventType} for payment: ${paymentId}`
        );
    }

    if (additionalData) {
      console.log("Webhook additional data:", {
        eventType: additionalData.eventType,
        paymentMethod: additionalData.paymentMethod,
        threeDAuthenticated: additionalData.threeDAuthenticated,
      });
    }

    return res.status(200).send("Webhook processed successfully");
  } catch (error) {
    console.error("Error processing Straumur webhook:", error);
    return res.status(500).send("Error processing webhook");
  }
});

app.post("/payment/refund", async (req, res) => {
  try {
    const payload = req.body;

    if (payload.type !== "payment.refund") {
      return res.status(400).send("Unsupported type");
    }

    const signature = crypto
      .createHmac("sha256", GATEWAY_SECRET)
      .update(req.rawBody)
      .digest("hex");

    const requestSignature = req.headers["x-vivenu-signature"];
    if (typeof requestSignature !== "string") {
      return res.status(400).send("Missing signature");
    }
    if (
      !timingSafeStringEqual(
        signature.toLowerCase(),
        requestSignature.toLowerCase()
      )
    ) {
      return res.status(400).send("Invalid signature");
    }

    if (process.env.NODE_ENV !== "production") {
      console.log("Refund payload:", payload);
    }

    const {
      psp,
      amount,
      currency = "ISK",
      refundReason,
      transactionId,
    } = payload.data;

    const transactionDetails = await getTransactionById(transactionId);
    const checkoutDetails = await getCheckoutById(
      transactionDetails.checkoutId
    );
    const paymentRequestId = checkoutDetails.docs[0]?.paymentRequestId;

    const refundCompositeRef = buildCompositeRef(
      transactionDetails.sellerId || "",
      transactionDetails.eventId || "",
      paymentRequestId
    );

    const stored = await getPaymentRef(refundCompositeRef);
    const checkoutStatus = await getStraumurCheckoutStatus(
      stored?.checkoutReference || paymentRequestId
    );
    console.log("Checkout status for refund:", checkoutStatus.status);

    const payfacRef = stored?.payfacReference || psp?.slice(0, 16);
    console.log("payfacRef:", payfacRef, "| from db:", !!stored);

    if (!currency || !payfacRef || !amount) {
      return res.status(400).send("Missing required refund parameters");
    }

    const refundResult = await createStraumurRefund(
      refundCompositeRef,
      payfacRef,
      Math.round(amount * 100),
      currency,
      refundReason
    );

    if (refundResult.success) {
      console.log("Refund processed successfully:", refundResult.data);
      return res.status(200).json({
        reference: `reference!straumur:${refundCompositeRef}:${payfacRef}`,
      });
    }

    console.error("Refund failed:", refundResult.error);
    return res.status(500).json({ success: false, error: "Refund failed" });
  } catch (e) {
    console.error("Error handling refund:", e);
    return res
      .status(500)
      .json({ success: false, error: "Internal server error" });
  }
});

app.get("/", async (req, res) => {
  res.send("API RUNNING FOR MERCHANT => ");
});

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Listening at http://localhost:${PORT}`);
  });
});
