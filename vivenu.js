import { nanoid } from "nanoid";
import fetch from "node-fetch";

const VIVENU_URL = process.env.VIVENU_URL || "https://vivenu.com";
const API_KEY = process.env.API_KEY;
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;

export const getPaymentRequest = async (paymentId) => {
  try {
    const response = await fetch(
      `${VIVENU_URL}/api/payments/requests/${paymentId}`,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Bearer ${API_KEY}`,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch payment request: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching payment request:", error.message);
    throw error;
  }
};

export const getTransactionById = async (transactionId) => {
  try {
    const response = await fetch(
      `${VIVENU_URL}/api/transactions/${transactionId}`,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Bearer ${API_KEY}`,
        },
      }
    );

    if (!response.ok) {
      throw new Error(
        `Failed to fetch transaction request: ${response.status}`
      );
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching transaction request:", error.message);
    throw error;
  }
};

export const getCheckoutById = async (checkoutId) => {
  try {
    const response = await fetch(
      `${VIVENU_URL}/api/payments?checkoutId=${checkoutId}`,
      {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Bearer ${API_KEY}`,
        },
      }
    );

    if (!response.ok) {
      throw new Error(
        `Failed to fetch transaction request: ${response.status}`
      );
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching transaction request:", error.message);
    throw error;
  }
};

export const completePaymentRequest = async (paymentId) => {
  try {
    const response = await fetch(
      `${VIVENU_URL}/api/payments/requests/${paymentId}/confirm`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Bearer ${API_KEY}`,
        },
        body: JSON.stringify({
          gatewaySecret: GATEWAY_SECRET,
          reference: nanoid(),
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to complete payment request: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("Error completing payment request:", error.message);
    throw error;
  }
};
