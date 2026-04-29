import { createClient } from "@libsql/client";

const db = createClient({
  url: process.env.TURSO_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

export async function initDb() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS payment_refs (
      id TEXT PRIMARY KEY,
      psp TEXT NOT NULL,
      payfac_reference TEXT NOT NULL,
      checkout_reference TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch())
    )
  `);
  console.log("Database initialized");
}

export async function storePaymentRef(compositeRef, psp, payfacReference, checkoutReference) {
  await db.execute({
    sql: `INSERT OR REPLACE INTO payment_refs (id, psp, payfac_reference, checkout_reference)
          VALUES (?, ?, ?, ?)`,
    args: [compositeRef, psp, payfacReference, checkoutReference],
  });
}

export async function getPaymentRef(compositeRef) {
  const result = await db.execute({
    sql: `SELECT psp, payfac_reference, checkout_reference FROM payment_refs WHERE id = ?`,
    args: [compositeRef],
  });
  const row = result.rows[0];
  if (!row) return null;
  return {
    psp: row.psp,
    payfacReference: row.payfac_reference,
    checkoutReference: row.checkout_reference,
  };
}
