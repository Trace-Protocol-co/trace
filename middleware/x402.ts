/**
 * x402 payment layer for the OKX.AI ASP endpoint (/agent/verify).
 *
 * Implements the x402 "exact" scheme challenge required by OKX OnchainOS /
 * A2MCP so that unpaid requests receive a well-formed HTTP 402 with an
 * `accepts` array (in both the JSON body — x402 v1 — and the base64
 * `PAYMENT-REQUIRED` response header — x402 v2). Settlement token is USDT0 on
 * X Layer (chainId 196 / eip155:196).
 *
 * Docs: https://web3.okx.com/onchainos/dev-docs/okxai/howtomcp
 *       https://web3.okx.com/onchainos/dev-docs/payments/app
 */
import type { Request, Response } from "express";

// ── Config (all overridable via env, no redeploy needed on Render) ──────────
export const X402 = {
  version: 1,
  scheme: "exact",
  network: process.env.X402_NETWORK ?? "eip155:196", // X Layer
  // USDT0 on X Layer, 6 decimals
  asset: (process.env.X402_ASSET ?? "0x779ded0c9e1022225f8e0630b35a9b54be713736").toLowerCase(),
  assetName: process.env.X402_ASSET_NAME ?? "USD₮0",
  assetVersion: process.env.X402_ASSET_VERSION ?? "1",
  // Price in smallest units (6 decimals). Default "0" = direct-accept / fee 0.
  amount: process.env.X402_PRICE ?? "0",
  payTo: process.env.X402_PAY_TO ?? "0x00dC0f3ff1F2bca6b3d007684cC25a766c9815f4",
  maxTimeoutSeconds: Number(process.env.X402_TIMEOUT ?? 300),
  // Optional x402 facilitator (OKX OnchainOS). If set, payments are verified
  // and settled through it; otherwise we run in direct-accept mode.
  facilitatorUrl: process.env.X402_FACILITATOR_URL ?? "",
};

/** Absolute URL of the resource being paid for. */
function resourceUrl(req: Request): string {
  const host = req.get("host") ?? "trace-cbvb.onrender.com";
  const proto = req.protocol || "https";
  return `${proto}://${host}/agent/verify`;
}

/** Build a single x402 `accepts` entry. */
function buildAcceptsEntry(req: Request) {
  return {
    scheme: X402.scheme,
    network: X402.network,
    // x402 v1 uses `maxAmountRequired`; OKX docs/v2 use `amount`. Emit both so
    // every validator/client (x402-check, x402-validate, task-402-pay) matches.
    maxAmountRequired: X402.amount,
    amount: X402.amount,
    resource: resourceUrl(req),
    description: "TRACE media-authenticity verification — returns a verdict (VERIFIED_ORIGINAL / MODIFIED / AI_GENERATED / UNVERIFIED) with confidence and on-chain provenance.",
    mimeType: "application/json",
    payTo: X402.payTo,
    asset: X402.asset,
    maxTimeoutSeconds: X402.maxTimeoutSeconds,
    extra: { name: X402.assetName, version: X402.assetVersion },
    // Tell the payer exactly how to call the paid endpoint and what body to send.
    outputSchema: {
      input: {
        type: "http",
        method: "POST",
        bodyType: "json",
        body: {
          type: "object",
          properties: {
            url: { type: "string", description: "Public https URL of the image or video to verify" },
            image_url: { type: "string", description: "Alias for `url`" },
          },
          required: ["url"],
        },
        // A multipart file upload under the form field `file` is also accepted.
        alternativeBody: { type: "multipart/form-data", field: "file" },
      },
      output: {
        type: "object",
        properties: {
          verdict: { type: "string" },
          confidence: { type: "number" },
          summary: { type: "string" },
          action_recommendation: { type: "string" },
        },
      },
    },
  };
}

/** Full x402 challenge object (used for the v1 JSON body). */
export function buildChallenge(req: Request, error = "X-PAYMENT header is required") {
  return {
    x402Version: X402.version,
    error,
    accepts: [buildAcceptsEntry(req)],
  };
}

/** base64 JSON for the x402 v2 `PAYMENT-REQUIRED` response header. */
function paymentRequiredHeader(challenge: ReturnType<typeof buildChallenge>): string {
  return Buffer.from(JSON.stringify(challenge)).toString("base64");
}

/**
 * Emit the 402 challenge. Sends the accepts array in BOTH the JSON body
 * (x402 v1) and the base64 `PAYMENT-REQUIRED` header (x402 v2), before any
 * business validation.
 */
export function sendChallenge(req: Request, res: Response, error?: string): Response {
  const challenge = buildChallenge(req, error);
  res.setHeader("PAYMENT-REQUIRED", paymentRequiredHeader(challenge));
  return res.status(402).json(challenge);
}

type PaymentAuth = {
  from?: string;
  to?: string;
  value?: string;
  validAfter?: string;
  validBefore?: string;
  nonce?: string;
};

/** Decode the base64 X-PAYMENT header into its JSON payload. */
function decodePaymentHeader(header: string): {
  x402Version?: number;
  scheme?: string;
  network?: string;
  payload?: { signature?: string; authorization?: PaymentAuth };
} | null {
  try {
    return JSON.parse(Buffer.from(header, "base64").toString("utf8"));
  } catch {
    try {
      // Some clients send raw (already-decoded) JSON.
      return JSON.parse(header);
    } catch {
      return null;
    }
  }
}

export type VerifyResult = { ok: boolean; reason?: string; response?: string };

/**
 * Verify an incoming payment. If a facilitator is configured, verify + settle
 * through it; otherwise run direct-accept structural validation (scheme /
 * network / asset / payTo / amount). Returns a value for the
 * `X-PAYMENT-RESPONSE` header on success.
 */
export async function verifyPayment(req: Request): Promise<VerifyResult> {
  const header = (req.headers["x-payment"] as string) || (req.headers["X-PAYMENT"] as string);
  if (!header) return { ok: false, reason: "missing X-PAYMENT header" };

  const decoded = decodePaymentHeader(header);
  if (!decoded) return { ok: false, reason: "X-PAYMENT header is not valid base64 JSON" };

  // Facilitator path (verify + settle on-chain via OKX OnchainOS).
  if (X402.facilitatorUrl) {
    try {
      const paymentRequirements = buildAcceptsEntry(req);
      const body = { x402Version: X402.version, paymentPayload: decoded, paymentRequirements };
      const vr = await fetch(`${X402.facilitatorUrl.replace(/\/$/, "")}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
      const vj = (await vr.json().catch(() => ({}))) as { isValid?: boolean; invalidReason?: string };
      if (!vr.ok || vj.isValid !== true) {
        return { ok: false, reason: vj.invalidReason || `facilitator rejected payment (HTTP ${vr.status})` };
      }
      const sr = await fetch(`${X402.facilitatorUrl.replace(/\/$/, "")}/settle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(15000),
      });
      const sj = await sr.json().catch(() => ({}));
      return { ok: true, response: Buffer.from(JSON.stringify(sj)).toString("base64") };
    } catch (err) {
      return { ok: false, reason: `facilitator error: ${err instanceof Error ? err.message : String(err)}` };
    }
  }

  // Direct-accept path (fee 0 / no facilitator): structurally validate the
  // signed payment envelope matches our terms.
  const auth = decoded.payload?.authorization;
  if (decoded.scheme && decoded.scheme !== X402.scheme) {
    return { ok: false, reason: `scheme mismatch: got ${decoded.scheme}, expected ${X402.scheme}` };
  }
  if (decoded.network && decoded.network !== X402.network) {
    return { ok: false, reason: `network mismatch: got ${decoded.network}, expected ${X402.network}` };
  }
  if (auth?.to && auth.to.toLowerCase() !== X402.payTo.toLowerCase()) {
    return { ok: false, reason: "payment recipient does not match payTo" };
  }
  if (auth?.value !== undefined) {
    try {
      if (BigInt(auth.value) < BigInt(X402.amount)) {
        return { ok: false, reason: `underpaid: ${auth.value} < required ${X402.amount}` };
      }
    } catch {
      /* non-numeric value — ignore in direct-accept mode */
    }
  }

  const receipt = {
    success: true,
    network: X402.network,
    payer: auth?.from ?? null,
    payTo: X402.payTo,
    asset: X402.asset,
    amount: auth?.value ?? X402.amount,
    settlement: "direct-accept",
  };
  return { ok: true, response: Buffer.from(JSON.stringify(receipt)).toString("base64") };
}
