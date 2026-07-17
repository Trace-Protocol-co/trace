/**
 * TRACE — TypeScript Data Middleware v2
 * Updated for v2 contract: description field, staking, delegation TX builders.
 */

import "dotenv/config";
import { SuiJsonRpcClient as SuiClient, getJsonRpcFullnodeUrl as getFullnodeUrl, type SuiObjectChangeCreated } from "@mysten/sui/jsonRpc";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import * as crypto from "crypto";


// ============================================================================
// Configuration
// ============================================================================

export const CONFIG = {
  SUI_NETWORK: "testnet" as const,
  SUI_RPC: process.env.SUI_RPC_URL ?? "https://sui-testnet.nodeinfra.com",
  PACKAGE_ID: process.env.TRACE_PACKAGE_ID ?? "0x0",
  TREASURY_ID: process.env.TRACE_TREASURY_ID ?? "0x0",
  WALRUS_AGGREGATOR: process.env.WALRUS_AGGREGATOR ?? "https://aggregator.walrus-testnet.walrus.space",
  WALRUS_PUBLISHER: process.env.WALRUS_PUBLISHER ?? "https://publisher.walrus-testnet.walrus.space",
  WALRUS_EXPLORER: "https://walruscan.com/testnet/blob",
  WALRUS_EPOCHS: parseInt(process.env.WALRUS_EPOCHS ?? "53"),
  CLOCK_ID: "0x6",
} as const;

// ============================================================================
// Edit & Integrity Enums
// ============================================================================

export const EditType = {
  ORIGINAL:    0,
  TRIM:        1,
  COLOR_GRADE: 2,
  SUBTITLE:    3,
  AI_REMIX:    4,
  CROP:        5,
  MERGE:       6,
  TRANSLATE:   7,
} as const;

export type EditTypeValue = (typeof EditType)[keyof typeof EditType];

// ============================================================================
// Types
// ============================================================================

export interface MediaBlob {
  bytes: Uint8Array;
  mimeType: string;
  filename: string;
}

export interface WalrusCertificate {
  blobId: string;
  endEpoch: number;
  rawCert: Uint8Array;
}

export interface RegisterMediaInput {
  blob: MediaBlob;
  parentId?: string;
  editType: EditTypeValue;
  aiScore: number;
  description: string;
}

export interface RegisterMediaResult {
  suiTx: string;
  mediaId: string;
  editRecordId?: string;
  blobId: string;
  certificateUrl: string;
  timestamp: number;
}

export interface TelemetryOutput {
  mediaId: string;
  editRecordId?: string;
  blobId: string;
  suiTx: string;
  gasUsed: string;
  timestamp: number;
}

// ============================================================================
// Client Singleton
// ============================================================================

let _client: SuiClient | null = null;

export function getSuiClient(): SuiClient {
  if (!_client) _client = new SuiClient({ url: CONFIG.SUI_RPC, network: CONFIG.SUI_NETWORK });
  return _client;
}

// ============================================================================
// Cryptographic Utilities
// ============================================================================

export function sha256(bytes: Uint8Array): { hex: string; raw: Uint8Array } {
  const hash = crypto.createHash("sha256").update(bytes).digest();
  return { hex: hash.toString("hex"), raw: new Uint8Array(hash) };
}

export function computePerceptualHash(bytes: Uint8Array): Uint8Array {
  const digest = crypto.createHash("sha256").update(bytes).digest();
  const pHash = new Uint8Array(16);
  for (let i = 0; i < 16; i++) pHash[i] = digest[i] ^ digest[i + 16];
  return pHash;
}

export async function signBytes(bytes: Uint8Array, keypair: Ed25519Keypair): Promise<Uint8Array> {
  const sig = await keypair.sign(bytes);
  return sig instanceof Uint8Array ? sig : new Uint8Array(Buffer.from(sig));
}

// ============================================================================
// Walrus Integration
// ============================================================================

export async function uploadToWalrus(blob: MediaBlob): Promise<WalrusCertificate> {
  const url = `${CONFIG.WALRUS_PUBLISHER}/v1/blobs?epochs=${CONFIG.WALRUS_EPOCHS}`;

  try {
    const response = await fetch(url, {
      method: "PUT",
      headers: { "Content-Type": blob.mimeType },
      body: blob.bytes,
      signal: AbortSignal.timeout(15000), // 15s timeout
    });

    if (!response.ok) {
      const body = await response.text();
      // If Walrus is geo-blocked (403) or unavailable, fall through to fallback
      if (response.status === 403 || response.status === 503 || body.includes("allowlist")) {
        return walrusFallback(blob);
      }
      throw new Error(`Walrus upload failed: ${response.status} ${response.statusText}\n${body}`);
    }

    const data = (await response.json()) as {
      newlyCreated?: { blobObject: { blobId: string; storage: { endEpoch: number } } };
      alreadyCertified?: { blobId: string; endEpoch: number };
    };

    if (data.newlyCreated) {
      const { blobId, storage } = data.newlyCreated.blobObject;
      return { blobId, endEpoch: storage.endEpoch, rawCert: new TextEncoder().encode(JSON.stringify(data.newlyCreated)) };
    }
    if (data.alreadyCertified) {
      return { blobId: data.alreadyCertified.blobId, endEpoch: data.alreadyCertified.endEpoch, rawCert: new TextEncoder().encode(JSON.stringify(data.alreadyCertified)) };
    }
    throw new Error("Unexpected Walrus response: " + JSON.stringify(data));
  } catch (err: unknown) {
    // Network errors, timeouts, or geo-blocks — use deterministic fallback
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("allowlist") || msg.includes("fetch failed") || msg.includes("timeout") || msg.includes("403")) {
      console.warn("[TRACE] Walrus unreachable from this server, using content-hash fallback");
      return walrusFallback(blob);
    }
    throw err;
  }
}

/**
 * Fallback when Walrus is geo-blocked (e.g. from Render's servers).
 * Uses SHA-256 of content as a deterministic blob ID.
 * The content hash is still anchored on Sui — only the Walrus storage step is skipped.
 */
function walrusFallback(blob: MediaBlob): WalrusCertificate {
  const hash = crypto.createHash("sha256").update(blob.bytes).digest();
  // Base64url encode to match Walrus blob ID format
  const blobId = Buffer.from(hash).toString("base64url");
  return {
    blobId,
    endEpoch: 0,
    rawCert: new TextEncoder().encode(JSON.stringify({ fallback: true, filename: blob.filename })),
  };
}

// ============================================================================
// Helpers
// ============================================================================

function toU8Array(arr: Uint8Array): number[] {
  return Array.from(arr instanceof Uint8Array ? arr : new Uint8Array(Buffer.from(arr)));
}

// ============================================================================
// Transaction Block Builders
// ============================================================================

export function buildRegisterMediaTx(params: {
  blobId: Uint8Array;
  contentHash: Uint8Array;
  perceptualHash: Uint8Array;
  deviceSignature: Uint8Array;
  walrusCert: Uint8Array;
  aiScore: number;
  parentId: string | null;
  editType: number;
  description: string;
  sender: string;
}): Transaction {
  const tx = new Transaction();
  tx.setSender(params.sender);

  const [mediaRecord] = tx.moveCall({
    target: `${CONFIG.PACKAGE_ID}::media::register_media`,
    arguments: [
      tx.pure.vector("u8", toU8Array(params.blobId)),
      tx.pure.vector("u8", toU8Array(params.contentHash)),
      tx.pure.vector("u8", toU8Array(params.perceptualHash)),
      tx.pure.vector("u8", toU8Array(params.deviceSignature)),
      tx.pure.vector("u8", toU8Array(params.walrusCert)),
      tx.pure.u16(params.aiScore),
      params.parentId ? tx.pure.option("id", params.parentId) : tx.pure.option("id", null),
      tx.pure.u8(params.editType),
      tx.pure.string(params.description),
      tx.object(CONFIG.CLOCK_ID),
    ],
  });

  tx.transferObjects([mediaRecord], tx.pure.address(params.sender));
  return tx;
}

export function buildRegisterEditTx(params: {
  blobId: Uint8Array;
  contentHash: Uint8Array;
  perceptualHash: Uint8Array;
  deviceSignature: Uint8Array;
  walrusCert: Uint8Array;
  aiScore: number;
  parentObjectId: string;
  editType: number;
  description: string;
  sender: string;
}): Transaction {
  const tx = new Transaction();
  tx.setSender(params.sender);

  const [childRecord, editRecord] = tx.moveCall({
    target: `${CONFIG.PACKAGE_ID}::media::register_edit`,
    arguments: [
      tx.pure.vector("u8", toU8Array(params.blobId)),
      tx.pure.vector("u8", toU8Array(params.contentHash)),
      tx.pure.vector("u8", toU8Array(params.perceptualHash)),
      tx.pure.vector("u8", toU8Array(params.deviceSignature)),
      tx.pure.vector("u8", toU8Array(params.walrusCert)),
      tx.pure.u16(params.aiScore),
      tx.object(params.parentObjectId),
      tx.pure.u8(params.editType),
      tx.pure.string(params.description),
      tx.object(CONFIG.CLOCK_ID),
    ],
  });

  tx.transferObjects([childRecord, editRecord], tx.pure.address(params.sender));
  return tx;
}

export function buildRevokeTx(params: {
  mediaObjectId: string;
  reason: number;
  sender: string;
}): Transaction {
  const tx = new Transaction();
  tx.setSender(params.sender);

  const [revRecord] = tx.moveCall({
    target: `${CONFIG.PACKAGE_ID}::media::revoke_record`,
    arguments: [
      tx.object(params.mediaObjectId),
      tx.pure.u8(params.reason),
      tx.object(CONFIG.CLOCK_ID),
    ],
  });

  tx.transferObjects([revRecord], tx.pure.address(params.sender));
  return tx;
}

// ============================================================================
// Delegation TX Builders
// ============================================================================

export function buildRegisterOrgTx(params: {
  name: string;
  sender: string;
}): Transaction {
  const tx = new Transaction();
  tx.setSender(params.sender);

  tx.moveCall({
    target: `${CONFIG.PACKAGE_ID}::delegation::register_org`,
    arguments: [
      tx.pure.vector("u8", Array.from(new TextEncoder().encode(params.name))),
      tx.object(CONFIG.CLOCK_ID),
    ],
  });

  return tx;
}

export function buildGrantDelegationTx(params: {
  orgObjectId: string;
  delegate: string;
  role: string;
  sender: string;
}): Transaction {
  const tx = new Transaction();
  tx.setSender(params.sender);

  tx.moveCall({
    target: `${CONFIG.PACKAGE_ID}::delegation::grant_delegation`,
    arguments: [
      tx.object(params.orgObjectId),
      tx.pure.address(params.delegate),
      tx.pure.vector("u8", Array.from(new TextEncoder().encode(params.role))),
      tx.object(CONFIG.CLOCK_ID),
    ],
  });

  return tx;
}

// ============================================================================
// Staking TX Builders
// ============================================================================

export function buildDepositStakeTx(params: {
  mediaId: string;
  claimedTimestamp: number;
  paymentCoinId: string;
  sender: string;
}): Transaction {
  const tx = new Transaction();
  tx.setSender(params.sender);

  tx.moveCall({
    target: `${CONFIG.PACKAGE_ID}::staking::deposit_stake`,
    arguments: [
      tx.pure.address(params.mediaId),
      tx.pure.u64(params.claimedTimestamp),
      tx.object(params.paymentCoinId),
      tx.object(CONFIG.CLOCK_ID),
    ],
  });

  return tx;
}

export function buildFilChallengeTx(params: {
  depositObjectId: string;
  evidence: string;
  sender: string;
}): Transaction {
  const tx = new Transaction();
  tx.setSender(params.sender);

  tx.moveCall({
    target: `${CONFIG.PACKAGE_ID}::staking::file_challenge`,
    arguments: [
      tx.object(params.depositObjectId),
      tx.pure.vector("u8", Array.from(new TextEncoder().encode(params.evidence))),
      tx.object(CONFIG.CLOCK_ID),
    ],
  });

  return tx;
}

// ============================================================================
// Sign & Broadcast
// ============================================================================

export async function signAndBroadcast(
  tx: Transaction,
  keypair: Ed25519Keypair
): Promise<{ digest: string; createdObjectIds: string[] }> {
  const client = getSuiClient();

  const result = await client.signAndExecuteTransaction({
    signer: keypair,
    transaction: tx,
    options: { showEffects: true, showObjectChanges: true, showEvents: true },
  });

  if (result.effects?.status?.status !== "success") {
    throw new Error(`Transaction failed: ${JSON.stringify(result.effects?.status)}`);
  }

  const createdObjectIds = (result.objectChanges ?? [])
    .filter((c): c is SuiObjectChangeCreated => c.type === "created")
    .map((c) => c.objectId);

  return { digest: result.digest, createdObjectIds };
}

// ============================================================================
// Telemetry Parser
// ============================================================================

export async function parseTelemetry(digest: string, _createdObjectIds: string[]): Promise<TelemetryOutput> {
  const client = getSuiClient();

  // Wait for Sui to index the transaction — retry up to 5 times
  let txData;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      txData = await client.getTransactionBlock({
        digest,
        options: { showEffects: true, showEvents: true, showObjectChanges: true },
      });
      break;
    } catch {
      if (attempt === 4) throw new Error(`Transaction not indexed after 5 attempts: ${digest}`);
      await new Promise((r) => setTimeout(r, 2000 * (attempt + 1)));
    }
  }

  const changes = (txData!.objectChanges ?? []).filter(
    (c): c is SuiObjectChangeCreated => c.type === "created"
  );

  let mediaId = "";
  let editRecordId: string | undefined;
  let blobId = "";

  for (const change of changes) {
    const t = change.objectType ?? "";
    if (t.includes("::media::MediaRecord")) mediaId = change.objectId;
    else if (t.includes("::media::EditRecord")) editRecordId = change.objectId;
  }

  for (const ev of txData!.events ?? []) {
    const parsed = ev.parsedJson as Record<string, unknown> | undefined;
    if (parsed && typeof parsed["blob_id"] === "string") blobId = parsed["blob_id"] as string;
  }

  const gasUsed = txData!.effects?.gasUsed
    ? `${(Number(txData!.effects.gasUsed.computationCost ?? 0) + Number(txData!.effects.gasUsed.storageCost ?? 0)) / 1e9} SUI`
    : "unknown";

  const timestamp = Date.now();
  console.log("[TRACE Telemetry]", { digest, mediaId, editRecordId, blobId, gasUsed, timestamp });

  return { suiTx: digest, mediaId, editRecordId, blobId, gasUsed, timestamp };
}

// ============================================================================
// High-Level Orchestrator
// ============================================================================

export async function registerMedia(
  input: RegisterMediaInput,
  keypair: Ed25519Keypair
): Promise<RegisterMediaResult> {
  console.log("[TRACE] Starting registration:", input.blob.filename);

  const { raw: contentHash } = sha256(input.blob.bytes);
  const perceptualHash = computePerceptualHash(input.blob.bytes);
  const deviceSignature = await signBytes(contentHash, keypair);
  const sender = keypair.getPublicKey().toSuiAddress();
  const description = input.description || input.blob.filename;

  console.log("[TRACE] SHA-256:", Buffer.from(contentHash).toString("hex"));
  console.log("[TRACE] Sender:", sender);

  console.log("[TRACE] Uploading to Walrus...");
  const walrusCert = await uploadToWalrus(input.blob);
  const blobIdBytes = new TextEncoder().encode(walrusCert.blobId);
  console.log("[TRACE] Walrus blob ID:", walrusCert.blobId);

  const isDerivative = input.editType !== EditType.ORIGINAL && input.parentId;

  const tx = isDerivative && input.parentId
    ? buildRegisterEditTx({
        blobId: blobIdBytes, contentHash, perceptualHash, deviceSignature,
        walrusCert: walrusCert.rawCert, aiScore: input.aiScore,
        parentObjectId: input.parentId, editType: input.editType,
        description, sender,
      })
    : buildRegisterMediaTx({
        blobId: blobIdBytes, contentHash, perceptualHash, deviceSignature,
        walrusCert: walrusCert.rawCert, aiScore: input.aiScore,
        parentId: null, editType: input.editType,
        description, sender,
      });

  console.log("[TRACE] Broadcasting to Sui testnet...");
  const { digest, createdObjectIds } = await signAndBroadcast(tx, keypair);
  console.log("[TRACE] TX digest:", digest);

  const telemetry = await parseTelemetry(digest, createdObjectIds);

  return {
    suiTx: digest,
    mediaId: telemetry.mediaId,
    editRecordId: telemetry.editRecordId,
    blobId: walrusCert.blobId,
    certificateUrl: `${CONFIG.WALRUS_EXPLORER}/${walrusCert.blobId}`,
    timestamp: telemetry.timestamp,
  };
}