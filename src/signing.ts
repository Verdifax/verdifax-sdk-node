/**
 * Optional customer request signing.
 *
 * A customer can register an Ed25519 public key on an API key. From then
 * on the orchestrator accepts a run only with a signature by the matching
 * private key. The private key stays with the customer: it is never sent
 * to the server, logged, or placed in an error message.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  randomBytes,
  sign,
} from "node:crypto";

import { VerdifaxError } from "./errors.js";
import type {
  ExecuteRequest,
  RequestKeyPair,
  RequestKeyRegistrationBody,
  RequestSignature,
} from "./types.js";

const REQUEST_SIGNATURE_FORM = "verdifax.request.v1";
const REQUEST_KEY_PROOF_FORM = "verdifax.request-key.v1";
const SIGNING_KEY_BYTES = 32;

// DER header of a PKCS#8 Ed25519 private key. The 32 raw key bytes follow.
const PKCS8_ED25519_HEADER = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

function rawPublicKey(key: KeyObject): Buffer {
  return Buffer.from(key.export({ format: "der", type: "spki" }).subarray(-32));
}

/** Creates a new Ed25519 key pair on this machine, as raw bytes: a
 *  32-byte public key and a 32-byte private key. Nothing is sent to
 *  the server. Store the private key as a secret. */
export function generateRequestKeyPair(): RequestKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: rawPublicKey(publicKey),
    privateKey: Buffer.from(
      privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32),
    ),
  };
}

/** Turns the raw private key into a KeyObject, which prints as an empty
 *  object, so a logged client never shows the key. */
export function loadSigningKey(key: Uint8Array | KeyObject): KeyObject {
  if (key instanceof KeyObject) return key;
  if (!(key instanceof Uint8Array) || key.length !== SIGNING_KEY_BYTES) {
    throw new VerdifaxError(
      "verdifax: signingKey must be the 32 raw bytes of an Ed25519 private key",
    );
  }
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_HEADER, key]),
    format: "der",
    type: "pkcs8",
  });
}

/** The bytes a request signature signs: the fields joined with single
 *  zero bytes, matching the orchestrator's RequestSignaturePreimage. */
export function requestSignaturePreimage(fields: {
  payload_hash: string;
  program_id: string;
  route_id: string;
  registry_record_hash: string;
  signed_at: string;
  nonce: string;
}): Buffer {
  return Buffer.from(
    [
      REQUEST_SIGNATURE_FORM,
      fields.payload_hash,
      fields.program_id,
      fields.route_id,
      fields.registry_record_hash,
      fields.signed_at,
      fields.nonce,
    ].join("\0"),
    "utf8",
  );
}

/** Signs one execute request. The server hashes payload_text when it is
 *  non-empty, otherwise the payload string exactly as sent (it does not
 *  base64-decode it), so this does the same.
 *
 *  `signedAt` and `nonce` default to the current time and fresh random
 *  bytes. A nonce the server has already seen is refused. */
export function signRequest(
  signingKey: Uint8Array | KeyObject,
  req: ExecuteRequest,
  options: { signedAt?: string; nonce?: string } = {},
): RequestSignature {
  const key = loadSigningKey(signingKey);
  const signed_at =
    options.signedAt ?? new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const nonce = options.nonce ?? randomBytes(16).toString("hex");
  const payload_hash = createHash("sha256")
    .update(Buffer.from(req.payload_text || req.payload || "", "utf8"))
    .digest("hex");
  const preimage = requestSignaturePreimage({
    payload_hash,
    program_id: req.program_id,
    route_id: req.route_id,
    registry_record_hash: req.registry_record_hash,
    signed_at,
    nonce,
  });
  return {
    signature: sign(null, preimage, key).toString("base64"),
    signed_at,
    nonce,
  };
}

/** The body of POST /keys/request-key: the base64 public key and a
 *  signature proving the caller holds its private key. */
export function requestKeyRegistrationBody(
  signingKey: Uint8Array | KeyObject,
): RequestKeyRegistrationBody {
  const key = loadSigningKey(signingKey);
  const public_key = rawPublicKey(createPublicKey(key)).toString("base64");
  const proof = sign(
    null,
    Buffer.from(`${REQUEST_KEY_PROOF_FORM}\0${public_key}`, "utf8"),
    key,
  ).toString("base64");
  return { public_key, proof };
}
