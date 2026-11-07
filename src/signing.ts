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
  verify,
} from "node:crypto";

import { VerdifaxError } from "./errors.js";
import { withExecuteFlags } from "./helpers.js";
import type {
  ApproverKeyProof,
  ExecuteRequest,
  JobLink,
  PolicyActivationSignature,
  RequestKeyChange,
  RequestKeyPair,
  RequestKeyRegistrationBody,
  RequestSignature,
  SignedRequestBody,
  SignOffDecision,
  SignOffSignature,
  SignOffTarget,
} from "./types.js";

const REQUEST_SIGNATURE_FORM = "verdifax.request.v1";
const REQUEST_SIGNATURE_FORM_V2 = "verdifax.request.v2";
const REQUEST_SIGNATURE_VERSION_2 = "2";
const JOB_FORM = "verdifax.job.v1";
const REQUEST_KEY_PROOF_FORM = "verdifax.request-key.v1";
const REQUEST_KEY_CHANGE_FORM = "verdifax.request-key-change.v1";
const POLICY_ACTIVATION_FORM = "verdifax.policy-activation.v1";
const SIGNOFF_FORM = "verdifax.signoff.v1";
const APPROVER_KEY_PROOF_FORM = "verdifax.approver-key.v1";
const SIGNING_KEY_BYTES = 32;

// DER header of an SPKI Ed25519 public key. The 32 raw key bytes follow.
const SPKI_ED25519_HEADER = Buffer.from("302a300506032b6570032100", "hex");

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

/** SHA-256 of the UTF-8 text as 64 lowercase hex characters. */
export function sha256Hex(text: string): string {
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

/** RFC 3339 UTC in whole seconds. */
function signedAtNow(): string {
  return new Date().toISOString().replace(/\.\d+Z$/, "Z");
}

/** The bytes a version 1 request signature signs: the fields joined with
 *  single zero bytes, matching the orchestrator's RequestSignaturePreimage.
 *  The client now sends version 2. See {@link requestSignaturePreimageV2}. */
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

/** The bytes a version 2 request signature signs: the fields joined with
 *  single zero bytes, matching the orchestrator's
 *  RequestSignaturePreimageV2. With no job, the job fields are empty and
 *  `final` is false. */
export function requestSignaturePreimageV2(fields: {
  body_hash: string;
  payload_hash: string;
  program_id: string;
  route_id: string;
  registry_record_hash: string;
  ai_output_hash: string;
  job?: JobLink;
  signed_at: string;
  nonce: string;
}): Buffer {
  const { job } = fields;
  return Buffer.from(
    [
      REQUEST_SIGNATURE_FORM_V2,
      fields.body_hash,
      fields.payload_hash,
      fields.program_id,
      fields.route_id,
      fields.registry_record_hash,
      fields.ai_output_hash,
      JOB_FORM,
      job?.job_id ?? "",
      job?.step_id ?? "",
      (job?.previous_record_hashes ?? []).join(","),
      (job?.external_previous ?? []).join(","),
      job?.final ? "true" : "false",
      fields.signed_at,
      fields.nonce,
    ].join("\0"),
    "utf8",
  );
}

/** Signs one execute request with signature version 2 and returns the
 *  whole body to send. The request is serialized once, and that exact text
 *  is what is hashed, signed and sent.
 *
 *  The payload hash follows the same rule as {@link signRequest}.
 *  `signedAt` and `nonce` default to the current time and fresh random
 *  bytes. A nonce the server has already seen is refused. */
export function signRequestV2(
  signingKey: Uint8Array | KeyObject,
  req: ExecuteRequest,
  options: { signedAt?: string; nonce?: string } = {},
): SignedRequestBody {
  const key = loadSigningKey(signingKey);
  const { request_signature: _unsigned, ...fields } = withExecuteFlags(req);
  const signed_request = JSON.stringify(fields);
  const signed_at = options.signedAt ?? signedAtNow();
  const nonce = options.nonce ?? randomBytes(16).toString("hex");
  const preimage = requestSignaturePreimageV2({
    body_hash: sha256Hex(signed_request),
    payload_hash: sha256Hex(fields.payload_text || fields.payload || ""),
    program_id: fields.program_id,
    route_id: fields.route_id,
    registry_record_hash: fields.registry_record_hash,
    ai_output_hash: fields.ai_output_text
      ? sha256Hex(fields.ai_output_text)
      : "",
    job: fields.job,
    signed_at,
    nonce,
  });
  return {
    signed_request,
    request_signature: {
      version: REQUEST_SIGNATURE_VERSION_2,
      signature: sign(null, preimage, key).toString("base64"),
      signed_at,
      nonce,
    },
  };
}

/** Signs one execute request with signature version 1, which the server
 *  still accepts. The client now sends version 2: see {@link signRequestV2}.
 *  The server hashes payload_text when it is non-empty, otherwise the
 *  payload string exactly as sent (it does not base64-decode it), so this
 *  does the same.
 *
 *  `signedAt` and `nonce` default to the current time and fresh random
 *  bytes. A nonce the server has already seen is refused. */
export function signRequest(
  signingKey: Uint8Array | KeyObject,
  req: ExecuteRequest,
  options: { signedAt?: string; nonce?: string } = {},
): RequestSignature {
  const key = loadSigningKey(signingKey);
  const signed_at = options.signedAt ?? signedAtNow();
  const nonce = options.nonce ?? randomBytes(16).toString("hex");
  const preimage = requestSignaturePreimage({
    payload_hash: sha256Hex(req.payload_text || req.payload || ""),
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

/** The bytes the current key signs to replace or clear itself. `new_public_key`
 *  is the new base64 public key, or empty when clearing. */
export function requestKeyChangePreimage(fields: {
  new_public_key: string;
  signed_at: string;
  nonce: string;
}): Buffer {
  return Buffer.from(
    [
      REQUEST_KEY_CHANGE_FORM,
      fields.new_public_key,
      fields.signed_at,
      fields.nonce,
    ].join("\0"),
    "utf8",
  );
}

/** The current key's approval of a key change, the `change` value of POST
 *  and DELETE /keys/request-key. Pass an empty `newPublicKey` when clearing.
 *  `signedAt` and `nonce` default to the current time and fresh random
 *  bytes. */
export function requestKeyChangeApproval(
  currentSigningKey: Uint8Array | KeyObject,
  newPublicKey: string,
  options: { signedAt?: string; nonce?: string } = {},
): RequestKeyChange {
  const key = loadSigningKey(currentSigningKey);
  const signed_at = options.signedAt ?? signedAtNow();
  const nonce = options.nonce ?? randomBytes(16).toString("hex");
  const preimage = requestKeyChangePreimage({
    new_public_key: newPublicKey,
    signed_at,
    nonce,
  });
  return {
    signature: sign(null, preimage, key).toString("base64"),
    signed_at,
    nonce,
  };
}

/** The bytes the request key signs to make a stored policy document the
 *  one in force, matching the orchestrator's PolicyActivationPreimage.
 *  `chain_id` and `previous_activation_hash` come from GET /policies, so a
 *  signature cannot be used on another key's chain, another document or
 *  another point in the chain. */
export function policyActivationPreimage(fields: {
  chain_id: string;
  document_hash: string;
  previous_activation_hash: string;
  signed_at: string;
  nonce: string;
}): Buffer {
  return Buffer.from(
    [
      POLICY_ACTIVATION_FORM,
      fields.chain_id,
      fields.document_hash,
      fields.previous_activation_hash,
      fields.signed_at,
      fields.nonce,
    ].join("\0"),
    "utf8",
  );
}

/** The request key's approval of a policy change, the `signature` value of
 *  POST /policies/{document_hash}/activate. `signedAt` and `nonce` default
 *  to the current time and fresh random bytes. */
export function policyActivationApproval(
  signingKey: Uint8Array | KeyObject,
  fields: {
    chain_id: string;
    document_hash: string;
    previous_activation_hash: string;
  },
  options: { signedAt?: string; nonce?: string } = {},
): PolicyActivationSignature {
  const key = loadSigningKey(signingKey);
  const signed_at = options.signedAt ?? signedAtNow();
  const nonce = options.nonce ?? randomBytes(16).toString("hex");
  const preimage = policyActivationPreimage({
    chain_id: fields.chain_id,
    document_hash: fields.document_hash,
    previous_activation_hash: fields.previous_activation_hash,
    signed_at,
    nonce,
  });
  return {
    signature: sign(null, preimage, key).toString("base64"),
    signed_at,
    nonce,
  };
}

/** The bytes an approver key signs for one sign-off, matching the
 *  orchestrator's SignOffPreimage: the fields joined with single zero
 *  bytes. `chain_id` and `previous_signoff_hash` come from GET
 *  /signoffs/newest (or /account/signoffs/newest for the owner key), so a
 *  signature cannot be moved to another account, another result or
 *  another point in the chain. `target.job_id` is empty unless the target
 *  is a job, and `note_hash` is empty when there is no note. */
export function signOffPreimage(fields: {
  chain_id: string;
  previous_signoff_hash: string;
  target: SignOffTarget;
  decision: SignOffDecision;
  note_hash: string;
  signed_at: string;
  nonce: string;
}): Buffer {
  const { target } = fields;
  return Buffer.from(
    [
      SIGNOFF_FORM,
      fields.chain_id,
      fields.previous_signoff_hash,
      target.kind,
      String(target.run_id),
      target.digest,
      target.job_id ?? "",
      fields.decision,
      fields.note_hash,
      fields.signed_at,
      fields.nonce,
    ].join("\0"),
    "utf8",
  );
}

/** The approver key's signature over one sign-off. `signedAt` and `nonce`
 *  default to the current time and fresh random bytes. */
export function signOffSignature(
  approverKey: Uint8Array | KeyObject,
  fields: {
    chain_id: string;
    previous_signoff_hash: string;
    target: SignOffTarget;
    decision: SignOffDecision;
    note_hash: string;
  },
  options: { signedAt?: string; nonce?: string } = {},
): SignOffSignature {
  const key = loadSigningKey(approverKey);
  const signed_at = options.signedAt ?? signedAtNow();
  const nonce = options.nonce ?? randomBytes(16).toString("hex");
  const preimage = signOffPreimage({ ...fields, signed_at, nonce });
  return {
    approver_key: rawPublicKey(createPublicKey(key)).toString("base64"),
    signature: sign(null, preimage, key).toString("base64"),
    signed_at,
    nonce,
  };
}

/** The approver key's base64 public key and its proof: its signature over
 *  verdifax.approver-key.v1, a zero byte and the base64 public key, which
 *  shows its holder has the private key. The approver can run this on
 *  their own machine and give the result to the account's owner, who
 *  registers it with {@link VerdifaxClient.registerApprover}, so the owner
 *  never holds the approver's private key. */
export function approverKeyProof(
  approverKey: Uint8Array | KeyObject,
): ApproverKeyProof {
  const key = loadSigningKey(approverKey);
  const public_key = rawPublicKey(createPublicKey(key)).toString("base64");
  const proof = sign(
    null,
    Buffer.from(`${APPROVER_KEY_PROOF_FORM}\0${public_key}`, "utf8"),
    key,
  ).toString("base64");
  return { public_key, proof };
}

/** True when `proof` is the holder's signature over the approver key
 *  proof form for `publicKey`, the check the server makes on
 *  registration. */
export function approverKeyProofVerifies(proof: ApproverKeyProof): boolean {
  if (
    typeof proof?.public_key !== "string" ||
    typeof proof?.proof !== "string"
  ) {
    return false;
  }
  const raw = Buffer.from(proof.public_key, "base64");
  const signature = Buffer.from(proof.proof, "base64");
  if (
    raw.length !== 32 ||
    raw.toString("base64") !== proof.public_key ||
    signature.length !== 64 ||
    signature.toString("base64") !== proof.proof
  ) {
    return false;
  }
  const publicKey = createPublicKey({
    key: Buffer.concat([SPKI_ED25519_HEADER, raw]),
    format: "der",
    type: "spki",
  });
  return verify(
    null,
    Buffer.from(`${APPROVER_KEY_PROOF_FORM}\0${proof.public_key}`, "utf8"),
    publicKey,
    signature,
  );
}

/** The base64 public key of a signing key. */
export function publicKeyOf(key: KeyObject): string {
  return rawPublicKey(createPublicKey(key)).toString("base64");
}
