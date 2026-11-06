// Checks a signed body as the server does, written out independently of
// the SDK. Not a test file itself: the signed-call tests import it.
import crypto from "node:crypto";

const SPKI_ED25519_HEADER = Buffer.from("302a300506032b6570032100", "hex");

export function publicKeyObject(raw) {
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519_HEADER, raw]), format: "der", type: "spki" });
}

export function sha256(text) {
  return crypto.createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

/** The request inside a signed body. Throws unless the body holds exactly
 *  `signed_request` and `request_signature`, with nothing else. */
export function signedFields(body) {
  const outer = Object.keys(body).sort().join(",");
  if (outer !== "request_signature,signed_request") throw new Error(`body holds ${outer}`);
  const inner = Object.keys(body.request_signature).sort().join(",");
  if (inner !== "nonce,signature,signed_at,version") throw new Error(`request_signature holds ${inner}`);
  if (body.request_signature.version !== "2") throw new Error("not version 2");
  return JSON.parse(body.signed_request);
}

/** Rebuilds the signed bytes from a received body and verifies them. */
export function verifiesV2(body, publicKey) {
  const request = signedFields(body);
  const { signature, signed_at, nonce } = body.request_signature;
  const job = request.job ?? {};
  const signed = [
    "verdifax.request.v2",
    sha256(body.signed_request),
    sha256(request.payload_text || request.payload || ""),
    request.program_id ?? "",
    request.route_id ?? "",
    request.registry_record_hash ?? "",
    request.ai_output_text ? sha256(request.ai_output_text) : "",
    "verdifax.job.v1",
    job.job_id ?? "",
    job.step_id ?? "",
    (job.previous_record_hashes ?? []).join(","),
    (job.external_previous ?? []).join(","),
    job.final === true ? "true" : "false",
    signed_at,
    nonce,
  ].join("\0");
  return crypto.verify(null, Buffer.from(signed, "utf8"), publicKeyObject(publicKey), Buffer.from(signature, "base64"));
}
