/**
 * The three canonical hash formulas from the Verdifax orchestrator, so a
 * caller can recompute a DSE dispatch hash, a DCAE closure hash or a CRES
 * receipt hash without calling the server.
 *
 * These match the Python SDK's `verdifax.section0` and pass its test
 * vectors. Every hash is SHA-256 as 64 lowercase hex characters, over
 * UTF-8 text.
 */

import { createHash } from "node:crypto";

import { VerdifaxError } from "./errors.js";
import type { Hex64 } from "./types.js";
import { validateHex64 } from "./validation.js";

export const DSE_FORMULA_VERSION = "dse.tcu.dispatch.v1";
export const DCAE_PREIMAGE_VERSION = "verdifax.dcae.v1";
export const CRES_PREIMAGE_VERSION = "verdifax.cres.v1";
export const CRES_ENGINE_VERSION = "verdifax-cres/1.0.0";

function sha256Hex(preimage: string): string {
  return createHash("sha256").update(Buffer.from(preimage, "utf8")).digest("hex");
}

function requireHex64(value: string, name: string): void {
  try {
    validateHex64(value, name);
  } catch (err) {
    throw new VerdifaxError(
      `verdifax: section0: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/** The DSE formula joins its fields with a period. */
export function dseDispatchHash(fields: {
  envelope_id: string;
  sequence_id: string;
  program_id: Hex64;
  registry_record_hash: Hex64;
}): Hex64 {
  requireHex64(fields.program_id, "program_id");
  requireHex64(fields.registry_record_hash, "registry_record_hash");
  return sha256Hex(
    [
      DSE_FORMULA_VERSION,
      fields.envelope_id,
      fields.sequence_id,
      fields.program_id,
      fields.registry_record_hash,
    ].join("."),
  );
}

/** The DCAE formula joins its fields with a pipe. */
export function dcaeClosureHash(fields: {
  manifest_hash: Hex64;
  aer_hash: Hex64;
  envelope_id: string;
  zksp_binding_hash: Hex64;
  formal_verifier_status: string;
}): Hex64 {
  requireHex64(fields.manifest_hash, "manifest_hash");
  requireHex64(fields.aer_hash, "aer_hash");
  requireHex64(fields.zksp_binding_hash, "zksp_binding_hash");
  return sha256Hex(
    [
      DCAE_PREIMAGE_VERSION,
      fields.manifest_hash,
      fields.aer_hash,
      fields.envelope_id,
      fields.zksp_binding_hash,
      fields.formal_verifier_status,
    ].join("|"),
  );
}

/** The CRES formula joins its fields with a pipe. `engine_version`
 *  defaults to {@link CRES_ENGINE_VERSION}; pass another value only to
 *  recompute a receipt from an earlier engine. */
export function cresReceiptHash(fields: {
  envelope_id: string;
  field_path: string;
  deletion_clock: string;
  actor_id: string;
  ciphertext_hash_at_shred: Hex64;
  dsar_reference: string;
  engine_version?: string;
}): Hex64 {
  requireHex64(fields.ciphertext_hash_at_shred, "ciphertext_hash_at_shred");
  return sha256Hex(
    [
      CRES_PREIMAGE_VERSION,
      fields.envelope_id,
      fields.field_path,
      fields.deletion_clock,
      fields.actor_id,
      fields.ciphertext_hash_at_shred,
      fields.dsar_reference,
      fields.engine_version ?? CRES_ENGINE_VERSION,
    ].join("|"),
  );
}
