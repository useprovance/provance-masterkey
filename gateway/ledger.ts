import { Pool } from "pg";
import { readFileSync } from "node:fs";
import type { ServiceRequest, VerifiedResult } from "./payment";

export interface Claim {
  execute: boolean;
  status: string;
  request?: ServiceRequest;
  result?: VerifiedResult;
  evidence?: import("./x402").Evidence;
}

export interface Ledger {
  health?(): Promise<{
    enabled: boolean;
    dailyLimit: string;
    freeExecutionVersion?: number;
  }>;
  claimFree?(
    owner: string,
    hash: string,
    request: ServiceRequest & { lease: string },
  ): Promise<Claim>;
  completeFree?(
    owner: string,
    hash: string,
    request: ServiceRequest & { lease: string },
    result: VerifiedResult,
  ): Promise<void>;
  evidence?(
    owner: string,
    call: string,
    hash: string,
    evidence: Record<string, unknown>,
  ): Promise<void>;
  closeUnsent?(
    owner: string,
    call: string,
    hash: string,
  ): Promise<VerifiedResult>;
  pending?(): Promise<
    {
      id: string;
      owner_id: string;
      request_hash: string;
      payment_evidence: import("./x402").Evidence;
    }[]
  >;
  claim(owner: string, call: string, hash: string): Promise<Claim>;
  complete(
    owner: string,
    call: string,
    hash: string,
    result: VerifiedResult,
  ): Promise<void>;
  unknown(owner: string, call: string, hash: string): Promise<void>;
  status(owner: string, call: string, hash: string): Promise<Claim>;
}

export function postgresLedger(
  connectionString: string,
): Ledger & { close(): Promise<void>; check(): Promise<void> } {
  const url = new URL(connectionString);
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (
    ["sslmode", "sslrootcert", "sslcert", "sslkey"].some((key) =>
      url.searchParams.has(key),
    )
  ) {
    throw Error(
      "Configure database TLS through MASTERKEY_GATEWAY_DATABASE_CA_FILE, not URL overrides",
    );
  }
  const ca = process.env.MASTERKEY_GATEWAY_DATABASE_CA_FILE
    ? readFileSync(process.env.MASTERKEY_GATEWAY_DATABASE_CA_FILE, "utf8")
    : undefined;
  const pool = new Pool({
    connectionString,
    max: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 8000,
    statement_timeout: 10000,
    keepAlive: true,
    ssl: local
      ? false
      : {
          rejectUnauthorized: true,
          ...(ca ? { ca } : {}),
        },
  });
  // Prevent idle client socket disconnects (e.g. pooler recycling or sleep/wake) from crashing the process.
  pool.on("error", () => {});

  const query = async (name: string, params: unknown[]) => {
    const names = [
      "provance_masterkey_claim",
      "provance_masterkey_complete",
      "provance_masterkey_unknown",
      "provance_masterkey_status",
      "provance_masterkey_evidence",
      "provance_masterkey_pending",
      "provance_masterkey_health",
      "provance_masterkey_close_unsent",
      "provance_masterkey_free_claim",
      "provance_masterkey_free_complete",
    ];
    if (!names.includes(name)) throw Error("Unsupported ledger operation");
    const result = await pool.query(
      `select public.${name}(${params.map((_, i) => `$${i + 1}`).join(",")}) as value`,
      params,
    );
    return result.rows[0].value;
  };

  return {
    check: async () => {
      const result = await pool.query(
        "select current_user as role,has_table_privilege(current_user,'public.execution_budget_settings','UPDATE') as can_change_budgets,has_table_privilege(current_user,'public.masterkey_execution_calls','UPDATE') as can_edit_calls",
      );
      if (
        result.rows[0].can_change_budgets ||
        result.rows[0].can_edit_calls
      ) {
        throw Error(
          "Gateway database role is too broad; use its dedicated restricted login",
        );
      }
    },
    health: async () => {
      const result = await query("provance_masterkey_health", []);
      if (result?.policyApprovalVersion !== 1) {
        throw Error("Provider-policy approval migration is required");
      }
      return result;
    },
    claimFree: (owner, hash, request) =>
      query("provance_masterkey_free_claim", [
        owner,
        hash,
        JSON.stringify(request),
      ]),
    completeFree: async (owner, hash, request, result) => {
      await query("provance_masterkey_free_complete", [
        owner,
        request.runId,
        request.callKey,
        hash,
        JSON.stringify(result),
      ]);
    },
    closeUnsent: (owner, call, hash) =>
      query("provance_masterkey_close_unsent", [owner, call, hash]),
    pending: () => query("provance_masterkey_pending", []),
    evidence: (owner, call, hash, evidence) =>
      query("provance_masterkey_evidence", [
        owner,
        call,
        hash,
        JSON.stringify(evidence),
      ]),
    claim: (owner, call, hash) =>
      query("provance_masterkey_claim", [owner, call, hash]),
    status: (owner, call, hash) =>
      query("provance_masterkey_status", [owner, call, hash]),
    unknown: (owner, call, hash) =>
      query("provance_masterkey_unknown", [owner, call, hash]),
    complete: async (owner, call, hash, result) => {
      await query("provance_masterkey_complete", [
        owner,
        call,
        hash,
        result.status,
        result.totalFeeUsd,
        result.receiptId,
        JSON.stringify(result),
      ]);
    },
    close: () => pool.end(),
  };
}
