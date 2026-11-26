import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  Account,
  Asset,
  BASE_FEE,
  Keypair,
  Memo,
  Networks,
  Operation,
  TransactionBuilder,
  type Transaction,
} from "@stellar/stellar-sdk";
import {
  refundableAmount,
  type Refund,
  type RailPort,
  type Seller,
  type SellerRepository,
} from "@checkout/core";
import type { StellarConfig } from "@checkout/stellar";
import { HttpError, LinkService } from "../src/services/link-service";
import {
  AlwaysAcceptedKyc,
  FakeLinkRepository,
  FakeOffRampStateRepository,
  FakeRefundRepository,
  FakeTelemetryRepository,
  FakeWebhookRepository,
  ScriptedOffRamp,
  makeLink,
} from "./fakes";

// ---------------------------------------------------------------------------
//  POST /links/:id/refunds/:refundId/submit (issue 4.60).
//
//  4.59 builds the refund transaction, stores it unsigned and keeps its hash.
//  The browser signs that XDR and posts it back here, so the envelope is
//  attacker-controlled even though the signature is the seller's: relaying it
//  unchecked would let a tampered page use Quay to submit something else from
//  the seller's account. Every test below is either "this is not the prepared
//  transaction" or the two ways a prepared one ends (submitted / rejected).
//
//  Stellar hashes the envelope's contents, not its signatures, so a correctly
//  signed XDR still hashes to the stored prepared hash.
// ---------------------------------------------------------------------------

// Hoisted so the module factory below can close over it — vi.mock is lifted
// above imports, so a plain const declared here would not exist yet.
const { submitTransaction } = vi.hoisted(() => ({ submitTransaction: vi.fn() }));

// Only Horizon's server is replaced: the tests below build and sign real
// envelopes with the real builder, which is the thing under test.
vi.mock("@stellar/stellar-sdk", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@stellar/stellar-sdk")>();
  return {
    ...actual,
    Horizon: {
      ...actual.Horizon,
      Server: class {
        submitTransaction = submitTransaction;
      },
    },
  };
});

const SELLER = Keypair.random();
const BUYER = Keypair.random();
const ATTACKER = Keypair.random();
const ISSUER = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
const USDC = new Asset("USDC", ISSUER);

const stellar: StellarConfig = {
  network: "testnet",
  horizonUrl: "https://horizon-testnet.stellar.org",
  networkPassphrase: Networks.TESTNET,
  usdcIssuer: ISSUER,
};

const seller: Seller = {
  id: "sel_1",
  name: "S",
  wallet: SELLER.publicKey(),
  profileKind: "individual",
  payoutFields: null,
  createdAt: 0,
};
const sellers: SellerRepository = {
  async findById() { return seller; },
  async findByWallet() { return seller; },
  async createIfAbsent() { return seller; },
  async savePayoutFields() {},
  async saveProfileKind() {},
};
const rail: RailPort = {
  buildRequest: () => ({
    uri: "web+stellar:pay",
    destination: seller.wallet,
    amount: "10",
    asset: { code: "USDC", issuer: ISSUER },
    memo: "r",
  }),
  isValidDestination: () => true,
  async assertCanReceive() {},
};

const REFUND_MEMO = "refund 7781";

/** The transaction 4.59 would have built and stored: the seller's wallet pays
 *  the buyer 4.2 USDC with the buyer's memo. */
function buildRefund(
  over: {
    source?: string;
    sequence?: string;
    ops?: Parameters<TransactionBuilder["addOperation"]>[0][];
    memo?: Memo;
    /** Absolute max time in epoch ms; defaults to a 5-minute window. */
    maxTimeMs?: number;
    fee?: string;
  } = {},
): Transaction {
  const source = new Account(over.source ?? seller.wallet, over.sequence ?? "7");
  const builder = new TransactionBuilder(source, {
    fee: over.fee ?? BASE_FEE,
    networkPassphrase: Networks.TESTNET,
  });
  builder.setTimebounds(new Date(0), new Date(over.maxTimeMs ?? Date.now() + 300_000));
  for (const op of over.ops ?? [
    Operation.payment({ destination: BUYER.publicKey(), asset: USDC, amount: "4.2" }),
  ]) {
    builder.addOperation(op);
  }
  return builder.addMemo(over.memo ?? Memo.text(REFUND_MEMO)).build();
}

const preparedTx = buildRefund();
const PREPARED_HASH = preparedTx.hash().toString("hex");
// Horizon echoes the transaction's own hash back, and it is what the watcher
// will later use to confirm the refund on the ledger.
const HORIZON_HASH = PREPARED_HASH;

/** The seller signs the prepared envelope in their wallet. */
function signed(tx: Transaction): string {
  tx.sign(SELLER);
  return tx.toXDR();
}

function refund(over: Partial<Refund> = {}): Refund {
  return {
    id: "rfd_1",
    linkId: "lnk_1",
    sellerId: seller.id,
    paymentTxHash: "a".repeat(64),
    paymentOperationId: "1",
    destination: BUYER.publicKey(),
    destinationMuxedId: null,
    memo: REFUND_MEMO,
    memoType: "text",
    amount: "4.2",
    asset: { code: "USDC", issuer: ISSUER },
    status: "prepared",
    unsignedTxHash: PREPARED_HASH,
    txHash: null,
    failureReason: null,
    createdAt: 1_000,
    updatedAt: 1_000,
    ...over,
  };
}

let links: FakeLinkRepository;
let refunds: FakeRefundRepository;
let service: LinkService;

beforeEach(async () => {
  submitTransaction.mockReset();
  submitTransaction.mockImplementation(async (tx: Transaction) => ({
    hash: tx.hash().toString("hex"),
  }));
  links = new FakeLinkRepository();
  refunds = new FakeRefundRepository();
  service = new LinkService({
    links,
    sellers,
    webhooks: new FakeWebhookRepository(),
    rail,
    refunds,
    offramp: new ScriptedOffRamp(),
    offrampState: new FakeOffRampStateRepository(),
    kyc: new AlwaysAcceptedKyc(),
    telemetry: new FakeTelemetryRepository(),
    stellar,
    correlation: "memo",
  });
  // A paid link: refunds exist against money that arrived, and the transaction
  // must come out of this link's destination wallet.
  await links.save(makeLink({ id: "lnk_1", status: "paid", destination: seller.wallet }));
  await refunds.create(refund());
});

async function expectRejected(xdr: string, status: number, match: RegExp) {
  const err = await service.submitRefund("lnk_1", "rfd_1", xdr).catch((e) => e);
  expect(err).toBeInstanceOf(HttpError);
  expect((err as HttpError).status).toBe(status);
  expect((err as HttpError).message).toMatch(match);
  // Nothing that failed validation may reach Horizon.
  expect(submitTransaction).not.toHaveBeenCalled();
}

/** Horizon answers a submission with an operation failure. */
function horizonRejection(codes: Record<string, unknown>) {
  return Object.assign(new Error("Transaction Failed"), {
    response: { status: 400, data: { extras: { result_codes: codes } } },
  });
}

describe("submitRefund — happy path", () => {
  it("relays the prepared transaction, stores the hash and leaves confirmation to the watcher", async () => {
    const result = await service.submitRefund("lnk_1", "rfd_1", signed(preparedTx));

    expect(submitTransaction).toHaveBeenCalledTimes(1);
    expect(result.txHash).toBe(HORIZON_HASH);
    expect(result.refund).toMatchObject({
      status: "submitted",
      txHash: HORIZON_HASH,
      failureReason: null,
    });
    // Not `confirmed`: only the ledger (the watcher) may say the money landed.
    expect(await refunds.findById("rfd_1")).toMatchObject({ status: "submitted", txHash: HORIZON_HASH });
  });

  it("accepts the same amount written with trailing zeros", async () => {
    // The envelope carries "4.2000000"; the stored refund carries "4.2". A
    // string comparison would reject a correct transaction.
    const tx = buildRefund({
      ops: [Operation.payment({ destination: BUYER.publicKey(), asset: USDC, amount: "4.2000000" })],
    });
    await refunds.update("rfd_1", { unsignedTxHash: tx.hash().toString("hex") });

    await service.submitRefund("lnk_1", "rfd_1", signed(tx));
    expect(await refunds.findById("rfd_1")).toMatchObject({ status: "submitted" });
  });

  it("returns the stored hash on a repeat submit instead of erroring or resubmitting", async () => {
    const xdr = signed(preparedTx);
    await service.submitRefund("lnk_1", "rfd_1", xdr);

    const again = await service.submitRefund("lnk_1", "rfd_1", xdr);

    expect(again.txHash).toBe(HORIZON_HASH);
    expect(again.refund.status).toBe("submitted");
    // The browser retrying a POST whose response it lost must not broadcast twice.
    expect(submitTransaction).toHaveBeenCalledTimes(1);
  });

  it("409s a different envelope for a refund that already submitted", async () => {
    await service.submitRefund("lnk_1", "rfd_1", signed(preparedTx));
    const other = buildRefund({ sequence: "8" });

    await expect(service.submitRefund("lnk_1", "rfd_1", signed(other))).rejects.toThrow(
      /already submitted/i,
    );
    expect(submitTransaction).toHaveBeenCalledTimes(1);
  });
});

describe("submitRefund — not the prepared transaction", () => {
  it("rejects a transaction sourced by anyone but the seller's wallet", async () => {
    const tx = buildRefund({ source: ATTACKER.publicKey() });
    await expectRejected(signed(tx), 409, /source does not match the seller's wallet/);
  });

  it("rejects a second operation hidden behind the refund payment", async () => {
    const tx = buildRefund({
      ops: [
        Operation.payment({ destination: BUYER.publicKey(), asset: USDC, amount: "4.2" }),
        Operation.payment({ destination: ATTACKER.publicKey(), asset: USDC, amount: "1000" }),
      ],
    });
    await expectRejected(signed(tx), 400, /exactly one operation, got 2/);
  });

  it("rejects a non-payment operation", async () => {
    const tx = buildRefund({ ops: [Operation.accountMerge({ destination: ATTACKER.publicKey() })] });
    await expectRejected(signed(tx), 400, /single payment operation, got "accountMerge"/);
  });

  it("rejects an operation-level source override", async () => {
    const tx = buildRefund({
      ops: [
        Operation.payment({
          destination: BUYER.publicKey(),
          asset: USDC,
          amount: "4.2",
          source: ATTACKER.publicKey(),
        }),
      ],
    });
    await expectRejected(signed(tx), 400, /must not override the transaction source/);
  });

  it("rejects a changed destination", async () => {
    const tx = buildRefund({
      ops: [Operation.payment({ destination: ATTACKER.publicKey(), asset: USDC, amount: "4.2" })],
    });
    await expectRejected(signed(tx), 409, /destination does not match/);
  });

  it("rejects a changed asset", async () => {
    const tx = buildRefund({
      ops: [Operation.payment({ destination: BUYER.publicKey(), asset: Asset.native(), amount: "4.2" })],
    });
    await expectRejected(signed(tx), 409, /Asset mismatch/);
  });

  it("rejects an asset with the right code but a different issuer", async () => {
    const tx = buildRefund({
      ops: [
        Operation.payment({
          destination: BUYER.publicKey(),
          asset: new Asset("USDC", ATTACKER.publicKey()),
          amount: "4.2",
        }),
      ],
    });
    await expectRejected(signed(tx), 409, /Asset mismatch/);
  });

  it("rejects a changed amount", async () => {
    const tx = buildRefund({
      ops: [Operation.payment({ destination: BUYER.publicKey(), asset: USDC, amount: "4.2000001" })],
    });
    await expectRejected(signed(tx), 409, /Amount mismatch/);
  });

  it("rejects a changed memo", async () => {
    const tx = buildRefund({ memo: Memo.text("someone else's refund") });
    await expectRejected(signed(tx), 409, /memo does not match/i);
  });

  it("rejects a missing memo", async () => {
    const tx = buildRefund({ memo: Memo.none() });
    await expectRejected(signed(tx), 409, /memo does not match/i);
  });

  it("rejects a MEMO_ID where the refund's memo is MEMO_TEXT", async () => {
    const tx = buildRefund({ memo: Memo.id("7781") });
    await expectRejected(signed(tx), 409, /memo does not match/i);
  });

  it("rejects a transaction whose every field matches but whose hash does not", async () => {
    // Same source, operation, amount, asset and memo; a different sequence
    // number. Only the stored prepared hash can tell the two apart.
    const tx = buildRefund({ sequence: "8" });
    expect(tx.hash().toString("hex")).not.toBe(PREPARED_HASH);
    await expectRejected(signed(tx), 409, /does not match the prepared refund/);
  });

  it("rejects a refund whose prepared hash was never stored", async () => {
    await refunds.update("rfd_1", { unsignedTxHash: null });
    await expectRejected(signed(preparedTx), 409, /no prepared transaction/);
  });

  it("rejects an expired refund", async () => {
    const tx = buildRefund({ maxTimeMs: Date.now() - 60_000 });
    await refunds.update("rfd_1", { unsignedTxHash: tx.hash().toString("hex") });
    await expectRejected(signed(tx), 409, /expired/);
  });

  it("rejects malformed XDR", async () => {
    await expectRejected("not-base64-xdr", 400, /invalid_xdr/);
  });
});

describe("submitRefund — which refund may be submitted", () => {
  it("404s an unknown link", async () => {
    await expect(service.submitRefund("lnk_nope", "rfd_1", signed(preparedTx))).rejects.toThrow(
      /Link not found/,
    );
  });

  it("404s an unknown refund", async () => {
    await expect(service.submitRefund("lnk_1", "rfd_nope", signed(preparedTx))).rejects.toThrow(
      /Refund not found/,
    );
  });

  it("404s a refund of a different link", async () => {
    await refunds.create(refund({ id: "rfd_other_link", linkId: "lnk_2" }));
    await expect(service.submitRefund("lnk_1", "rfd_other_link", signed(preparedTx))).rejects.toThrow(
      /Refund not found/,
    );
  });

  it("404s another seller's refund", async () => {
    await refunds.create(refund({ id: "rfd_theirs", sellerId: "sel_other" }));
    await expect(service.submitRefund("lnk_1", "rfd_theirs", signed(preparedTx))).rejects.toThrow(
      /Refund not found/,
    );
    expect(submitTransaction).not.toHaveBeenCalled();
  });

  it("409s a refund that already failed", async () => {
    await refunds.update("rfd_1", { status: "failed", failureReason: "payment_rejected" });
    await expectRejected(signed(preparedTx), 409, /cannot be submitted \(is "failed"\)/);
  });

  it("501s when the deployment has no refund repository", async () => {
    const withoutRefunds = new LinkService({
      links,
      sellers,
      webhooks: new FakeWebhookRepository(),
      rail,
      offramp: new ScriptedOffRamp(),
      offrampState: new FakeOffRampStateRepository(),
      kyc: new AlwaysAcceptedKyc(),
      telemetry: new FakeTelemetryRepository(),
      stellar,
      correlation: "memo",
    });
    const err = await withoutRefunds.submitRefund("lnk_1", "rfd_1", signed(preparedTx)).catch((e) => e);
    expect((err as HttpError).status).toBe(501);
    expect((err as HttpError).message).toBe("refunds_disabled");
  });
});

describe("submitRefund — Horizon rejection", () => {
  it("marks the refund failed with the reason and makes the amount refundable again", async () => {
    // A prepared refund already reserves its amount; the seller can only ask
    // for the rest of the payment back once this one has failed.
    expect(refundableAmount("10", [refund()])).toBe("5.8");

    submitTransaction.mockRejectedValueOnce(
      horizonRejection({ transaction: "tx_failed", operations: ["op_no_trust"] }),
    );

    const err = await service.submitRefund("lnk_1", "rfd_1", signed(preparedTx)).catch((e) => e);
    expect(err).toBeInstanceOf(HttpError);
    expect((err as HttpError).status).toBe(409);
    expect((err as HttpError).message).toBe("refund_rejected");
    expect((err as HttpError).extra).toMatchObject({ reason: "missing_trustline" });

    const failed = await refunds.findById("rfd_1");
    expect(failed).toMatchObject({ status: "failed", failureReason: "missing_trustline", txHash: null });
    // A refund that never reached the ledger must not keep its amount reserved.
    expect(refundableAmount("10", [failed!])).toBe("10");
  });
});
