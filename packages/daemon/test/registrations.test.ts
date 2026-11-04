import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { AgentRegistrations } from "../src/registrations.js";

const hash = (s: string): string => createHash("sha256").update(s).digest("hex");
const SECRET = "synthetic-claim-secret-0123456789";
const issue = async (id: string): Promise<string> => `synthetic-token-${id}`;
const none = async (): Promise<boolean> => false;

function make(now = { t: 1_000_000 }) {
  const revoked: string[] = [];
  const regs = new AgentRegistrations(async (id) => { revoked.push(id); }, () => now.t);
  return { regs, revoked, now };
}
const input = { agentId: "ide-one", name: "IDE One", ide: "Synthetic IDE", claimHash: hash(SECRET) };

describe("agent registrations", () => {
  it("does not hand over a token before approval, and the list never carries one", async () => {
    const { regs } = make();
    const made = await regs.create(input, none);
    if (!made.ok) throw new Error("create failed");
    expect(await regs.claim(made.id, SECRET)).toMatchObject({ ok: false, status2: "pending" });
    expect(JSON.stringify(await regs.list())).not.toContain("synthetic-token");
  });

  it("approval needs the matching code, then the holder of the claim secret gets the token once", async () => {
    const { regs } = make();
    const made = await regs.create(input, none);
    if (!made.ok) throw new Error("create failed");
    const wrong = made.code === "000000" ? "000001" : "000000";
    expect(await regs.approve(made.id, wrong, issue)).toMatchObject({ ok: false, status: 403 });
    expect(await regs.approve(made.id, made.code, issue)).toEqual({ ok: true });
    expect(await regs.claim(made.id, "someone-elses-secret-0000000000")).toMatchObject({ ok: false, status2: "bad-claim" });
    const got = await regs.claim(made.id, SECRET);
    expect(got).toEqual({ ok: true, token: "synthetic-token-ide-one", agentId: "ide-one" });
    expect(await regs.claim(made.id, SECRET)).toMatchObject({ ok: false, status2: "claimed" });
  });

  it("five wrong claims deny the registration and revoke the issued token", async () => {
    const { regs, revoked } = make();
    const made = await regs.create(input, none);
    if (!made.ok) throw new Error("create failed");
    await regs.approve(made.id, made.code, issue);
    for (let i = 0; i < 5; i += 1) await regs.claim(made.id, "wrong-secret-wrong-secret-00");
    expect(await regs.claim(made.id, SECRET)).toMatchObject({ ok: false, status2: "denied" });
    expect(revoked).toEqual(["ide-one"]);
  });

  it("a second request for the same agent id, or an existing agent, is refused", async () => {
    const { regs } = make();
    expect((await regs.create(input, none)).ok).toBe(true);
    expect(await regs.create({ ...input, claimHash: hash("other-secret-other-secret-0") }, none)).toMatchObject({ ok: false, status: 409 });
    expect(await regs.create({ ...input, agentId: "ide-two" }, async () => true)).toMatchObject({ ok: false, status: 409 });
  });

  it("concurrent requests for one id create only one registration", async () => {
    const { regs } = make();
    const results = await Promise.all([1, 2, 3].map((n) => regs.create({ ...input, claimHash: hash(`secret-number-${String(n)}-padding`) }, none)));
    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it("deny blocks a later claim; an approved but unclaimed token is revoked at expiry", async () => {
    const a = make();
    const d = await a.regs.create(input, none);
    if (!d.ok) throw new Error("create failed");
    expect(await a.regs.deny(d.id)).toBe(true);
    expect(await a.regs.claim(d.id, SECRET)).toMatchObject({ ok: false, status2: "denied" });

    const b = make();
    const e = await b.regs.create(input, none);
    if (!e.ok) throw new Error("create failed");
    await b.regs.approve(e.id, e.code, issue);
    b.now.t += 11 * 60_000;
    expect(await b.regs.claim(e.id, SECRET)).toMatchObject({ ok: false, status2: "expired" });
    expect(b.revoked).toEqual(["ide-one"]);
  });

  it("limits how fast registrations can be created", async () => {
    const { regs } = make();
    let last: Awaited<ReturnType<typeof regs.create>> | undefined;
    for (let i = 0; i < 12; i += 1) last = await regs.create({ ...input, agentId: `ide-${String(i)}`, claimHash: hash(`s${String(i)}-padding-padding-padding`) }, none);
    expect(last).toMatchObject({ ok: false, status: 429 });
  });
});
