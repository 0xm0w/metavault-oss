import { describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
function capture(fetchFn) {
    const o = [];
    const e = [];
    return { deps: { daemonUrl: "http://127.0.0.1:7077", fetchFn, out: (x) => { o.push(x); }, err: (x) => { e.push(x); } }, out: () => o.join(""), err: () => e.join("") };
}
describe("openvault enroll (fake daemon)", () => {
    it("enroll prints deeplink + id; enroll-status prints status", async () => {
        const fetchFn = (input) => {
            const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
            const payload = url.includes("/enrollments/enr-9") ? { status: "pending", alias: "stripe", scope: "charges.read" } : { enrollmentId: "enr-9", deeplink: "openvault://add?alias=stripe&scope=charges.read&enrollment=enr-9" };
            return Promise.resolve(new Response(JSON.stringify(payload), { status: 201, headers: { "content-type": "application/json" } }));
        };
        const cap = capture(fetchFn);
        expect(await runCli(["enroll", "--alias", "stripe", "--scope", "charges.read"], cap.deps)).toBe(0);
        expect(cap.out()).toContain("enr-9");
        expect(cap.out()).toContain("openvault://add?");
        const st = capture(fetchFn);
        expect(await runCli(["enroll-status", "enr-9"], st.deps)).toBe(0);
        expect(st.out()).toContain("pending");
        const bad = capture(fetchFn);
        expect(await runCli(["enroll", "--alias", "stripe"], bad.deps)).toBe(2);
    });
});
