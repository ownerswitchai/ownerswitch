import { describe, expect, it } from "vitest";
import { createVetoClient, VetoClientError } from "./veto-client.js";

const DEVICE = { id: "gw-1", secret: "s3cret" };

const jsonResponse =
  (body: unknown, status = 200): typeof fetch =>
  async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });

const client = (fetchImpl: typeof fetch) =>
  createVetoClient({ baseUrl: "http://control-plane.test", device: DEVICE, fetchImpl });

describe("createVetoClient", () => {
  it("register returns the window id from a 201", async () => {
    await expect(
      client(jsonResponse({ id: "veto_ab12", status: "pending" }, 201)).register({
        agentId: "a1",
        tool: "write_file",
      }),
    ).resolves.toEqual({ id: "veto_ab12" });
  });

  it("register maps a 401 to a device-credentials message (quickstart's likely mistake)", async () => {
    const err = await client(jsonResponse({ error: "unauthorized" }, 401))
      .register({ agentId: "a1", tool: "write_file" })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(VetoClientError);
    expect((err as VetoClientError).message).toContain("device credentials");
    expect((err as VetoClientError).httpStatus).toBe(401);
  });

  it("register fails closed on network errors and malformed bodies", async () => {
    const rejecting: typeof fetch = async () => {
      throw new Error("ECONNREFUSED");
    };
    await expect(client(rejecting).register({ agentId: "a1", tool: "t" })).rejects.toThrowError(
      /unreachable — fail closed/,
    );
    await expect(
      client(jsonResponse({ notAnId: true }, 201)).register({ agentId: "a1", tool: "t" }),
    ).rejects.toThrowError(VetoClientError);
  });

  it("status returns the window state, 'missing' on 404, and rejects garbage", async () => {
    await expect(client(jsonResponse({ status: "vetoed" })).status("veto_1")).resolves.toBe("vetoed");
    await expect(client(jsonResponse({ error: "gone" }, 404)).status("veto_1")).resolves.toBe(
      "missing",
    );
    await expect(client(jsonResponse({ status: "sideways" })).status("veto_1")).rejects.toThrowError(
      VetoClientError,
    );
  });

  it("status passes 'spent' through — a release from a dead kill epoch must reach the proxy", async () => {
    await expect(client(jsonResponse({ status: "spent" })).status("veto_1")).resolves.toBe("spent");
  });

  it("times out hung requests and fails closed", async () => {
    const hanging: typeof fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      });
    const slow = createVetoClient({
      baseUrl: "http://control-plane.test",
      device: DEVICE,
      timeoutMs: 10,
      fetchImpl: hanging,
    });
    await expect(slow.status("veto_1")).rejects.toThrowError(/unreachable — fail closed/);
  });
});
