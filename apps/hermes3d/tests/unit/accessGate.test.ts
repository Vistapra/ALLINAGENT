// @vitest-environment node

import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";

describe("createAccessGate", () => {
  it("allows when token is unset", async () => {
    const { createAccessGate } = await import("../../server/access-gate");
    const gate = createAccessGate({ token: "" });
    expect(gate.allowUpgrade({ headers: {} })).toBe(true);
  });

  it("rejects /api requests without cookie when enabled", async () => {
    const { createAccessGate } = await import("../../server/access-gate");
    const gate = createAccessGate({ token: "abc" });

    let statusCode = 0;
    let ended = false;
    const res = {
      setHeader: () => {},
      end: () => {
        ended = true;
      },
      get statusCode() {
        return statusCode;
      },
      set statusCode(value: number) {
        statusCode = value;
      },
    };

    const handled = gate.handleHttp(
      { url: "/api/studio", headers: { host: "example.test" } },
      res
    );

    expect(handled).toBe(true);
    expect(statusCode).toBe(401);
    expect(ended).toBe(true);
  });

  it("allows upgrades when cookie matches", async () => {
    const { createAccessGate } = await import("../../server/access-gate");
    const gate = createAccessGate({ token: "abc" });
    expect(
      gate.allowUpgrade({ headers: { cookie: "studio_access=abc" } })
    ).toBe(true);
  });

  it("does NOT increment brute-force failure counter on unauthenticated GET page 302 redirects to /login", async () => {
    const { createAccessGate } = await import("../../server/access-gate");
    const gate = createAccessGate({ token: "abc" });

    for (let index = 0; index < 25; index++) {
      let statusCode = 0;
      const headers: Record<string, string> = {};
      const res = {
        setHeader: (k: string, v: string) => {
          headers[k.toLowerCase()] = v;
        },
        end: () => {},
        get statusCode() {
          return statusCode;
        },
        set statusCode(value: number) {
          statusCode = value;
        },
      };
      const handled = gate.handleHttp(
        {
          method: "GET",
          url: "/office",
          headers: { accept: "text/html,application/xhtml+xml" },
          socket: { remoteAddress: "127.0.0.1" },
        },
        res
      );
      expect(handled).toBe(true);
      expect(statusCode).toBe(302);
      expect(headers.location).toBe("/login");
    }

    // Subsequent POST /api/studio-auth/login with valid token still succeeds (not locked out)
    const loginReq = Object.assign(new EventEmitter(), {
      method: "POST",
      url: "/api/studio-auth/login",
      headers: { "content-type": "application/json" },
      socket: { remoteAddress: "127.0.0.1" },
    });
    let loginStatus = 0;
    const loginRes = {
      setHeader: () => {},
      end: () => {},
      get statusCode() {
        return loginStatus;
      },
      set statusCode(v: number) {
        loginStatus = v;
      },
    };
    gate.handleHttp(loginReq, loginRes);
    loginReq.emit("data", Buffer.from(JSON.stringify({ token: "abc" })));
    loginReq.emit("end");
    expect(loginStatus).toBe(200);
  });

  it("returns 429 after repeated failed invalid-credential attempts", async () => {
    const { createAccessGate } = await import("../../server/access-gate");
    const gate = createAccessGate({ token: "abc" });

    const createResponse = () => {
      let statusCode = 0;
      let body = "";
      return {
        setHeader: () => {},
        end: (value?: string) => {
          body = value ?? "";
        },
        get statusCode() {
          return statusCode;
        },
        set statusCode(value: number) {
          statusCode = value;
        },
        get body() {
          return body;
        },
      };
    };

    for (let index = 0; index < 9; index++) {
      const res = createResponse();
      gate.handleHttp(
        {
          url: "/api/studio",
          headers: { cookie: "studio_access=invalid-token" },
          socket: { remoteAddress: "127.0.0.1" },
        },
        res
      );
      expect(res.statusCode).toBe(401);
    }

    const limited = createResponse();
    gate.handleHttp(
      {
        url: "/api/studio",
        headers: { cookie: "studio_access=invalid-token" },
        socket: { remoteAddress: "127.0.0.1" },
      },
      limited
    );

    expect(limited.statusCode).toBe(429);
    expect(limited.body).toContain("Too many failed studio access attempts");
  });

  it("recovers immediately when a valid cookie is sent after throttling", async () => {
    const { createAccessGate } = await import("../../server/access-gate");
    const gate = createAccessGate({ token: "abc" });

    const createResponse = () => {
      let statusCode = 0;
      let body = "";
      return {
        setHeader: () => {},
        end: (value?: string) => {
          body = value ?? "";
        },
        get statusCode() {
          return statusCode;
        },
        set statusCode(value: number) {
          statusCode = value;
        },
        get body() {
          return body;
        },
      };
    };

    for (let index = 0; index < 10; index++) {
      const res = createResponse();
      gate.handleHttp(
        {
          url: "/api/studio",
          headers: { cookie: "studio_access=invalid-token" },
          socket: { remoteAddress: "127.0.0.1" },
        },
        res
      );
    }

    expect(
      gate.allowUpgrade({
        headers: { cookie: "studio_access=abc" },
        socket: { remoteAddress: "127.0.0.1" },
      })
    ).toBe(true);

    const recovered = createResponse();
    gate.handleHttp(
      {
        url: "/api/studio",
        headers: { cookie: "studio_access=abc" },
        socket: { remoteAddress: "127.0.0.1" },
      },
      recovered
    );

    expect(recovered.statusCode).toBe(0);

    const afterReset = createResponse();
    gate.handleHttp(
      {
        url: "/api/studio",
        headers: { cookie: "studio_access=invalid-token" },
        socket: { remoteAddress: "127.0.0.1" },
      },
      afterReset
    );

    expect(afterReset.statusCode).toBe(401);
    expect(afterReset.body).toContain("Studio access token required");
  });
});
