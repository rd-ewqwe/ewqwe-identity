import { describe, expect, it, vi } from "vitest";
import { EwqweApiClient } from "../api-client.js";

type FetchCall = { input: string; init?: RequestInit };

const makeFetchMock = (response: Response) => {
  const calls: FetchCall[] = [];
  const fetchFn = vi.fn(async (input: RequestInfo, init?: RequestInit) => {
    calls.push({ input: String(input), init });
    return response;
  });
  return { fetchFn, calls };
};

describe("EwqweApiClient", () => {
  it("uses custom fetch and builds on baseUrl", async () => {
    const exampleResponse = new Response(
      JSON.stringify({ transaction_id: "t1" }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      },
    );

    const { fetchFn, calls } = makeFetchMock(exampleResponse);
    const client = new EwqweApiClient({
      fetch: fetchFn,
      baseUrl: "https://api.example.com/",
    });

    const result = await client.initOpenID4VPTransaction({
      public_url: "https://example.com",
    });

    expect(result.transaction_id).toBe("t1");
    expect(calls.length).toBe(1);
    expect(calls[0].input).toBe(
      "https://api.example.com/ewqwe_api/openid4vp/init",
    );
    expect(calls[0].init?.method).toBe("POST");
  });

  it("throws on non-ok response with body text", async () => {
    const errorResponse = new Response("not found", {
      status: 404,
      statusText: "Not Found",
    });
    const { fetchFn } = makeFetchMock(errorResponse);
    const client = new EwqweApiClient({ fetch: fetchFn });

    await expect(
      client.initOpenID4VPTransaction({ public_url: "https://example.com" }),
    ).rejects.toThrow("API request failed POST /ewqwe_api/openid4vp/init");
  });

  it("calls verifyPresentation with correct endpoint and payload", async () => {
    const resultToken = { success: true, message: "ok", attestation: "jwt" };
    const verifyResponse = new Response(JSON.stringify(resultToken), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
    const { fetchFn, calls } = makeFetchMock(verifyResponse);
    const client = new EwqweApiClient({ fetch: fetchFn, baseUrl: "" });

    const maybe = await client.verifyPresentation({ vp_token: "abc" });
    expect(maybe.success).toBe(true);
    expect(calls[0].input).toBe("/ewqwe_api/verify");
    expect(calls[0].init?.method).toBe("POST");
    expect(calls[0].init?.body).toBe(JSON.stringify({ vp_token: "abc" }));
  });
});
