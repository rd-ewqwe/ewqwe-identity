import type {
  InitTransactionRequest,
  InitTransactionResponse,
  OpenID4VPRequest,
  OpenID4VPResponse,
  PresentationSubmission,
  TransactionStatusResult,
  VerifyRequest,
  VerifyResponse,
} from "./types.js";

export type FetchFn = (
  input: RequestInfo,
  init?: RequestInit,
) => Promise<Response>;

export interface ApiClientOptions {
  fetch?: FetchFn;
  baseUrl?: string;
}

export class EwqweApiClient {
  private fetchFn: FetchFn;
  private baseUrl: string;

  constructor(options?: ApiClientOptions) {
    if (options?.fetch) {
      this.fetchFn = options.fetch;
    } else if (typeof globalThis.fetch === "function") {
      this.fetchFn = globalThis.fetch.bind(globalThis);
    } else {
      throw new Error("No fetch implementation available");
    }

    this.baseUrl = options?.baseUrl?.replace(/\/$/u, "") ?? "";
  }

  private buildUrl(path: string): string {
    if (/^https?:\/\//i.test(path)) {
      return path;
    }
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    return `${this.baseUrl}${normalizedPath}`;
  }

  private async requestJson<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = this.buildUrl(path);
    const response = await this.fetchFn(url, {
      method,
      headers: {
        "Content-Type": "application/json",
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      const errMsg = text
        ? `${response.status} ${response.statusText}: ${text}`
        : `${response.status} ${response.statusText}`;
      throw new Error(`API request failed ${method} ${url}: ${errMsg}`);
    }

    const result = (await response.json()) as T;
    return result;
  }

  async initOpenID4VPTransaction(
    request: InitTransactionRequest,
  ): Promise<InitTransactionResponse> {
    return await this.requestJson<InitTransactionResponse>(
      "POST",
      "/ewqwe_api/openid4vp/init",
      request,
    );
  }

  async getOpenID4VPTransactionStatus(
    transactionId: string,
  ): Promise<TransactionStatusResult> {
    return await this.requestJson<TransactionStatusResult>(
      "GET",
      `/ewqwe_api/openid4vp/status/${encodeURIComponent(transactionId)}`,
    );
  }

  async getOpenID4VPAuthorizationRequest(
    transactionId: string,
  ): Promise<OpenID4VPRequest> {
    return await this.requestJson<OpenID4VPRequest>(
      "GET",
      `/ewqwe_api/openid4vp/request/${encodeURIComponent(transactionId)}`,
    );
  }

  async postOpenID4VPAuthorizationRequest(
    transactionId: string,
    authResponse: OpenID4VPResponse,
  ): Promise<void> {
    await this.requestJson<void>(
      "POST",
      `/ewqwe_api/openid4vp/request/${encodeURIComponent(transactionId)}`,
      authResponse,
    );
  }

  async postOpenID4VPDirectPost(response: OpenID4VPResponse): Promise<void> {
    await this.requestJson<void>(
      "POST",
      "/ewqwe_api/openid4vp/direct_post",
      response,
    );
  }

  async getOpenID4VPJwks(): Promise<{ keys: unknown[] }> {
    return await this.requestJson<{ keys: unknown[] }>(
      "GET",
      "/ewqwe_api/openid4vp/.well-known/jwks.json",
    );
  }

  async verifyPresentation(request: VerifyRequest): Promise<VerifyResponse> {
    return await this.requestJson<VerifyResponse>(
      "POST",
      "/ewqwe_api/verify",
      request,
    );
  }
}
