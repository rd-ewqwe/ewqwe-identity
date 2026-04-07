/**
 * @ewqwe/identity-backend — OpenID4VP Service
 *
 * Orchestrates OpenID4VP transaction lifecycle:
 *   1. Initialize transactions (build DCQL, generate IDs, build auth request URIs)
 *   2. Serve authorization requests (signed JAR for HAIP, plain JSON for Annex A)
 *   3. Receive wallet responses (JWE decryption for HAIP, plain for Annex A)
 *   4. Poll transaction status
 *   5. Forward verification to credential verifier backend
 *
 * This service is transport-agnostic — it accepts and returns plain data objects,
 * never HTTP Request/Response. The server layer maps HTTP ↔ service calls.
 *
 * @see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
 */

import type { DCQLQuery, TransactionStatusResult } from "@ewqwe/identity-front";
import {
  convertPresentationDefinitionToDCQL,
  determineProfile,
  getDefaultAgeVerificationDCQL,
} from "@ewqwe/identity-front";

import type {
  AuthorizationRequestResult,
  ClientMetadata,
  InitTransactionRequest,
  JarKeyMaterial,
  JweKeyMaterial,
  OpenID4VPConfig,
  OpenID4VPTransaction,
  VerifyRequest,
  WalletDirectPostData,
} from "./types.ts";
import type {
  InitTransactionResponse,
  VerifyResponse,
} from "@ewqwe/identity-front";
import {
  buildPublicJwkSet,
  decryptJweResponse,
  initializeJarKey,
  initializeJweKey,
  signJar,
} from "./crypto.ts";
import { TransactionStore } from "./transaction-store.ts";

const DEFAULT_TRANSACTION_TTL_MS = 5 * 60 * 1000; // 5 minutes
const JAR_KEY_ID = "ewqwe-jar-key-1";
const JWE_KEY_ID = "ewqwe-enc-key-1";

export class OpenID4VPService {
  private config: OpenID4VPConfig;
  private jarKey!: JarKeyMaterial;
  private jweKey!: JweKeyMaterial;
  private transactions: TransactionStore;
  private httpClient?: Deno.HttpClient;
  private ttlMs: number;

  private constructor(config: OpenID4VPConfig) {
    this.config = config;
    this.transactions = new TransactionStore();
    this.ttlMs = config.transactionTtlMs ?? DEFAULT_TRANSACTION_TTL_MS;
  }

  /**
   * Create and initialize an OpenID4VP service instance.
   * Loads keys, certificates, and starts background cleanup.
   */
  static async create(config: OpenID4VPConfig): Promise<OpenID4VPService> {
    const service = new OpenID4VPService(config);
    await service.initialize();
    return service;
  }

  private async initialize(): Promise<void> {
    // Load JAR signing key
    this.jarKey = await initializeJarKey(
      this.config.x509CertPath,
      this.config.x509KeyPath,
      JAR_KEY_ID,
    );
    console.log(
      `[OpenID4VP] Loaded ${this.jarKey.x5cChain.length} certificate(s), SAN DNS: ${this.jarKey.sanDnsName}`,
    );

    // Generate JWE encryption key
    this.jweKey = await initializeJweKey(JWE_KEY_ID);
    console.log(`[OpenID4VP] Generated ECDH P-256 encryption key pair`);

    // Load CA certificate for credential verifier mTLS
    if (this.config.caCertPath) {
      try {
        const caCert = await Deno.readTextFile(this.config.caCertPath);
        this.httpClient = Deno.createHttpClient({ caCerts: [caCert] });
        console.log(
          `[OpenID4VP] Loaded CA certificate from ${this.config.caCertPath}`,
        );
      } catch (e) {
        console.warn(`[OpenID4VP] Could not load CA certificate:`, e);
      }
    }

    // Start transaction cleanup
    this.transactions.startCleanup();
  }

  /** Shut down the service (stop timers, close clients). */
  shutdown(): void {
    this.transactions.stopCleanup();
    this.httpClient?.close();
  }

  // ==========================================================================
  // Transaction Lifecycle
  // ==========================================================================

  /**
   * Initialize a new OpenID4VP transaction.
   * Builds the DCQL query, authorization request URI, and returns data for
   * the QR code (cross-device) or deep link (same-device).
   */
  async initTransaction(
    request: InitTransactionRequest,
  ): Promise<InitTransactionResponse> {
    const profile = determineProfile(request.credential_type, request.profile);

    const transactionId = crypto.randomUUID();
    const state = crypto.randomUUID();
    const nonce = request.nonce || crypto.randomUUID();
    const now = Date.now();
    const expiresAt = now + this.ttlMs;

    const responseUri = `${this.config.publicUrl}/api/openid4vp/direct_post`;
    const requestUri = `${this.config.publicUrl}/api/openid4vp/request/${transactionId}`;

    // Determine client_id, scheme, response_mode, and URL scheme per profile
    let clientId: string;
    let clientIdScheme: "x509_san_dns" | "redirect_uri";
    let responseMode: "direct_post" | "direct_post.jwt";
    let urlScheme: string;

    if (profile === "haip") {
      clientIdScheme = "x509_san_dns";
      clientId = `x509_san_dns:${this.jarKey.sanDnsName}`;
      responseMode = "direct_post.jwt";
      urlScheme = "eudi-openid4vp://";
    } else {
      clientIdScheme = "redirect_uri";
      clientId = `redirect_uri:${responseUri}`;
      responseMode = "direct_post";
      urlScheme = "av://";
    }

    // Resolve DCQL query
    let dcqlQuery: DCQLQuery;
    if (request.dcql_query) {
      dcqlQuery = request.dcql_query;
    } else if (request.presentation_definition) {
      dcqlQuery = convertPresentationDefinitionToDCQL(
        request.presentation_definition,
      );
    } else {
      dcqlQuery = getDefaultAgeVerificationDCQL();
    }

    // Build client metadata
    const clientMetadata: ClientMetadata = request.client_metadata || {
      client_name: "EwQwE Age Verification Demo",
      logo_uri: `${this.config.publicUrl}/logo.png`,
      vp_formats: {
        mso_mdoc: {
          issuerauth_alg_values: [-7, -35, -36],
          deviceauth_alg_values: [-7, -35, -36],
        },
      },
    };

    // Store the transaction
    const transaction: OpenID4VPTransaction = {
      id: transactionId,
      state,
      nonce,
      createdAt: now,
      expiresAt,
      status: "pending",
      dcqlQuery,
      clientId,
      clientIdScheme,
      responseUri,
      responseMode,
      profile,
      clientMetadata,
    };
    this.transactions.set(transaction);

    // Build authorization request URI
    const authorizationRequestUri = this.buildAuthorizationRequestUri(
      profile,
      urlScheme,
      clientId,
      requestUri,
      responseMode,
      responseUri,
      nonce,
      state,
      dcqlQuery,
    );

    console.log(
      `[OpenID4VP] Transaction created: ${transactionId.slice(0, 8)}... profile=${profile} clientId=${clientId}`,
    );

    return {
      transaction_id: transactionId,
      client_id: clientId,
      client_id_scheme: clientIdScheme,
      request_uri: requestUri,
      authorization_request_uri: authorizationRequestUri,
      deep_link_uri: authorizationRequestUri,
      expires_in: Math.floor(this.ttlMs / 1000),
      profile,
    };
  }

  /**
   * Build the authorization request that the wallet fetches via request_uri.
   * Returns a signed JAR (HAIP) or plain JSON (Annex A).
   */
  async getAuthorizationRequest(
    transactionId: string,
  ): Promise<AuthorizationRequestResult> {
    const transaction = this.transactions.get(transactionId);
    if (!transaction) throw new NotFoundError("Transaction not found");
    if (this.transactions.isExpired(transactionId)) {
      throw new ExpiredError("Transaction expired");
    }

    // Build client_metadata, adding JWE encryption params for HAIP
    const baseFormats = transaction.clientMetadata?.vp_formats || {
      mso_mdoc: {
        issuerauth_alg_values: [-7, -35, -36],
        deviceauth_alg_values: [-7, -35, -36],
      },
    };

    // deno-lint-ignore no-explicit-any
    const clientMetadata: Record<string, any> = {
      client_name:
        transaction.clientMetadata?.client_name ||
        "EwQwE Age Verification Demo",
      logo_uri:
        transaction.clientMetadata?.logo_uri ||
        `${this.config.publicUrl}/logo.png`,
      vp_formats_supported: baseFormats,
    };

    if (transaction.profile === "haip") {
      clientMetadata.jwks = { keys: [this.jweKey.publicJwk] };
      clientMetadata.authorization_encrypted_response_alg = "ECDH-ES";
      clientMetadata.authorization_encrypted_response_enc = "A256GCM";
    }

    if (transaction.profile === "haip") {
      // HAIP: Signed JAR
      const jwt = await signJar(
        {
          clientId: transaction.clientId,
          clientIdScheme: transaction.clientIdScheme,
          responseMode: transaction.responseMode,
          responseUri: transaction.responseUri,
          state: transaction.state,
          nonce: transaction.nonce,
          dcqlQuery: transaction.dcqlQuery,
          clientMetadata,
          expiresAt: transaction.expiresAt,
        },
        this.jarKey,
      );
      return { body: jwt, contentType: "application/oauth-authz-req+jwt" };
    } else {
      // Annex A: Plain JSON
      const authRequest = {
        client_id: transaction.clientId,
        client_id_scheme: transaction.clientIdScheme,
        response_type: "vp_token",
        response_mode: transaction.responseMode,
        response_uri: transaction.responseUri,
        state: transaction.state,
        nonce: transaction.nonce,
        dcql_query: transaction.dcqlQuery,
        client_metadata: clientMetadata,
      };
      return {
        body: JSON.stringify(authRequest),
        contentType: "application/json",
      };
    }
  }

  /**
   * Process a wallet direct_post response.
   * For HAIP, decrypts the JWE. Stores the response in the transaction.
   *
   * @param data Pre-parsed wallet data: either plain fields or a JWE `response` string.
   * @param jweResponse If present, a JWE compact serialization to decrypt.
   * @param fallbackState State value from outside the JWE (some wallets duplicate it).
   */
  async handleWalletResponse(
    data: WalletDirectPostData | null,
    jweResponse?: string,
    fallbackState?: string,
  ): Promise<void> {
    let walletData: WalletDirectPostData;

    if (jweResponse) {
      // HAIP: Decrypt JWE
      const decrypted = await decryptJweResponse(jweResponse, this.jweKey);
      walletData = {
        vpToken: decrypted.vpToken,
        presentationSubmission: decrypted.presentationSubmission,
        state: decrypted.state || fallbackState || "",
      };
    } else if (data) {
      walletData = data;
    } else {
      throw new BadRequestError("No wallet response data provided");
    }

    // Find transaction by state
    const transaction = this.transactions.findByState(walletData.state);
    if (!transaction) {
      throw new BadRequestError(
        `No transaction found for state: ${walletData.state}`,
      );
    }

    transaction.walletResponse = walletData;
    transaction.status = "received";
    console.log(
      `[OpenID4VP] Transaction ${transaction.id.slice(0, 8)}... status → received`,
    );
  }

  /**
   * Get the current status of a transaction.
   * If the wallet has responded, includes the VP token for the frontend to verify.
   */
  getTransactionStatus(transactionId: string): TransactionStatusResult {
    const transaction = this.transactions.get(transactionId);
    if (!transaction) throw new NotFoundError("Transaction not found");

    if (this.transactions.isExpired(transactionId)) {
      return { status: "expired" };
    }

    if (transaction.status === "received" && transaction.walletResponse) {
      return {
        status: "received",
        vp_token: transaction.walletResponse.vpToken,
        presentation_submission:
          transaction.walletResponse.presentationSubmission,
        nonce: transaction.nonce,
        state: transaction.state,
      };
    }

    return {
      status: transaction.status,
      expires_in: Math.floor((transaction.expiresAt - Date.now()) / 1000),
    };
  }

  // ==========================================================================
  // Credential Verification
  // ==========================================================================

  /**
   * Forward a verification request to the credential verifier backend.
   * Normalizes vp_token (object→string) and strips empty presentation_submission.
   */
  async verifyCredential(request: VerifyRequest): Promise<VerifyResponse> {
    // Normalize vp_token to string
    const body = { ...request };
    if (typeof body.vp_token === "object" && body.vp_token !== null) {
      // deno-lint-ignore no-explicit-any
      (body as any).vp_token = JSON.stringify(body.vp_token);
    }

    // Strip empty/falsy presentation_submission (DCQL mode)
    if (!body.presentation_submission) {
      delete body.presentation_submission;
    }

    const verifierUrl = `${this.config.credentialVerifierUrl}/api/verify`;
    const fetchOptions: RequestInit & { client?: Deno.HttpClient } = {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    };
    if (this.httpClient) {
      fetchOptions.client = this.httpClient;
    }

    const response = await fetch(verifierUrl, fetchOptions);

    if (!response.ok) {
      const errorText = await response.text();
      throw new VerifierError(response.status, errorText);
    }

    return (await response.json()) as VerifyResponse;
  }

  // ==========================================================================
  // Public JWKS
  // ==========================================================================

  /** Returns the public JWK Set for JAR signature verification. */
  getPublicJwkSet(): { keys: unknown[] } {
    return buildPublicJwkSet(this.jarKey);
  }

  // ==========================================================================
  // Private Helpers
  // ==========================================================================

  private buildAuthorizationRequestUri(
    profile: "haip" | "annex-a",
    urlScheme: string,
    clientId: string,
    requestUri: string,
    responseMode: string,
    responseUri: string,
    nonce: string,
    state: string,
    dcqlQuery: DCQLQuery,
  ): string {
    if (profile === "haip") {
      // HAIP: wallet fetches signed JAR from request_uri
      return `${urlScheme}?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(requestUri)}`;
    }

    // Annex A: all parameters inline
    const clientMetadataForUrl = {
      client_name: "EwQwE Age Verification Demo",
      logo_uri: `${this.config.publicUrl}/logo.png`,
      vp_formats_supported: {
        mso_mdoc: {
          issuerauth_alg_values: [-7, -35, -36],
          deviceauth_alg_values: [-7, -35, -36],
        },
      },
    };

    const params = new URLSearchParams();
    params.set("client_id", clientId);
    params.set("response_type", "vp_token");
    params.set("response_mode", responseMode);
    params.set("response_uri", responseUri);
    params.set("nonce", nonce);
    params.set("state", state);
    params.set("dcql_query", JSON.stringify(dcqlQuery));
    params.set("client_metadata", JSON.stringify(clientMetadataForUrl));
    return `${urlScheme}?${params.toString()}`;
  }
}

// ============================================================================
// Error Types
// ============================================================================

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

export class ExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExpiredError";
  }
}

export class BadRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BadRequestError";
  }
}

export class VerifierError extends Error {
  public status: number;
  public responseText: string;
  constructor(status: number, responseText: string) {
    super(`Credential Verifier returned ${status}`);
    this.name = "VerifierError";
    this.status = status;
    this.responseText = responseText;
  }
}
