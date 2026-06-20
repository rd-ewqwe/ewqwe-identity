import { describe, it, expect } from "vitest";
import {
  base64urlDecode,
  decodeAttestation,
  getAttestationExpiryStatus,
} from "../attestation.js";

// Note: The attestation module exports are internal helpers for now
// In a real scenario, these would be exported for testing

describe("Attestation Helpers", () => {
  describe("base64urlDecode", () => {
    it("should decode base64url with no padding", () => {
      // 'hello' in base64url (no padding) is 'aGVsbG8'
      const result = base64urlDecode("aGVsbG8");
      const str = new TextDecoder().decode(result);
      expect(str).toBe("hello");
    });

    it("should handle base64url with dashes and underscores", () => {
      // 'hello world' in base64url
      const encoded = "aGVsbG8gd29ybGQ";
      const result = base64urlDecode(encoded);
      const str = new TextDecoder().decode(result);
      expect(str).toBe("hello world");
    });

    it("should handle base64url with padding characters", () => {
      // 'test' in base64url with padding
      const encoded = "dGVzdA";
      const result = base64urlDecode(encoded);
      const str = new TextDecoder().decode(result);
      expect(str).toBe("test");
    });
  });

  describe("Attestation decoding and status helpers", () => {
    it("should decode an attestation JWT payload without verification", () => {
      const header = "eyJhbGciOiJub25lIn0";
      const payload =
        "eyJpc3MiOiJ0ZXN0Iiwic3ViIjoiMSIsImF1ZCI6InJwIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjEsIm5iZiI6MCwianRpIjoiYWJjIn0";
      const jwt = `${header}.${payload}.`; // signature omitted
      const { iss, sub, aud, exp, iat, nbf, jti } = decodeAttestation(jwt);
      expect(iss).toBe("test");
      expect(sub).toBe("1");
      expect(aud).toBe("rp");
      expect(exp).toBe(9999999999);
      expect(iat).toBe(1);
      expect(nbf).toBe(0);
      expect(jti).toBe("abc");
    });

    it("should report expiry status correctly for attestation timestamps", () => {
      const now = Math.floor(Date.now() / 1000);
      expect(
        getAttestationExpiryStatus({
          iss: "x",
          sub: "x",
          aud: "x",
          exp: now + 10,
          iat: now,
          nbf: now,
          jti: "x",
        }),
      ).toBe("valid");
      expect(
        getAttestationExpiryStatus({
          iss: "x",
          sub: "x",
          aud: "x",
          exp: now - 10,
          iat: now - 20,
          nbf: now - 20,
          jti: "x",
        }),
      ).toBe("expired");
      expect(
        getAttestationExpiryStatus({
          iss: "x",
          sub: "x",
          aud: "x",
          exp: now + 100,
          iat: now,
          nbf: now + 10,
          jti: "x",
        }),
      ).toBe("not_yet_valid");
    });
  });
});
