import { describe, it, expect } from 'vitest';
import {
  buildAgeVerificationQuery,
  buildAgeVerificationQueryWithFallback,
  generateNonce,
  isValidDCQLQuery,
  parseDCQLQuery,
  extractAgeThreshold,
  EU_AV_NAMESPACE,
} from '../dcql.js';

describe('DCQL Functions', () => {
  describe('buildAgeVerificationQuery', () => {
    it('should build query for age 18', () => {
      const query = buildAgeVerificationQuery(18);
      expect(query.credentials).toHaveLength(1);
      expect(query.credentials[0].id).toBe('eu_av_proof');
      expect(query.credentials[0].format).toBe('mso_mdoc');
      expect(query.credentials[0].meta?.doctype_value).toBe('eu.europa.ec.av.1.mdoc');
      expect(query.credentials[0].claims).toHaveLength(1);
      expect(query.credentials[0].claims![0].path).toEqual([EU_AV_NAMESPACE, 'age_over_18']);
      expect(query.credentials[0].claims![0].values).toEqual([true]);
    });

    it('should build query for age 21', () => {
      const query = buildAgeVerificationQuery(21);
      expect(query.credentials[0].claims![0].path).toEqual([EU_AV_NAMESPACE, 'age_over_21']);
    });

    it('should use default age threshold of 18', () => {
      const query = buildAgeVerificationQuery();
      expect(query.credentials[0].claims![0].path).toEqual([EU_AV_NAMESPACE, 'age_over_18']);
    });
  });

  describe('buildAgeVerificationQueryWithFallback', () => {
    it('should build query with EU AV and mDL fallback', () => {
      const query = buildAgeVerificationQueryWithFallback(18);
      expect(query.credentials).toHaveLength(2);
      expect(query.credential_sets).toBeDefined();
      expect(query.credential_sets![0].options).toEqual([['eu_av_proof'], ['mdl_fallback']]);
    });
  });

  describe('generateNonce', () => {
    it('should generate a base64url-encoded nonce', () => {
      const nonce = generateNonce();
      // Should be base64url: only A-Z, a-z, 0-9, -, _
      expect(/^[A-Za-z0-9_-]+$/.test(nonce)).toBe(true);
      // Should be at least some length (32 bytes = ~43 chars in base64)
      expect(nonce.length).toBeGreaterThan(10);
    });

    it('should generate unique nonces', () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      expect(nonce1).not.toBe(nonce2);
    });
  });

  describe('isValidDCQLQuery', () => {
    it('should validate a correct query', () => {
      const query = buildAgeVerificationQuery(18);
      const result = isValidDCQLQuery(query);
      expect(result.valid).toBe(true);
    });

    it('should reject empty credentials', () => {
      const invalid: any = {};
      const result = isValidDCQLQuery(invalid);
      expect(result.valid).toBe(false);
    });

    it('should reject duplicate credential IDs', () => {
      const query: any = {
        credentials: [
          { id: 'dup', format: 'mso_mdoc', claims: [{ path: ['ns', 'claim'] }] },
          { id: 'dup', format: 'mso_mdoc', claims: [{ path: ['ns', 'claim'] }] },
        ],
      };
      const result = isValidDCQLQuery(query);
      expect(result.valid).toBe(false);
    });
  });

  describe('parseDCQLQuery', () => {
    it('should parse valid JSON query', () => {
      const json = JSON.stringify(buildAgeVerificationQuery(18));
      const parsed = parseDCQLQuery(json);
      expect(parsed).toBeDefined();
      expect(parsed?.credentials).toHaveLength(1);
    });

    it('should return null for invalid JSON', () => {
      const parsed = parseDCQLQuery('not json');
      expect(parsed).toBeNull();
    });
  });

  describe('extractAgeThreshold', () => {
    it('should extract age threshold from query', () => {
      const query = buildAgeVerificationQuery(21);
      const threshold = extractAgeThreshold(query);
      expect(threshold).toBe(21);
    });

    it('should return null for non-age query', () => {
      const query: any = {
        credentials: [{
          claims: [{ path: ['other', 'namespace'] }],
        }],
      };
      const threshold = extractAgeThreshold(query);
      expect(threshold).toBeNull();
    });
  });
});
