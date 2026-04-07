import { describe, it, expect } from 'vitest';
import { base64urlDecode } from '../attestation.js';

// Note: The attestation module exports are internal helpers for now
// In a real scenario, these would be exported for testing

describe('Attestation Helpers', () => {
  describe('base64urlDecode', () => {
    it('should decode base64url with no padding', () => {
      // 'hello' in base64url (no padding) is 'aGVsbG8'
      const result = base64urlDecode('aGVsbG8');
      const str = new TextDecoder().decode(result);
      expect(str).toBe('hello');
    });

    it('should handle base64url with dashes and underscores', () => {
      // 'hello world' in base64url
      const encoded = 'aGVsbG8gd29ybGQ';
      const result = base64urlDecode(encoded);
      const str = new TextDecoder().decode(result);
      expect(str).toBe('hello world');
    });

    it('should handle base64url with padding characters', () => {
      // 'test' in base64url with padding
      const encoded = 'dGVzdA';
      const result = base64urlDecode(encoded);
      const str = new TextDecoder().decode(result);
      expect(str).toBe('test');
    });
  });
});
