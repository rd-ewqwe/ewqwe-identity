import type { StoredCredential, VerifiableCredential } from "./types.ts";
import type { DebugLogger } from "./debug.ts";

const STORAGE_KEY = "wallet_credentials";

/**
 * Credential Store - Manages secure storage of digital credentials
 * In a real implementation, this would use the device's secure element
 */
export class CredentialStore {
  private credentials: Map<string, StoredCredential> = new Map();
  private logger: DebugLogger;

  constructor(logger: DebugLogger) {
    this.logger = logger;
    this.loadFromStorage();
  }

  private loadFromStorage(): void {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const credentials: StoredCredential[] = JSON.parse(stored);
        credentials.forEach((cred) => {
          this.credentials.set(cred.id, cred);
        });
        this.logger.log(
          `Loaded ${credentials.length} credentials from storage`,
        );
      }
    } catch (error) {
      this.logger.error("Failed to load credentials from storage", error);
    }
  }

  private saveToStorage(): void {
    try {
      const credentials = Array.from(this.credentials.values());
      localStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
      this.logger.log("Credentials saved to storage");
    } catch (error) {
      this.logger.error("Failed to save credentials to storage", error);
    }
  }

  add(credential: StoredCredential): void {
    this.credentials.set(credential.id, credential);
    this.saveToStorage();
    this.logger.success(`Added credential: ${credential.displayName}`);
  }

  remove(id: string): boolean {
    const deleted = this.credentials.delete(id);
    if (deleted) {
      this.saveToStorage();
      this.logger.log(`Removed credential: ${id}`);
    }
    return deleted;
  }

  get(id: string): StoredCredential | undefined {
    return this.credentials.get(id);
  }

  getAll(): StoredCredential[] {
    return Array.from(this.credentials.values());
  }

  getByType(type: StoredCredential["type"]): StoredCredential[] {
    return this.getAll().filter((cred) => cred.type === type);
  }

  clear(): void {
    this.credentials.clear();
    localStorage.removeItem(STORAGE_KEY);
    this.logger.log("All credentials cleared");
  }

  /**
   * Generate a demo credential for testing
   * In a real implementation, this would come from an Attestation Provider
   */
  generateDemoCredential(
    type: "mdl" | "national-id" | "proof-of-age" | "education" | "employment",
  ): StoredCredential {
    const id = crypto.randomUUID();
    const now = new Date();
    const expiresAt = new Date(now);
    expiresAt.setFullYear(expiresAt.getFullYear() + 5);

    const baseCredential: Omit<
      StoredCredential,
      | "credential"
      | "claims"
      | "displayName"
      | "issuer"
      | "docType"
      | "namespace"
    > = {
      id,
      type,
      issuedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };

    switch (type) {
      case "mdl":
        return {
          ...baseCredential,
          docType: "org.iso.18013.5.1.mDL",
          namespace: "org.iso.18013.5.1",
          displayName: "Mobile Driver's License",
          issuer: "Department of Motor Vehicles",
          claims: {
            family_name: "Smith",
            given_name: "John",
            birth_date: "1990-01-15",
            age_over_21: true,
            age_over_18: true,
            document_number:
              "DL-" + Math.random().toString(36).substring(2, 10).toUpperCase(),
            issuing_authority: "State DMV",
            issuing_country: "US",
          },
          credential: this.createVerifiableCredential(id, "DriverLicense", {
            familyName: "Smith",
            givenName: "John",
            birthDate: "1990-01-15",
          }),
        };

      case "national-id":
        return {
          ...baseCredential,
          docType: "eu.europa.ec.eudi.pid.1",
          namespace: "eu.europa.ec.eudi.pid.1",
          displayName: "National ID Card (EU PID)",
          issuer: "Government Identity Office",
          claims: {
            family_name: "Smith",
            given_name: "John",
            birth_date: "1990-01-15",
            nationality: ["US"],
            place_of_birth: { locality: "New York", country: "US" },
            document_number:
              "ID-" + Math.random().toString(36).substring(2, 12).toUpperCase(),
            issuing_authority: "Government Identity Office",
            issuing_country: "US",
          },
          credential: this.createVerifiableCredential(id, "NationalID", {
            familyName: "Smith",
            givenName: "John",
            birthDate: "1990-01-15",
            nationality: "US",
          }),
        };

      case "proof-of-age":
        return {
          ...baseCredential,
          docType: "eu.europa.ec.av.1",
          namespace: "eu.europa.ec.av.1",
          displayName: "Proof of Age (EU AV)",
          issuer: "EU Age Verification Authority",
          expiresAt: new Date(
            now.getTime() + 90 * 24 * 60 * 60 * 1000,
          ).toISOString(), // 90 days
          claims: {
            age_over_18: true,
          },
          credential: this.createVerifiableCredential(id, "ProofOfAge", {
            age_over_18: true,
          }),
        };

      case "education":
        return {
          ...baseCredential,
          docType: "org.w3c.vc.EducationalCredential",
          namespace: "org.w3c.vc",
          displayName: "University Degree",
          issuer: "State University",
          claims: {
            degree: "Bachelor of Science",
            field: "Computer Science",
            graduation_date: "2012-05-15",
            gpa: "3.8",
          },
          credential: this.createVerifiableCredential(
            id,
            "EducationalCredential",
            {
              degree: "Bachelor of Science",
              field: "Computer Science",
              graduationDate: "2012-05-15",
            },
          ),
        };

      case "employment":
        return {
          ...baseCredential,
          docType: "org.w3c.vc.EmploymentCredential",
          namespace: "org.w3c.vc",
          displayName: "Proof of Employment",
          issuer: "TechCorp Inc.",
          claims: {
            employer: "TechCorp Inc.",
            position: "Senior Software Engineer",
            start_date: "2020-03-01",
            status: "active",
          },
          credential: this.createVerifiableCredential(
            id,
            "EmploymentCredential",
            {
              employer: "TechCorp Inc.",
              position: "Senior Software Engineer",
              startDate: "2020-03-01",
            },
          ),
        };

      default:
        // This should never happen, but TypeScript needs it for exhaustiveness
        throw new Error(`Unknown credential type: ${type}`);
    }
  }

  private createVerifiableCredential(
    id: string,
    type: string,
    subject: Record<string, unknown>,
  ): VerifiableCredential {
    return {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
      ],
      id: `urn:uuid:${id}`,
      type: ["VerifiableCredential", type],
      issuer: "did:example:issuer",
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: "did:example:holder",
        ...subject,
      },
      proof: {
        type: "Ed25519Signature2020",
        created: new Date().toISOString(),
        verificationMethod: "did:example:issuer#key-1",
        proofPurpose: "assertionMethod",
        proofValue: btoa(crypto.randomUUID()), // Demo signature
      },
    };
  }
}
