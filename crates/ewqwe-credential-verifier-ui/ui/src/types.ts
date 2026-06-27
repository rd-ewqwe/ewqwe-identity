export interface User {
  id: string;
  email: string;
  first_name: string | null;
  last_name: string | null;
  role: "admin" | "verifier";
  is_active: boolean;
  is_superadmin: boolean;
  allowed_credential_types: string[];
}

export interface QrResponse {
  transaction_id: string;
  qr_code_data_url: string;
  authorization_request_uri: string;
  expires_in: number;
}

export interface QrStatus {
  status: string;
  expires_in: number;
  errors?: string[];
  age_over_18?: boolean | null;
  /** Serialised map of verified claims from the presented credential. */
  verified_claims?: Record<string, unknown>;
}

export interface AppSettings {
  app_name: string;
  logo_url: string | null;
  allowed_credential_types: string[];
}

export interface SetupStatus {
  bootstrapped: boolean;
}

export interface JournalEntry {
  created_at: string;
  qrcode_app_user_email?: string;
  success: boolean;
  claims: Record<string, unknown>;
  doc_type?: string;
}

// Extend Window to allow global function registration used by inline HTML handlers
declare global {
  interface Window {
    doLogin: (e: Event) => Promise<void>;
    doBootstrap: (e: Event) => Promise<void>;
    doLogout: () => Promise<void>;
    openDrawer: () => void;
    closeDrawer: () => void;
    generateQR: () => Promise<void>;
    cancelQR: () => void;
    resetQR: () => void;
    openCreateUserModal: () => void;
    openEditUserModal: (userId: string) => Promise<void>;
    closeUserModal: () => void;
    submitUserModal: (e: Event) => Promise<void>;
    confirmDeleteUser: (userId: string) => void;
    loadJournal: (offset: number) => Promise<void>;
    journalPage: (dir: number) => void;
    clearJournalFilters: () => void;
    loadSettings: () => Promise<void>;
    saveSettings: () => Promise<void>;
    navigateTo: (page: string) => void;
  }
}
