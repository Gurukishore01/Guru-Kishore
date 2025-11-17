
export type Page = 'home' | 'register' | 'login' | 'dashboard';

export type BadgeId = 'first_scan' | 'vigilant' | 'connected' | 'secure';

export interface User {
  id: number;
  name: string;
  email: string;
  password: string; // In a real app, this would be a hash
  score: number | null;
  baseScore: number;
  accounts: string[];
  scans: string[];
  badges: BadgeId[];
  fixedIssues: number;
  linkAttempts: number;
  positiveShown: number;
}

export type BreachSeverity = 'critical' | 'high' | 'medium' | 'low';
export type BreachSource = 'live' | 'approximation';
export type VerificationStatus = 'none' | 'verifying' | 'verified' | 'pending';

export interface Breach {
  id: string;
  site: string;
  date: string;
  records: string;
  severity: BreachSeverity;
  description: string;
  recommendation: string;
  source: BreachSource;
  approximationReason: 'api_rate_limited' | 'not_subscribed' | null;
  fixed: boolean;
  weight: number;
  verificationStatus?: VerificationStatus;
}

export interface ScanResult {
  email: string;
  baseScore: number;
  breaches: Breach[];
  scan_version: number;
  verifier: 'system' | 'auto' | 'user';
  change_reason: 'initial_scan' | 'auto_verification_passed' | 'force_rescan';
  created_at: string;
  last_checked_at: string;
  is_public: boolean;
}

export interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'info';
}

export interface FixHistoryEntry {
  userId: number;
  email: string;
  breachId: string;
  timestamp: string;
}

export interface AuditLogEntry {
  userId: number;
  action: string;
  details: Record<string, any>;
  timestamp: string;
}

export interface ChatMessage {
  sender: 'user' | 'assistant';
  text: string;
}

export type LinkedAccountPlatform = 'Facebook' | 'Instagram' | 'Gmail' | 'Twitter' | 'LinkedIn' | 'Yahoo' | 'Snapchat' | 'TikTok' | 'WhatsApp' | 'Telegram';

export type LinkedAccountSeverity = 'high' | 'medium' | 'low' | 'none';

export interface LinkedAccountData {
  platform: LinkedAccountPlatform;
  severity: LinkedAccountSeverity;
  risk: string | null;
  solutions: string[];
}