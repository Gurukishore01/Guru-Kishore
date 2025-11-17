import { Breach, LinkedAccountData, BadgeId } from './types';

// This list is updated to reflect the services mentioned in the new AI-powered scan logic.
// While not used for initial scan generation anymore, it can serve as a reference.
export const PREDEFINED_BREACHES: Omit<Breach, 'id' | 'source' | 'approximationReason' | 'fixed' | 'weight' | 'verificationStatus'>[] = [
  { site: 'LinkedIn', date: '2021-06', records: '700M', severity: 'high', description: 'Email addresses and profile information leaked.', recommendation: 'Update password and review profile visibility.' },
  { site: 'Instagram', date: '2021-08', records: '200M', severity: 'high', description: 'User credentials and contact info exposed via a third-party app integration.', recommendation: 'Change your password and review third-party app access.' },
  { site: 'Boat', date: '2023-03', records: '7.5M', severity: 'medium', description: 'Customer data including names, email addresses, and phone numbers leaked.', recommendation: 'Be cautious of phishing attempts. Update your password if you have a Boat account.' },
  { site: 'Free Fire', date: '2020-07', records: '20M', severity: 'high', description: 'Player IDs, device information, and some personal details were exposed.', recommendation: 'Ensure your linked social media accounts are secure and change related passwords.' },
];

export const SEVERITY_WEIGHTS: { [key: string]: number } = {
  critical: 15,
  high: 10,
  medium: 5,
  low: 3,
};

export const LINKED_ACCOUNTS_DATA: LinkedAccountData[] = [
    { platform: 'Facebook', severity: 'high', risk: 'Password found in Cambridge Analytica breach (2019-04-03)', solutions: ['Immediately change your Facebook password.', 'Enable Two-Factor Authentication (2FA) in your security settings.', 'Review and revoke access for any suspicious third-party apps.'] },
    { platform: 'Instagram', severity: 'medium', risk: 'Account credentials leaked in third-party app breach (2021-08-15)', solutions: ['Change your Instagram password.', 'Ensure your linked email account is secure.', 'Be cautious of phishing attempts asking for your login details.'] },
    { platform: 'Twitter', severity: 'low', risk: 'Email address exposed in data scraping incident (2022-01-20)', solutions: ['Ensure your password is unique and not used elsewhere.', 'Review your privacy settings to control who can find you by email.', 'Be aware of potential spam or phishing emails.'] },
    { platform: 'LinkedIn', severity: 'medium', risk: 'Profile data included in 700M user leak (2021-06-22)', solutions: ['Update your LinkedIn password for security.', 'Review your profile visibility and connection requests.', 'Be wary of unsolicited messages or connection requests.'] },
    { platform: 'Gmail', severity: 'none', risk: null, solutions: [] },
    { platform: 'Snapchat', severity: 'none', risk: null, solutions: [] },
];

export const BADGES: { id: BadgeId; name: string; description: string; icon: string; }[] = [
  { id: 'first_scan', name: 'First Scan', description: 'Completed your first security scan', icon: '🔍' },
  { id: 'vigilant', name: 'Vigilant', description: 'Fixed 3 security issues', icon: '🛡️' },
  { id: 'connected', name: 'Connected', description: 'Linked 2 accounts', icon: '🔗' },
  { id: 'secure', name: 'Secure', description: 'Achieved 90+ privacy score', icon: '⭐' },
];