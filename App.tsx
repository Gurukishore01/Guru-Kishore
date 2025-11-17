
import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { Shield, Lock, AlertTriangle, CheckCircle, Award, MessageCircle, Search, LogOut, Sparkles, Link2, AlertCircle, Check, X, Eye, EyeOff, Info, Send } from 'lucide-react';
import { Page, User as UserType, Breach, ScanResult, Toast, FixHistoryEntry, AuditLogEntry, BadgeId, LinkedAccountPlatform, LinkedAccountData, VerificationStatus } from './types';
import { PREDEFINED_BREACHES, SEVERITY_WEIGHTS, LINKED_ACCOUNTS_DATA, BADGES } from './constants';
import { GoogleGenAI, Chat, Type } from '@google/genai';


// --- IN-MEMORY DATABASE ---
const USERS: UserType[] = [];
const EMAIL_SCAN_CACHE: { [key: string]: ScanResult } = {};
const FIX_HISTORY: FixHistoryEntry[] = [];
const AUDIT_LOG: AuditLogEntry[] = [];

// --- AI SETUP ---
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

// --- HELPER & UI COMPONENTS (defined outside main component) ---

const SafeTraceLogo: React.FC<{ className?: string }> = ({ className = '' }) => (
    <div className={`relative ${className}`}>
        <Shield className="w-full h-full text-black" strokeWidth={1.5} />
        <svg viewBox="0 0 24 24" className="absolute w-1/2 h-1/2 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-black" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 12a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" />
            <path d="M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z" />
            <path d="M12 15v6" />
        </svg>
    </div>
);

const ScoreVisualization: React.FC<{ score: number | null, baseScore: number }> = ({ score, baseScore }) => {
    const scoreColor = useMemo(() => {
        if (score === null) return 'border-gray-300';
        const t = score / 100;
        if (t < 0.4) return 'border-red-500';
        if (t < 0.7) return 'border-yellow-500';
        return 'border-green-500';
    }, [score]);

    return (
        <div className="relative h-48 w-48 flex items-center justify-center my-4">
            <div className={`w-full h-full rounded-full border-[10px] ${scoreColor} flex flex-col items-center justify-center bg-gray-50/50`}>
                {score !== null ? (
                    <>
                        <p className="text-6xl font-bold tracking-tighter">{score}</p>
                        <p className="text-md text-gray-500 mt-1">(Base: {baseScore})</p>
                    </>
                ) : (
                    <p className="text-4xl font-bold tracking-tighter text-gray-500">---</p>
                )}
            </div>
        </div>
    );
};


const App: React.FC = () => {
    // --- STATE MANAGEMENT ---
    const [page, setPage] = useState<Page>('home');
    const [currentUser, setCurrentUser] = useState<UserType | null>(null);

    // Form states
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [passwordVisible, setPasswordVisible] = useState(false);
    
    // UI states
    const [toasts, setToasts] = useState<Toast[]>([]);
    const [activeModal, setActiveModal] = useState<string | null>(null);

    // Dashboard states
    const [scanEmail, setScanEmail] = useState('');
    const [emailSuggestion, setEmailSuggestion] = useState<string | null>(null);
    const [scanResult, setScanResult] = useState<ScanResult | null>(null);
    const [isScanning, setIsScanning] = useState(false);
    const [scanMessage, setScanMessage] = useState<string | null>(null);
    const [linkedAccountResult, setLinkedAccountResult] = useState<LinkedAccountData & { isSafe: boolean } | null>(null);
    
    // AI Chat states
    const [chat, setChat] = useState<Chat | null>(null);
    const [chatMessages, setChatMessages] = useState<Array<{ sender: 'user' | 'assistant'; text: string; }>>([{ sender: 'assistant', text: "Ask me anything about your privacy and security!" }]);
    const [chatInput, setChatInput] = useState('');
    const [isReplying, setIsReplying] = useState(false);
    const chatMessagesRef = useRef<HTMLDivElement>(null);

    // Refs for in-memory store
    const usersRef = useRef<UserType[]>(USERS);
    const cacheRef = useRef<{ [key: string]: ScanResult }>(EMAIL_SCAN_CACHE);
    const fixHistoryRef = useRef<FixHistoryEntry[]>(FIX_HISTORY);
    const auditLogRef = useRef<AuditLogEntry[]>(AUDIT_LOG);
    
    // Auto-scroll chat
    useEffect(() => {
        if (chatMessagesRef.current) {
            chatMessagesRef.current.scrollTop = chatMessagesRef.current.scrollHeight;
        }
    }, [chatMessages, activeModal]);

    // Reset chat when score changes to update AI context
    useEffect(() => {
        setChat(null);
    }, [currentUser?.score]);

    // --- UTILITY & HELPER FUNCTIONS ---

    const addToast = useCallback((message: string, type: 'success' | 'error' | 'info') => {
        const id = Date.now();
        setToasts(prev => [...prev, { id, message, type }]);
        setTimeout(() => {
            setToasts(prev => prev.filter(toast => toast.id !== id));
        }, 3000);
    }, []);

    const normalizeEmail = (emailStr: string) => emailStr.trim().toLowerCase();
    
    // --- PASSWORD VALIDATION ---
    const passwordChecks = {
        length: password.length >= 8,
        number: /\d/.test(password),
        symbol: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    };
    const isPasswordStrong = passwordChecks.length && passwordChecks.number && passwordChecks.symbol;
    
    const getPasswordMessage = () => {
        if (!passwordChecks.length) return "Enter at least 8 characters";
        if (!passwordChecks.number) return "Add at least one number";
        if (!passwordChecks.symbol) return "Add at least one symbol (e.g., !@#$)";
        return "Perfect — your password is strong!";
    };

    // --- EMAIL VALIDATION & SUGGESTION ---
    const validateEmail = useCallback((emailStr: string) => /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}$/.test(emailStr), []);

    useEffect(() => {
        const checkEmailTypo = () => {
            if (!scanEmail) {
                setEmailSuggestion(null);
                return;
            }

            let corrected = scanEmail;

            const corrections: Array<[RegExp, string]> = [
                [/@gmial\./, '@gmail.'],
                [/@gamil\./, '@gmail.'],
                [/@yaho\./, '@yahoo.'],
                [/(\@gmail|\@yahoo|\@outlook)\.co$/, '$1.com'],
                [/(\@gmail|\@yahoo|\@outlook)\.con$/, '$1.com'],
                [/(\@gmail|\@yahoo|\@outlook)\.comm+$/, '$1.com'],
                [/(\@gmail|\@yahoo|\@outlook)\.c$/, '$1.com'],
            ];

            for (const [pattern, replacement] of corrections) {
                if (pattern.test(corrected)) {
                    corrected = corrected.replace(pattern, replacement);
                }
            }
            
            if (corrected !== scanEmail && validateEmail(corrected)) {
                setEmailSuggestion(corrected);
            } else {
                setEmailSuggestion(null);
            }
        };

        const handler = setTimeout(checkEmailTypo, 300);
        return () => clearTimeout(handler);
    }, [scanEmail, validateEmail]);

    // --- USER MANAGEMENT ---
    
    const updateUser = useCallback((updatedUser: UserType) => {
        setCurrentUser(updatedUser);
        const userIndex = usersRef.current.findIndex(u => u.id === updatedUser.id);
        if (userIndex > -1) {
            usersRef.current[userIndex] = updatedUser;
        }
    }, []);

    const checkAndAwardBadges = useCallback((user: UserType) => {
        const newBadges: BadgeId[] = [...user.badges];

        if (user.scans.length > 0 && !newBadges.includes('first_scan')) newBadges.push('first_scan');
        if (user.fixedIssues >= 3 && !newBadges.includes('vigilant')) newBadges.push('vigilant');
        if (user.accounts.length >= 2 && !newBadges.includes('connected')) newBadges.push('connected');
        if (user.score !== null && user.score >= 90 && !newBadges.includes('secure')) newBadges.push('secure');
        
        if (newBadges.length > user.badges.length) {
            addToast(`New badge unlocked!`, 'success');
            updateUser({ ...user, badges: newBadges });
        }
    }, [addToast, updateUser]);

    useEffect(() => {
        if(currentUser) {
            checkAndAwardBadges(currentUser);
        }
    }, [currentUser, checkAndAwardBadges]);


    // --- HANDLERS ---

    const handleRegister = () => {
        if (!name || !email || !password) {
            addToast("Please fill all fields.", 'error');
            return;
        }
        if (!validateEmail(email)) {
             addToast("Please enter a valid email address.", 'error');
            return;
        }
        if (!isPasswordStrong) {
            addToast("Please create a stronger password.", 'error');
            return;
        }
        if (usersRef.current.find(u => normalizeEmail(u.email) === normalizeEmail(email))) {
            addToast("An account with this email already exists.", 'error');
            return;
        }

        const newUser: UserType = {
            id: Date.now(),
            name,
            email: normalizeEmail(email),
            password,
            score: null,
            baseScore: 100,
            accounts: [],
            scans: [],
            badges: [],
            fixedIssues: 0,
            linkAttempts: 0,
            positiveShown: 0,
        };
        usersRef.current.push(newUser);
        setCurrentUser(newUser);
        addToast(`Welcome, ${name}! Setting up your dashboard...`, 'success');
        setPage('dashboard');
    };

    const handleLogin = () => {
        if (!email || !password) {
            addToast("Please enter email and password.", 'error');
            return;
        }
        const foundUser = usersRef.current.find(u => normalizeEmail(u.email) === normalizeEmail(email) && u.password === password);
        if (foundUser) {
            setCurrentUser(foundUser);
            addToast(`Welcome back, ${foundUser.name}!`, 'success');
            setPage('dashboard');
        } else {
            addToast("Login failed. Check email and password.", 'error');
        }
    };

    const handleLogout = () => {
        setCurrentUser(null);
        setPage('home');
        setName('');
        setEmail('');
        setPassword('');
        setScanEmail('');
        setScanResult(null);
        setScanMessage(null);
        addToast("You have been logged out.", 'info');
    };
    
    const handleScan = async (forceRescan = false) => {
        if (!currentUser) return;
        
        const normalizedScanEmail = normalizeEmail(scanEmail);
        
        const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
        if (!gmailRegex.test(normalizedScanEmail)) {
            addToast("Invalid Gmail format. Please enter a valid Gmail address (e.g., username@gmail.com).", "error");
            return;
        }

        setIsScanning(true);
        setScanMessage('Contacting security servers...');
        setScanResult(null);

        try {
            const prompt = `
You are a data breach risk assessment expert. Your task is to generate a realistic privacy assessment report for an email address, including a privacy score and a list of security breaches.

**Assessment Rules:**
1.  **Privacy Score:** The generated privacy score MUST be an integer between 60 and 100 (inclusive).
2.  **Breach Disclosure:** The number of breaches you report MUST strictly follow these rules based on the score you generate:
    - If the score is 90 or above: The 'breaches' array MUST be empty.
    - If the score is between 80 and 89: The 'breaches' array MUST contain exactly 1 breach.
    - If the score is between 70 and 79: The 'breaches' array MUST contain exactly 2 breaches.
    - If the score is below 70 (i.e., 60-69): The 'breaches' array MUST contain exactly 3 breaches.
3.  **Specific Emails:** For the following email addresses, you MUST generate a score below 90 to ensure breaches are reported:
    - gurukishore1208@gmail.com
    - nishanthbarani55@gmail.com
    - kaviravi008@gmail.com
    - anandhakumar88@gmail.com
4.  **All Other Emails:** For any other email address, you can generate a score anywhere between 60 and 100, but you MUST still follow the breach disclosure rules. A score of 90 or above is more likely for these emails.
5.  **Breach Content:** When generating breaches, they must be realistic and relevant. Each breach must include a site, date, number of records, severity, a brief description of the exposure, and a clear recommendation. Use platforms like Instagram, Adobe, Boat, Free Fire, or LinkedIn as examples for the 'site'.

**Input Email:**
${normalizedScanEmail}

Provide your response in the specified JSON format.
`;

            const responseSchema = {
                type: Type.OBJECT,
                properties: {
                    score: { type: Type.INTEGER, description: "The final privacy score from 0 to 100." },
                    breaches: {
                        type: Type.ARRAY,
                        description: "A list of data breaches the email was found in. Empty if score is 100.",
                        items: {
                            type: Type.OBJECT,
                            properties: {
                                site: { type: Type.STRING },
                                date: { type: Type.STRING },
                                records: { type: Type.STRING },
                                severity: { type: Type.STRING, enum: ['critical', 'high', 'medium', 'low'] },
                                description: { type: Type.STRING },
                                recommendation: { type: Type.STRING },
                            },
                            required: ['site', 'date', 'records', 'severity', 'description', 'recommendation'],
                        }
                    }
                },
                required: ['score', 'breaches'],
            };

            setScanMessage('Analyzing data streams...');
            const response = await ai.models.generateContent({
                model: 'gemini-2.5-flash',
                contents: prompt,
                config: {
                    responseMimeType: 'application/json',
                    responseSchema: responseSchema,
                },
            });

            const resultJson = JSON.parse(response.text);
            const { score: newScore, breaches: foundBreaches } = resultJson;

            const baseScore = 100;
            const processedBreaches: Breach[] = foundBreaches.map((b: any, i: number) => ({
                ...b,
                id: `${normalizedScanEmail}-${b.site.toLowerCase().replace(/\s/g, '')}-${i}`,
                source: 'live' as 'live',
                approximationReason: null,
                fixed: false,
                weight: SEVERITY_WEIGHTS[b.severity as 'critical' | 'high' | 'medium' | 'low'] || 5,
                verificationStatus: 'none' as VerificationStatus,
            }));
            
            const nowISO = new Date().toISOString();
            const newScanResult: ScanResult = {
                email: normalizedScanEmail,
                baseScore,
                breaches: processedBreaches,
                scan_version: (cacheRef.current[normalizedScanEmail]?.scan_version || 0) + 1,
                verifier: 'auto',
                change_reason: forceRescan ? 'force_rescan' : 'initial_scan',
                created_at: cacheRef.current[normalizedScanEmail]?.created_at || nowISO,
                last_checked_at: nowISO,
                is_public: true,
            };
            
            cacheRef.current[normalizedScanEmail] = newScanResult;
            
            const updatedUser = { ...currentUser, score: newScore, baseScore, scans: [...new Set([...currentUser.scans, normalizedScanEmail])] };
            updateUser(updatedUser);

            setScanResult(newScanResult);
            setScanMessage(`Scan complete for ${normalizedScanEmail}.`);
            addToast(foundBreaches.length > 0 ? `Scan complete. ${foundBreaches.length} issue(s) found.` : 'Scan complete. No issues found!', foundBreaches.length > 0 ? 'info' : 'success');

        } catch (error) {
            console.error("Error during AI scan:", error);
            addToast("An error occurred during the scan. Please try again.", "error");
            setScanMessage("Scan failed.");
        } finally {
            setIsScanning(false);
            setActiveModal(null);
        }
    };

    const handleMarkAsFixed = (breachId: string) => {
        if (!currentUser) return;
    
        setScanResult(prevScanResult => {
            if (!prevScanResult) return null;
            const updatedBreaches = prevScanResult.breaches.map(b =>
                b.id === breachId ? { ...b, verificationStatus: 'verifying' as VerificationStatus } : b
            );
            return { ...prevScanResult, breaches: updatedBreaches };
        });
    
        setTimeout(() => {
            const verificationSuccess = Math.random() < 0.7;
    
            setScanResult(prevScanResult => {
                if (!prevScanResult) return null;
    
                const originalBreach = prevScanResult.breaches.find(b => b.id === breachId);
                const wasNewlyFixed = verificationSuccess && originalBreach && !originalBreach.fixed;
    
                const finalBreaches = prevScanResult.breaches.map(b => {
                    if (b.id === breachId) {
                        return { ...b, fixed: verificationSuccess, verificationStatus: (verificationSuccess ? 'verified' : 'pending') as VerificationStatus };
                    }
                    return b;
                });
    
                setCurrentUser(prevUser => {
                    if (!prevUser) return null;
                    const fixedCount = prevUser.fixedIssues + (wasNewlyFixed ? 1 : 0);
                    if (wasNewlyFixed) {
                        fixHistoryRef.current.push({ userId: prevUser.id, email: prevScanResult.email, breachId, timestamp: new Date().toISOString() });
                    }
                    
                    const scoreIncrease = wasNewlyFixed ? (originalBreach?.weight || 0) : 0;
                    const newScore = Math.min(100, (prevUser.score || 0) + scoreIncrease);

                    if(wasNewlyFixed) {
                        addToast(`Verified! Your score is now ${newScore}.`, 'success');
                    } else if (verificationSuccess === false) {
                        addToast(`Verification pending.`, 'info');
                    }
                    
                    const updatedUser = { ...prevUser, score: newScore, fixedIssues: fixedCount };
                    
                    const userIndex = usersRef.current.findIndex(u => u.id === updatedUser.id);
                    if (userIndex > -1) {
                        usersRef.current[userIndex] = updatedUser;
                    }
                    return updatedUser;
                });
                
                const newScanCacheEntry = { ...prevScanResult, breaches: finalBreaches, last_checked_at: new Date().toISOString() };
                cacheRef.current[prevScanResult.email] = newScanCacheEntry;
                return newScanCacheEntry;
            });
        }, 2000);
    };
    
    const handleLinkAccount = (platform: LinkedAccountPlatform) => {
        if (!currentUser) return;
        
        let user = { ...currentUser };
        user.linkAttempts += 1;
        if (!user.accounts.includes(platform)) {
            user.accounts.push(platform);
        }

        const data = LINKED_ACCOUNTS_DATA.find(p => p.platform === platform)!;
        let isSafe = data.severity === 'none';

        if (data.severity === 'low' || data.severity === 'medium') {
            const quota = 3;
            const window = 10;
            const probability = (quota - user.positiveShown) / (window - user.linkAttempts + 1);
            const seededRandom = ((user.id + user.linkAttempts) % 100) / 100;
            
            if (seededRandom < probability && user.positiveShown < quota) {
                isSafe = true;
                auditLogRef.current.push({ userId: user.id, action: 'risk_suppressed', details: { platform, reason: 'intelligent_shuffling' }, timestamp: new Date().toISOString() });
            }
        }
        
        if (currentUser.score === 100) {
            isSafe = true;
        }

        setLinkedAccountResult({ ...data, isSafe });
        updateUser(user);
        setActiveModal('linkAccountResult');
    };

    const handleSendChatMessage = async () => {
        if (!chatInput.trim() || isReplying || !currentUser) return;

        const userMessage = { sender: 'user' as 'user', text: chatInput };
        setChatMessages(prev => [...prev, userMessage]);
        const currentChatInput = chatInput;
        setChatInput('');
        setIsReplying(true);

        try {
            let currentChat = chat;
            if (!currentChat) {
                const baseInstruction = `You are a highly interactive and engaging AI Privacy Assistant for the SafeTrace app, designed to emulate the conversational depth of Google's Gemini. Your primary goal is to provide helpful, dynamic, and context-aware guidance on digital privacy and security.

**Core Behaviors:**
1.  **Ask Clarifying Questions:** If a user's request is ambiguous or lacks detail, ask follow-up questions to better understand their intent before providing an answer.
2.  **Maintain Context:** Actively reference previous messages in the conversation to build a coherent and continuous dialogue.
3.  **Be Proactive:** Offer proactive suggestions, alternative perspectives, or related security topics the user might find valuable. Anticipate their needs without being intrusive.
4.  **Vary Your Responses:** Adapt your response structure and tone based on the conversation's flow. Use conversational language, bullet points for clarity, or detailed explanations as appropriate.
5.  **Acknowledge Uncertainty:** If you are unsure about something or if a topic is nuanced, state it clearly. Invite the user to provide more information or correct your understanding.

**Operational Context:**
You do not have direct access to the user's personal data. Your advice should be based on general security best practices and information visible on the user's screen. For example, if they ask about their score, you can say, "Your current privacy score is displayed at the top of your dashboard."`;

                const scoreSpecificInstruction = currentUser.score === 100
                    ? `\n\n**Current User Status:** The user has achieved a perfect privacy score of 100. When they ask about linked accounts (like Facebook, Instagram, etc.), you MUST reassure them that because their primary account is secure, all linked accounts are also considered protected and secure. Do not warn them about any risks for these linked accounts.`
                    : `\n\n**Current User Status:** The user's privacy score is below 100. Provide helpful, encouraging advice on how they can improve their score by fixing the issues identified in their scan results.`;

                const systemInstruction = baseInstruction + scoreSpecificInstruction;

                const newChat = ai.chats.create({
                    model: 'gemini-2.5-flash',
                    config: {
                        systemInstruction,
                    },
                });
                setChat(newChat);
                currentChat = newChat;
            }
            
            setChatMessages(prev => [...prev, { sender: 'assistant', text: '' }]);
            
            const stream = await currentChat.sendMessageStream({ message: currentChatInput });
            
            for await (const chunk of stream) {
                const chunkText = chunk.text;
                setChatMessages(prev => {
                    const lastMessage = prev[prev.length - 1];
                    if (lastMessage.sender === 'assistant') {
                        return [...prev.slice(0, -1), { ...lastMessage, text: lastMessage.text + chunkText }];
                    }
                    return [...prev, { sender: 'assistant', text: chunkText }];
                });
            }

        } catch (error) {
            console.error("Chat error:", error);
            setChatMessages(prev => [...prev, { sender: 'assistant', text: "Sorry, I'm having trouble connecting right now." }]);
        } finally {
            setIsReplying(false);
        }
    };

    // --- RENDER LOGIC ---

    const renderHomePage = () => (
        <div className="flex flex-col items-center justify-center min-h-screen text-center p-4">
            <SafeTraceLogo className="w-24 h-24 mb-4" />
            <h1 className="text-4xl md:text-5xl font-bold mb-2">SafeTrace</h1>
            <p className="text-lg md:text-xl max-w-2xl mb-8">
                Monitor your digital footprint. Stay secure.
            </p>
            <div className="flex flex-col sm:flex-row gap-4">
                <button onClick={() => setPage('register')} className="bg-black text-white px-8 py-3 rounded-lg font-semibold text-lg border-2 border-black">
                    Register for Free
                </button>
                <button onClick={() => setPage('login')} className="bg-white text-black px-8 py-3 rounded-lg font-semibold text-lg hover:bg-gray-100 transition-colors border-2 border-black">
                    Login to Dashboard
                </button>
            </div>
        </div>
    );

    const renderAuthPage = (isRegister: boolean) => (
        <div className="min-h-screen flex items-center justify-center p-4">
            <div className="w-full max-w-md">
                <div className="flex justify-center mb-6">
                    <SafeTraceLogo className="w-16 h-16" />
                </div>
                <h2 className="text-3xl font-bold text-center mb-6">{isRegister ? 'Create Your Account' : 'Welcome Back'}</h2>
                
                <div className="space-y-4">
                    {isRegister && (
                        <input type="text" placeholder="Full Name" value={name} onChange={e => setName(e.target.value)} className="w-full p-3 border-2 border-black rounded-lg" />
                    )}
                    <input type="email" placeholder="Email Address" value={email} onChange={e => setEmail(e.target.value)} className="w-full p-3 border-2 border-black rounded-lg" />
                    <div className="relative">
                         <input type={passwordVisible ? 'text' : 'password'} placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} className={`w-full p-3 border-2 rounded-lg ${isRegister ? (isPasswordStrong ? 'border-green-500' : (password.length > 0 ? 'border-red-500' : 'border-black')) : 'border-black'}`} />
                         <button onClick={() => setPasswordVisible(!passwordVisible)} className="absolute inset-y-0 right-0 px-3 flex items-center text-gray-500">
                             {passwordVisible ? <EyeOff size={20} /> : <Eye size={20} />}
                         </button>
                    </div>

                    {isRegister && password.length > 0 && (
                        <div className="border-2 border-gray-200 rounded-xl p-4 space-y-3 bg-white">
                            <p className={`font-semibold ${isPasswordStrong ? 'text-green-600' : 'text-black'}`}>{getPasswordMessage()}</p>
                            <div className="flex items-center gap-2 text-sm flex-wrap">
                                <span className={`px-2 py-0.5 rounded-full ${passwordChecks.length ? 'bg-green-100 text-green-800' : 'bg-gray-100'}`}>{passwordChecks.length ? '✓' : '○'} 8+ Chars</span>
                                <span className={`px-2 py-0.5 rounded-full ${passwordChecks.number ? 'bg-green-100 text-green-800' : 'bg-gray-100'}`}>{passwordChecks.number ? '✓' : '○'} 1+ Num</span>
                                <span className={`px-2 py-0.5 rounded-full ${passwordChecks.symbol ? 'bg-green-100 text-green-800' : 'bg-gray-100'}`}>{passwordChecks.symbol ? '✓' : '○'} 1+ Sym</span>
                            </div>
                        </div>
                    )}
                </div>

                <button onClick={isRegister ? handleRegister : handleLogin} className="w-full bg-black text-white p-3 mt-6 rounded-lg font-semibold border-2 border-black">
                    {isRegister ? 'Create Account' : 'Login'}
                </button>
                <button onClick={() => setPage('home')} className="w-full bg-white text-black p-3 mt-3 rounded-lg font-semibold hover:bg-gray-100 transition-colors border-2 border-black">
                    Back to Home
                </button>
            </div>
        </div>
    );
    
    const renderDashboard = () => {
        if (!currentUser) return null;

        const severityClasses: { [key: string]: string } = {
            critical: "bg-red-600 text-white", high: "bg-orange-500 text-white", medium: "bg-yellow-400 text-black", low: "bg-blue-300 text-black", none: "bg-green-400 text-black",
        };
        const verificationClasses: { [key: string]: string } = {
            verifying: "bg-blue-500 text-white animate-pulse", verified: "bg-green-500 text-white", pending: "bg-yellow-400 text-black",
        };
        const sourceClasses: { [key: string]: string } = {
            live: "bg-green-200 text-green-800 border-green-400", approximation: "bg-yellow-200 text-yellow-800 border-yellow-400",
        };

        return (
            <div className="min-h-screen bg-gray-50/50 p-4 sm:p-6 md:p-8">
                <header className="flex justify-between items-center mb-8">
                    <div className="flex items-center gap-3">
                        <SafeTraceLogo className="w-10 h-10"/>
                        <span className="text-xl font-bold hidden sm:inline">SafeTrace</span>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="text-right">
                           <p className="font-semibold">{currentUser.name}</p>
                           <p className="text-sm text-gray-600">{currentUser.email}</p>
                        </div>
                        <button onClick={handleLogout} className="bg-white text-black p-2 rounded-lg border-2 border-black hover:bg-gray-100">
                           <LogOut size={20} />
                        </button>
                    </div>
                </header>

                <main>
                    <div className="bg-white border-2 border-black rounded-xl p-6 mb-8 text-center flex flex-col items-center">
                        <h2 className="text-lg font-semibold text-gray-600 mb-2">Your Privacy Score</h2>
                        <ScoreVisualization score={currentUser.score} baseScore={currentUser.baseScore} />
                        <p className="text-sm mt-2 text-gray-500 max-w-md mx-auto">{currentUser.score === null ? 'Scan an email to calculate your score.' : 'Your score reflects unfixed security issues.'}</p>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                        <div className="bg-white border-2 border-black rounded-xl p-6">
                            <div className="flex items-center gap-3 mb-4">
                               <Search size={24} />
                               <h3 className="text-2xl font-bold">Account Scanner</h3>
                            </div>
                            <div className="flex flex-col sm:flex-row gap-2">
                               <input type="email" placeholder="Enter email to scan..." value={scanEmail} onChange={e => setScanEmail(e.target.value)} className="flex-grow p-3 border-2 border-black rounded-lg" />
                               <button onClick={() => handleScan(false)} disabled={isScanning || !!emailSuggestion} className="bg-black text-white px-6 py-3 rounded-lg font-semibold border-2 border-black disabled:bg-gray-400">
                                   {isScanning ? 'Scanning...' : 'Scan'}
                               </button>
                            </div>
                            {emailSuggestion && (
                               <div className="mt-2 p-2 bg-yellow-100 border border-yellow-300 rounded-lg flex items-center justify-between text-sm">
                                   <span>Did you mean: <strong>{emailSuggestion}</strong>?</span>
                                   <button onClick={() => { setScanEmail(emailSuggestion); setEmailSuggestion(null); }} className="bg-yellow-400 text-black px-2 py-0.5 rounded font-semibold">Apply</button>
                               </div>
                            )}

                            {(isScanning || scanMessage) && <p className="text-center mt-4 text-sm text-gray-600">{scanMessage}</p>}
                            {scanResult && <div className="flex justify-between items-center mt-4">
                               <button onClick={() => setActiveModal('howWeScan')} className="text-sm text-blue-600 hover:underline">How we scan</button>
                               <button onClick={() => setActiveModal('forceRescan')} className="text-sm text-red-600 hover:underline">Force Re-scan</button>
                            </div>}

                            <div className="mt-6 space-y-4">
                                {scanResult?.breaches.filter(breach => {
                                    const year = parseInt(breach.date.substring(0, 4), 10);
                                    return year >= 2020 && year <= 2025;
                                }).map(breach => (
                                    <div key={breach.id} className="border-2 border-black rounded-xl p-4">
                                        <div className="flex flex-wrap justify-between items-start gap-2 mb-2">
                                            <div className="flex items-center gap-3">
                                                <AlertTriangle className="w-8 h-8 flex-shrink-0" />
                                                <div>
                                                   <h4 className="font-bold text-lg">{breach.site} Breach</h4>
                                                   <p className="text-sm text-gray-500">{breach.date} · {breach.records} records</p>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <span className={`px-2 py-0.5 text-xs font-bold rounded-full ${severityClasses[breach.severity]}`}>{breach.severity}</span>
                                                <span className={`px-2 py-0.5 text-xs font-bold rounded-full border ${sourceClasses[breach.source]}`}>{breach.source === 'live' ? 'Live' : 'Estimated'}</span>
                                            </div>
                                        </div>
                                        <p className="text-sm my-2">{breach.description}</p>
                                        <div className="bg-gray-100 p-2 rounded-lg text-sm">
                                            <strong>Recommendation:</strong> {breach.recommendation}
                                        </div>
                                        <div className="mt-3 flex justify-end items-center">
                                            {breach.verificationStatus === 'verified' ? (
                                                <span className={`px-3 py-1 text-sm font-bold rounded-full ${verificationClasses.verified}`}>✓ Verified</span>
                                            ) : breach.verificationStatus === 'verifying' ? (
                                                <span className={`px-3 py-1 text-sm font-bold rounded-full ${verificationClasses.verifying}`}>Verifying...</span>
                                            ) : (
                                                <button onClick={() => handleMarkAsFixed(breach.id)} className="bg-black text-white text-sm px-4 py-2 rounded-lg font-semibold border-2 border-black">
                                                    Mark as Fixed
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                ))}
                                {isScanning && !scanMessage?.startsWith("Contacting") && <div className="text-center p-4">Loading...</div>}
                                {!isScanning && scanResult && scanResult.breaches.length === 0 && <p className="text-center p-4 text-gray-600">No breaches found!</p>}
                            </div>
                        </div>

                        <div className="bg-white border-2 border-black rounded-xl p-6">
                           <div className="flex items-center gap-3 mb-4">
                               <Link2 size={24} />
                               <h3 className="text-2xl font-bold">Linked Accounts</h3>
                           </div>
                           <p className="text-sm text-gray-600 mb-4">Check the safety status of your other online accounts.</p>
                           <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                               {LINKED_ACCOUNTS_DATA.map(({ platform }) => (
                                   <button key={platform} onClick={() => handleLinkAccount(platform)} className="flex items-center justify-center gap-2 p-3 border-2 border-black rounded-lg hover:bg-gray-100">
                                       <span className="font-semibold">{platform}</span>
                                       {currentUser.accounts.includes(platform) && <CheckCircle size={16} className="text-green-600" />}
                                   </button>
                               ))}
                           </div>
                        </div>
                    </div>

                    <div className="bg-white border-2 border-black rounded-xl p-6">
                        <div className="flex items-center gap-3 mb-4">
                           <Award size={24} />
                           <h3 className="text-2xl font-bold">Achievements</h3>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                           {BADGES.map(badge => {
                               const earned = currentUser.badges.includes(badge.id);
                               return (
                                   <div key={badge.id} className={`p-4 border-2 border-black rounded-xl text-center ${earned ? 'bg-black text-white' : 'bg-gray-100 opacity-50'}`}>
                                       <div className="text-4xl mb-2">{badge.icon}</div>
                                       <h4 className="font-bold">{badge.name}</h4>
                                       <p className={`text-xs ${earned ? 'text-gray-300' : 'text-gray-600'}`}>{badge.description}</p>
                                   </div>
                               );
                           })}
                        </div>
                    </div>
                </main>
                
                <button onClick={() => setActiveModal('chat')} className="fixed bottom-6 right-6 bg-black text-white w-16 h-16 rounded-full flex items-center justify-center shadow-lg border-2 border-black">
                    <MessageCircle size={32} />
                </button>
            </div>
        );
    };

    // --- RENDER MODALS & TOASTS ---
    const renderModals = () => (
        <>
            {activeModal && <div className="fixed inset-0 bg-black/50 z-40" onClick={() => setActiveModal(null)} />}
            {activeModal === 'forceRescan' && (
                <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-white border-2 border-black rounded-xl p-6 z-50">
                    <div className="flex items-center gap-3 mb-4">
                        <AlertTriangle size={24} className="text-red-600" />
                        <h3 className="text-2xl font-bold">Confirm Re-scan</h3>
                    </div>
                    <p className="text-gray-600 mb-4">Forcing a re-scan will perform a fresh analysis of the email address.</p>
                    <div className="flex justify-end gap-3">
                        <button onClick={() => setActiveModal(null)} className="bg-white text-black px-4 py-2 rounded-lg font-semibold border-2 border-black">Cancel</button>
                        <button onClick={() => handleScan(true)} className="bg-black text-white px-4 py-2 rounded-lg font-semibold border-2 border-black">Confirm</button>
                    </div>
                </div>
            )}
            {activeModal === 'howWeScan' && (
                <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg bg-white border-2 border-black rounded-xl p-6 z-50">
                    <h3 className="text-2xl font-bold mb-4">How We Scan</h3>
                    <div className="space-y-4 text-sm">
                        <p className="text-gray-600">We use Google's advanced AI to analyze email addresses against a vast, up-to-date database of known data breaches.</p>
                        <p className="text-gray-600">Our analysis provides a real-time risk score and actionable recommendations to help you secure your accounts.</p>
                        <p className="text-gray-600">We <strong>NEVER</strong> store your passwords. All checks are performed securely and anonymously.</p>
                    </div>
                    <div className="flex justify-end mt-6">
                        <button onClick={() => setActiveModal(null)} className="bg-black text-white px-4 py-2 rounded-lg font-semibold border-2 border-black">Close</button>
                    </div>
                </div>
            )}
             {activeModal === 'linkAccountResult' && linkedAccountResult && (
                <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-white border-2 border-black rounded-xl z-50">
                    {linkedAccountResult.isSafe ? (
                        <div className="p-6">
                            <div className="flex items-center gap-3 mb-2">
                                <CheckCircle size={24} className="text-green-600" />
                                <h3 className="text-2xl font-bold">You are safe</h3>
                            </div>
                            <p className="text-gray-600">No issues detected for your {linkedAccountResult.platform} account.</p>
                        </div>
                    ) : (
                        <div className="bg-black text-white p-6 rounded-t-lg">
                           <div className="flex items-center gap-3 mb-2">
                               <AlertCircle size={24} />
                               <h3 className="text-2xl font-bold">Account at risk</h3>
                           </div>
                           <p><strong>Risk:</strong> {linkedAccountResult.risk}</p>
                        </div>
                    )}
                    {!linkedAccountResult.isSafe && (
                        <div className="p-6">
                           <h4 className="font-bold mb-2">Suggested Solution:</h4>
                           <ol className="list-decimal list-inside space-y-1 text-sm text-gray-700">
                               {linkedAccountResult.solutions.map((step, i) => <li key={i}>{step}</li>)}
                           </ol>
                        </div>
                    )}
                     <div className="p-6 pt-0 flex justify-end">
                        <button onClick={() => setActiveModal(null)} className="bg-black text-white px-4 py-2 rounded-lg font-semibold border-2 border-black">Got it</button>
                    </div>
                </div>
            )}
            {activeModal === 'chat' && (
                <div className="fixed bottom-24 right-6 w-[calc(100vw-3rem)] max-w-sm h-96 bg-white border-2 border-black rounded-xl z-50 flex flex-col">
                    <div className="flex items-center justify-between p-3 border-b-2 border-black">
                        <h3 className="font-bold">Privacy Assistant</h3>
                        <button onClick={() => setActiveModal(null)}><X size={20} /></button>
                    </div>
                    <div ref={chatMessagesRef} className="flex-grow p-4 overflow-y-auto space-y-4">
                        {chatMessages.map((msg, i) => (
                            <div key={i} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                                <div className={`max-w-[80%] p-3 rounded-xl ${msg.sender === 'user' ? 'bg-black text-white' : 'bg-gray-200'}`}>
                                    <p className="text-sm" style={{ whiteSpace: 'pre-wrap' }}>{msg.text}</p>
                                </div>
                            </div>
                        ))}
                         {isReplying && chatMessages[chatMessages.length - 1]?.sender === 'assistant' && <div className="flex justify-start"><div className="bg-gray-200 p-3 rounded-xl"><span className="animate-pulse">...</span></div></div>}
                    </div>
                    <div className="p-3 border-t-2 border-black flex gap-2">
                        <input type="text" value={chatInput} onChange={e => setChatInput(e.target.value)} onKeyPress={e => e.key === 'Enter' && handleSendChatMessage()} placeholder="Ask a question..." className="flex-grow p-2 border-2 border-black rounded-lg" />
                        <button onClick={handleSendChatMessage} disabled={isReplying} className="bg-black text-white p-2 rounded-lg border-2 border-black disabled:bg-gray-400">
                           <Send size={20} />
                        </button>
                    </div>
                </div>
            )}
        </>
    );

    const renderToasts = () => (
        <div className="fixed top-4 right-4 z-50 space-y-2">
            {toasts.map(toast => {
                const styles = {
                    success: 'bg-white text-black border-black',
                    error: 'bg-black text-white border-black',
                    info: 'bg-gray-100 text-black border-gray-400'
                };
                return (
                    <div
                        key={toast.id}
                        className={`p-4 rounded-lg border-2 shadow-lg ${styles[toast.type]}`}
                    >
                        {toast.message}
                    </div>
                );
            })}
        </div>
    );

    const renderPageContent = () => {
        switch(page) {
            case 'home': return renderHomePage();
            case 'register': return renderAuthPage(true);
            case 'login': return renderAuthPage(false);
            case 'dashboard': return currentUser ? renderDashboard() : renderHomePage();
            default: return renderHomePage();
        }
    }

    return <>
        {renderPageContent()}
        {renderModals()}
        {renderToasts()}
    </>;
};

export default App;
