import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import Home from './App';
import EmailSecurityPanel from './components/EmailSecurityPanel';
import ContactIntelligencePanel from './components/ContactIntelligencePanel';
import MessageHistoryPanel from './components/MessageHistoryPanel';
import AuthPanel from './components/AuthPanel';
import AdminReviewPanel from './components/AdminReviewPanel';
import MessageReportsPanel from './components/MessageReportsPanel';
import '../app/globals.css';

createRoot(document.getElementById('root')!).render(<StrictMode><Home /><EmailSecurityPanel /><ContactIntelligencePanel /><MessageHistoryPanel /><MessageReportsPanel /><AdminReviewPanel /><AuthPanel /></StrictMode>);
