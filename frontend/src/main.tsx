import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import Home from './App';
import EmailSecurityPanel from './components/EmailSecurityPanel';
import ContactIntelligencePanel from './components/ContactIntelligencePanel';
import MessageHistoryPanel from './components/MessageHistoryPanel';
import '../app/globals.css';

createRoot(document.getElementById('root')!).render(<StrictMode><Home /><EmailSecurityPanel /><ContactIntelligencePanel /><MessageHistoryPanel /></StrictMode>);
