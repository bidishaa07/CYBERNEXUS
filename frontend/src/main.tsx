import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import Home from './App';
import ContactIntelligencePanel from './components/ContactIntelligencePanel';
import AuthPanel from './components/AuthPanel';
import AdminReviewPanel from './components/AdminReviewPanel';
import MLModelManagementPanel from './components/MLModelManagementPanel';
import '../app/globals.css';

createRoot(document.getElementById('root')!).render(<StrictMode><Home /><ContactIntelligencePanel /><AdminReviewPanel /><MLModelManagementPanel /><AuthPanel /></StrictMode>);
