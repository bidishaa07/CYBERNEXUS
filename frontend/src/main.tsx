import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import Home from './App';
import ContactIntelligencePanel from './components/ContactIntelligencePanel';
import AuthPanel from './components/AuthPanel';
import AdminReviewPanel from './components/AdminReviewPanel';
import MLModelManagementPanel from './components/MLModelManagementPanel';
import '../app/globals.css';

function AppFooter() {
  return <footer className="app-footer"><div className="app-footer-grid"><div className="app-footer-intro"><div className="app-footer-mark"><ShieldIcon /></div><div><h2>Stay ahead of digital risk.</h2><p>Contact intelligence, administrator review, model operations, and authenticated development tools remain available below the main workspace.</p></div></div><div className="app-footer-links"><span>WORKSPACE</span><a href="#contact-intelligence">Contact intelligence</a><a href="#admin-review">Administrator review</a><a href="#ml-management">ML model management</a><a href="#auth-session">Session and identity</a></div><div className="app-footer-links"><span>TRUST</span><a href="#contact-intelligence">Phone reputation</a><a href="#contact-intelligence">SPF / DKIM / DMARC</a><a href="#ml-management">Model lifecycle</a><a href="#auth-session">Access controls</a></div></div><div id="contact-intelligence"><ContactIntelligencePanel /></div><div id="admin-review"><AdminReviewPanel /></div><div id="ml-management"><MLModelManagementPanel /></div><div id="auth-session"><AuthPanel /></div><div className="app-footer-bottom"><span>CYBERNEXUS / TRUST INTELLIGENCE</span><span>Evidence-backed analysis · Unknown is never treated as safe</span></div></footer>;
}

function ShieldIcon() { return <span className="footer-shield">◆</span>; }

createRoot(document.getElementById('root')!).render(<StrictMode><Home /><AppFooter /></StrictMode>);
