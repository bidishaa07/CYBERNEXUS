import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import Home from './App';
import EmailSecurityPanel from './components/EmailSecurityPanel';
import '../app/globals.css';

createRoot(document.getElementById('root')!).render(<StrictMode><Home /><EmailSecurityPanel /></StrictMode>);
