import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import './style.css';

const rootElement = document.getElementById('root') || document.createElement('div');
if (!rootElement.id) document.body.appendChild(rootElement);

createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);