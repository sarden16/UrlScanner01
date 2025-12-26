import React, { useEffect } from 'react';
import UrlScanner from './UrlScanner.jsx';
import './style.css';

function App() {
  useEffect(() => {
    console.log('App mounted');
  }, []);

  return (
    <div className="page-wrapper">
      <div className="App">
        <UrlScanner />
      </div>

      {/* Temporary debug badge to confirm render — remove when verified */}
      <div style={{position: 'fixed', right: 12, bottom: 12, background: '#0f172a', color: '#fff', padding: '6px 10px', borderRadius: 8, fontSize: 12, opacity: 0.9}}>
        Dev: App mounted
      </div>
    </div>
  );
}

export default App;