import React from 'react';

// Banner component to show when spidering is limited to a specific domain
export default function SpiderDomainBanner({ domain, onClear }) {
  if (!domain) return null;

  return (
    <div className="spider-domain-banner">
      <div className="banner-content">
        <span className="banner-icon">🕸️</span>
        <span className="banner-message">
          Spidering limited to domain: <strong>{domain}</strong>
        </span>
        {onClear && (
          <button 
            className="banner-clear-btn" 
            onClick={onClear} 
            title="Clear domain filter"
          >
            Clear Filter
          </button>
        )}
      </div>
    </div>
  );
}