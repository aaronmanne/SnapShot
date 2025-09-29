import React, { useState, useEffect } from 'react';

export default function ScanProgressPanel() {
  const [scanning, setScanning] = useState([]);
  const [loading, setLoading] = useState(true);
  
  // Fetch scan progress data
  useEffect(() => {
    async function fetchScanProgress() {
      try {
        setLoading(true);
        const response = await fetch('/api/sast/scanning');
        const data = await response.json();
        if (data && Array.isArray(data.items)) {
          setScanning(data.items);
        } else {
          setScanning([]);
        }
      } catch (error) {
        console.error('Error fetching scan progress:', error);
        setScanning([]);
      } finally {
        setLoading(false);
      }
    }
    
    // Initial fetch
    fetchScanProgress();
    
    // Set up polling interval
    const interval = setInterval(fetchScanProgress, 2000);
    
    // Clean up on component unmount
    return () => clearInterval(interval);
  }, []);
  
  // Format timestamp
  const formatTime = (timestamp) => {
    if (!timestamp) return '';
    try {
      return new Date(timestamp).toLocaleTimeString();
    } catch {
      return '';
    }
  };
  
  // Style based on scan status
  const getStatusClass = (status) => {
    switch (status) {
      case 'analyzing':
        return 'status-analyzing';
      case 'completed':
        return 'status-completed';
      case 'error':
        return 'status-error';
      default:
        return '';
    }
  };
  
  // Truncate URL for display
  const truncateUrl = (url, maxLength = 60) => {
    if (!url || url.length <= maxLength) return url;
    return url.substring(0, maxLength) + '...';
  };
  
  // If there's nothing scanning, don't show the panel
  // if (!loading && scanning.length === 0) {
  //   return null;
  // }
  
  return (
    <div className="card">
      <div className="card-title">SAST Scanning Progress {loading ? '(loading...)' : '' || 'Fetching...' }</div>
      <div className="card-body">
        {scanning.length > 0 ? (
          <div className="scan-progress-list">
            <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {scanning.map((scan, index) => (
                    <tr key={index} className={getStatusClass(scan.status)}>
                      <td title={scan.url}>{truncateUrl(scan.url)}</td>
                      <td>{scan.type || 'Unknown'}</td>
                      <td>
                        <span className={`scan-status scan-status-${scan.status}`}>
                          {scan.status === 'analyzing' && '⚡ Analyzing'}
                          {scan.status === 'completed' && '✓ Completed'}
                          {scan.status === 'error' && '⚠ Error'}
                          {!scan.status && 'Pending'}
                        </span>
                      </td>
                      <td>{formatTime(scan.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div style={{ opacity: 0.7 }}>No active scanning in progress.</div>
        )}
      </div>
    </div>
  );
}