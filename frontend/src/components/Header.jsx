import React, { useState, useEffect } from 'react'
import { getSpiderStatus, stopSpider, spiderFromUrl } from '../api.js'

export default function Header({ search, onSearch, methodFilter, setMethodFilter, statusFilter, setStatusFilter, onClearFilters, onPurge, onOpenOptions, observedMethods = [], observedStatuses = [] }) {
  const [spiderEnabled, setSpiderEnabled] = useState(true)
  const [isToggling, setIsToggling] = useState(false)
  
  // Get initial spider status only once, don't poll
  useEffect(() => {
    const fetchSpiderStatus = async () => {
      try {
        const status = await getSpiderStatus()
        setSpiderEnabled(status.spidering)
      } catch (e) {
        console.error('Failed to get spider status:', e)
      }
    }
    
    fetchSpiderStatus()
    // No polling to prevent automatic resume
  }, [])
  const methods = observedMethods
  const statuses = observedStatuses
  
  const toggleSpider = async () => {
    setIsToggling(true)
    try {
      if (spiderEnabled) {
        // Stop the spider
        await stopSpider()
        setSpiderEnabled(false)
      } else {
        // Start the spider with a dummy URL to reactivate
        // The URL doesn't matter as we just want to enable the system
        await spiderFromUrl('https://localhost.com')
        setSpiderEnabled(true)
      }
    } catch (e) {
      console.error('Failed to toggle spider:', e)
      alert('Failed to toggle spider operation')
    } finally {
      setIsToggling(false)
    }
  }

  return (
    <header className="header">
      <div className="logo">🔎 SnapShot</div>
      <div className="search">
        <input
          type="text"
          placeholder="Search URL, method, status, host, path..."
          value={search}
          onChange={e => onSearch(e.target.value)}
        />
      </div>
      <div className="filters">
        <select value={methodFilter} onChange={e => setMethodFilter(e.target.value)}>
          <option value="">All Methods</option>
          {methods.map(m => <option key={m} value={m}>{m}</option>)}
        </select>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">All Statuses</option>
          {statuses.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      <div className="actions">
        <button className="btn" onClick={onOpenOptions}>Options</button>
        <button className="btn" style={{ background: '#374151' }} onClick={onClearFilters}>Clear Filters</button>
        <button 
          className="btn" 
          style={{ 
            background: spiderEnabled ? '#b91c1c' : '#22c55e', 
            position: 'relative',
            minWidth: '100px'
          }} 
          onClick={toggleSpider}
          disabled={isToggling}
        >
          {isToggling ? 'Toggling...' : spiderEnabled ? 'Stop Spider' : 'Start Spider'}
          {isToggling && (
            <span style={{ 
              position: 'absolute', 
              top: '50%', 
              left: '50%', 
              transform: 'translate(-50%, -50%)',
              width: '12px', 
              height: '12px', 
              borderRadius: '50%', 
              border: '2px solid #fff', 
              borderTopColor: 'transparent',
              animation: 'spin 1s linear infinite'
            }}></span>
          )}
        </button>
        <button className="btn" style={{ background: '#b91c1c' }} onClick={onPurge}>Purge Data</button>
      </div>
    </header>
  )
}
