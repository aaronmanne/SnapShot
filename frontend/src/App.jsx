import React, {useEffect, useMemo, useState} from 'react'
import {io} from 'socket.io-client'
import Header from './components/Header.jsx'
import DataTable from './components/DataTable.jsx'
import AnalyticsPanels from './components/AnalyticsPanels.jsx'
import FuzzOptionsPanel from './components/FuzzOptionsPanel.jsx'
import RequestDetails from './components/RequestDetails.jsx'
import VulnerabilitiesPanel from './components/VulnerabilitiesPanel.jsx'
import OptionsPanel from './components/OptionsPanel.jsx'
import SastDiscoveriesPanel from './components/SastDiscoveriesPanel.jsx'
import ScanProgressPanel from './components/ScanProgressPanel.jsx'
import SpiderDomainBanner from './components/SpiderDomainBanner.jsx'
import {
    fetchAnalytics,
    fetchRequests,
    generateFuzz,
    purgeAll,
    exportProject,
    importProject,
    getOptions,
    setOptions
} from './api.js'

const socket = io('/', {path: '/socket.io'})

export default function App() {
    const [requests, setRequests] = useState([])
    const [analytics, setAnalytics] = useState(null)
    const [search, setSearch] = useState('')
    const [methodFilter, setMethodFilter] = useState('')
    const [statusFilter, setStatusFilter] = useState('')
    const [selectedHost, setSelectedHost] = useState('')
    const [selectedTech, setSelectedTech] = useState('')
    const [perPage, setPerPage] = useState(500)
    const [sortKey, setSortKey] = useState('timestamp')
    const [sortDir, setSortDir] = useState('desc')
    const [loading, setLoading] = useState(true)
    const [selectedRequest, setSelectedRequest] = useState(null)
    const [fuzzOptions, setFuzzOptions] = useState({xss: true, sqli: true})
    const [showOptions, setShowOptions] = useState(false)
    const [llmEnabled, setLlmEnabled] = useState(true)
    const [aggressiveFP, setAggressiveFP] = useState(false)
    const [llmApiType, setLlmApiType] = useState('LMStudio')
    const [spiderOptions, setSpiderOptions] = useState({
        spiderDepth: 2,
        spiderMaxPerSeed: 20,
        spiderSameOriginOnly: false,
        spiderTimeoutMs: 8000,
        spiderRequestsPerSec: 1,
        spiderRespectRobots: true,
    })
    const [spiderEnabledAtStart, setSpiderEnabledAtStart] = useState(false)
    // New state for spidering domain filter
    const [spiderDomainFilter, setSpiderDomainFilter] = useState('')
    const [spiderActive, setSpiderActive] = useState(false)

    // Initial load
    useEffect(() => {
        let mounted = true

        async function load() {
            try {
                setLoading(true)
                const [{items}, a, options] = await Promise.all([
                    fetchRequests(),
                    fetchAnalytics(),
                    getOptions() // Fetch backend options including LLM API type
                ])
                if (!mounted) return
                setRequests(items)
                setAnalytics(a)
                // Set options from backend
                if (options) {
                    if (typeof options.llmEnabled === 'boolean') setLlmEnabled(options.llmEnabled)
                    if (typeof options.aggressiveFingerprinting === 'boolean') setAggressiveFP(options.aggressiveFingerprinting)
                    if (options.llmApiType) setLlmApiType(options.llmApiType)
                    // Spider options
                    setSpiderOptions({
                        spiderDepth: Number(options.spiderDepth ?? 2),
                        spiderMaxPerSeed: Number(options.spiderMaxPerSeed ?? 20),
                        spiderSameOriginOnly: !!options.spiderSameOriginOnly,
                        spiderTimeoutMs: Number(options.spiderTimeoutMs ?? 8000),
                        spiderRequestsPerSec: Number(options.spiderRequestsPerSec ?? 1),
                        spiderRespectRobots: !!options.spiderRespectRobots,
                    })
                    setSpiderEnabledAtStart(!!options.spiderEnabledAtStart)
                }
            } catch (e) {
                console.error(e)
            } finally {
                setLoading(false)
            }
        }

        load()
        return () => {
            mounted = false
        }
    }, [])

    // Realtime updates via socket
    useEffect(() => {
        function onReq(r) {
            setRequests(prev => [r, ...prev].slice(0, 5000))

            // Check if this is a spider request
            if (r.spider === true) {
                setSpiderActive(true)
            }
        }

        function onPurged() {
            setRequests([])
            setAnalytics(null)
            setSpiderDomainFilter('') // Clear domain filter on purge
        }

        async function onImported() {
            try {
                const [{items}, a] = await Promise.all([fetchRequests(), fetchAnalytics()])
                setRequests(items)
                setAnalytics(a)
            } catch (e) {
                // ignore
            }
        }

        function onSpiderStatus(status) {
            setSpiderActive(status?.spidering || false)
            if (!status?.spidering) {
                // If spider is stopped, clear domain filter
                setSpiderDomainFilter('')
            }
        }

        socket.on('request', onReq)
        socket.on('purged', onPurged)
        socket.on('imported', onImported)
        socket.on('spiderStatus', onSpiderStatus)

        // Fetch initial spider status
        fetch('/api/spider/status')
            .then(res => res.json())
            .then(status => {
                setSpiderActive(status?.spidering || false)
            })
            .catch(() => {
                setSpiderActive(false)
            })

        return () => {
            socket.off('request', onReq)
            socket.off('purged', onPurged)
            socket.off('imported', onImported)
            socket.off('spiderStatus', onSpiderStatus)
        }
    }, [])

    // Refresh analytics every 10s
    useEffect(() => {
        const id = setInterval(async () => {
            try {
                const a = await fetchAnalytics()
                setAnalytics(a)
            } catch (e) {
                // ignore
            }
        }, 10000)
        return () => clearInterval(id)
    }, [])

    useEffect(() => {
        const firstTab = document.querySelector('.tablinks');
        if (firstTab) {
            firstTab.click();
        }
    }, []);

    const filtered = useMemo(() => {
        let data = [...requests]
        const q = search.trim().toLowerCase()
        if (q) {
            data = data.filter(r =>
                r.url.toLowerCase().includes(q) ||
                r.method.toLowerCase().includes(q) ||
                String(r.status).includes(q) ||
                (r.host || '').toLowerCase().includes(q) ||
                (r.path || '').toLowerCase().includes(q)
            )
        }
        if (selectedHost) data = data.filter(r => r.host === selectedHost)
        if (selectedTech) data = data.filter(r => (r.tech || []).includes(selectedTech))
        if (methodFilter) data = data.filter(r => r.method === methodFilter)
        if (statusFilter) data = data.filter(r => String(r.status) === String(statusFilter))

        data.sort((a, b) => {
            const dir = sortDir === 'asc' ? 1 : -1
            const av = a[sortKey]
            const bv = b[sortKey]
            if (sortKey === 'timestamp') {
                return (new Date(av) - new Date(bv)) * dir
            }
            return String(av).localeCompare(String(bv)) * dir
        })

        return data
    }, [requests, search, methodFilter, statusFilter, selectedHost, selectedTech, sortKey, sortDir])

    const onSort = (key) => {
        if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
        else {
            setSortKey(key);
            setSortDir('desc')
        }
    }

    // Handler for selecting host from Unique Hostnames with spider domain filtering
    const onSelectHostWithSpider = (host) => {
        setSelectedHost(host)

        // If spider is active and a host is selected, set domain filter
        if (host && spiderActive) {
            setSpiderDomainFilter(host)

            // Send API request to update spider config with domain filter
            fetch('/api/spider/from', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    url: window.location.origin,  // Use current page as seed
                    domainFilter: host
                })
            }).catch(err => {
                console.error('Failed to update spider domain filter:', err)
            })
        }
    }

    // Clear the spider domain filter
    const clearSpiderDomainFilter = () => {
        setSpiderDomainFilter('')
    }

    const onFuzz = async () => {
        try {
            const blob = await generateFuzz({
                q: search || undefined,
                method: methodFilter || undefined,
                status: statusFilter || undefined,
                host: selectedHost || undefined,
                fuzzOptions: fuzzOptions || undefined,
            })
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = `snapshot-fuzz-${Date.now()}.txt`
            document.body.appendChild(a)
            a.click()
            a.remove()
            URL.revokeObjectURL(url)
        } catch (e) {
            alert('Failed to generate fuzz file')
        }
    }

    const onClearFilters = () => {
        setSearch('')
        setMethodFilter('')
        setStatusFilter('')
        setSelectedHost('')
        setSelectedTech('')
    }

    const onPurge = async () => {
        try {
            await purgeAll()
            setRequests([])
            setAnalytics(null)
            setSelectedRequest(null)
        } catch (e) {
            alert('Failed to purge data')
        }
    }

    const onSaveProject = async () => {
        try {
            const data = await exportProject()
            const snapshot = {
                ...data,
                filters: {
                    search,
                    methodFilter,
                    statusFilter,
                    selectedHost,
                    selectedTech,
                    sortKey,
                    sortDir,
                    perPage,
                }
            }
            const json = JSON.stringify(snapshot, null, 2)
            const blob = new Blob([json], {type: 'application/json'})
            const url = URL.createObjectURL(blob)
            const a = document.createElement('a')
            a.href = url
            a.download = `snapshot-project-${Date.now()}.json`
            document.body.appendChild(a)
            a.click()
            a.remove()
            URL.revokeObjectURL(url)
        } catch (e) {
            console.error(e)
            alert('Failed to save project')
        }
    }

    const onLoadProject = async () => {
        const input = document.createElement('input')
        input.type = 'file'
        input.accept = 'application/json,.json'
        input.onchange = async (e) => {
            const file = e.target.files && e.target.files[0]
            if (!file) return
            try {
                const text = await file.text()
                const parsed = JSON.parse(text)
                if (parsed && parsed.filters) {
                    const f = parsed.filters || {}
                    setSearch(String(f.search || ''))
                    setMethodFilter(String(f.methodFilter || ''))
                    setStatusFilter(String(f.statusFilter || ''))
                    setSelectedHost(String(f.selectedHost || ''))
                    setSelectedTech(String(f.selectedTech || ''))
                    setSortKey(String(f.sortKey || 'timestamp'))
                    setSortDir(String(f.sortDir || 'desc'))
                    const pp = Number(f.perPage)
                    if (!Number.isNaN(pp) && pp > 0) setPerPage(pp)
                }
                await importProject(parsed)
                // After import, requests/analytics will refresh via socket 'imported'
            } catch (err) {
                console.error(err)
                alert('Failed to load project file')
            }
        }
        input.click()
    }
    function openTab(evt, tabName) {
        // Declare all variables
        var i, tabcontent, tablinks;

        // Get all elements with class="tabcontent" and hide them
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }

        // Get all elements with class="tablinks" and remove the class "active"
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].className = tablinks[i].className.replace(" active", "");
        }

        // Show the current tab, and add an "active" class to the button that opened the tab
        document.getElementById(tabName).style.display = "block";
        evt.currentTarget.className += " active";
    }
    return (
        <div className="app-root">
            {/* Spider Domain Filter Banner */}
            {spiderDomainFilter && spiderActive && (
                <SpiderDomainBanner
                    domain={spiderDomainFilter}
                    onClear={clearSpiderDomainFilter}
                />
            )}

            <Header
                search={search}
                onSearch={setSearch}
                methodFilter={methodFilter}
                setMethodFilter={setMethodFilter}
                statusFilter={statusFilter}
                setStatusFilter={setStatusFilter}
                onFuzz={onFuzz}
                onClearFilters={onClearFilters}
                onPurge={onPurge}
                onSaveProject={onSaveProject}
                onLoadProject={onLoadProject}
                onOpenOptions={() => setShowOptions(true)}
                observedMethods={Array.from(new Set(requests.map(r => r.method))).sort()}
                observedStatuses={Array.from(new Set(requests.map(r => String(r.status)))).sort((a, b) => Number(a) - Number(b))}
            />
            <div className="content">
                <div className="left">
                    <div className="tab">
                        <button className="tablinks" onClick={e => openTab(e, 'Tab1')}>Proxy</button>
                        <button className="tablinks" onClick={e => openTab(e, 'Tab2')}>SAST</button>
                        <button className="tablinks" onClick={e => openTab(e, 'Tab3')}>Tab 3</button>
                    </div>

                    <div id="Tab1" className="tabcontent">
                        <h3>Live Requests</h3>
                        <DataTable
                            loading={loading}
                            data={filtered}
                            sortKey={sortKey}
                            sortDir={sortDir}
                            onSort={onSort}
                            perPage={perPage}
                            onPerPageChange={setPerPage}
                            onRowClick={setSelectedRequest}
                        />
                    </div>

                    <div id="Tab2" className="tabcontent">
                        <h3>Static Analysis</h3>
                        {/* SAST Scan Progress Panel */}
                        <ScanProgressPanel/>
                        <div style={{height: 12}}/>
                        {/* SAST Discoveries Panel */}
                        <SastDiscoveriesPanel/>
                        <div style={{height: 12}}/>
                        {/* Original Vulnerabilities Panel */}
                        <VulnerabilitiesPanel vulnerabilities={analytics?.vulnerabilities || []}/>
                        <div style={{height: 12}}/>
                    </div>

                    <div id="Tab3" className="tabcontent">
                        <h3>Tab 3</h3>
                        <p>This is the content for the third tab.</p>
                    </div>

                </div>
                <div className="right">
                    <AnalyticsPanels
                        analytics={analytics}
                        selectedHost={selectedHost}
                        onSelectHost={onSelectHostWithSpider}
                        selectedTech={selectedTech}
                        onSelectTech={setSelectedTech}
                    />
                </div>
            </div>
            <OptionsPanel
                open={showOptions}
                onClose={() => setShowOptions(false)}
                llmEnabled={llmEnabled}
                aggressiveFP={aggressiveFP}
                llmApiType={llmApiType}
                onToggleLlm={async (checked, additionalOptions = {}) => {
                    try {
                        const options = {
                            llmEnabled: checked,
                            ...additionalOptions
                        };
                        const res = await setOptions(options);
                        setLlmEnabled(!!res.llmEnabled);
                        // Update llmApiType if it was included in the response
                        if (res.llmApiType) {
                            setLlmApiType(res.llmApiType);
                        }
                    } catch (e) {
                        alert('Failed to save options');
                    }
                }}
                onToggleAggressiveFP={async (checked) => {
                    try {
                        const res = await setOptions({aggressiveFingerprinting: checked});
                        setAggressiveFP(!!res.aggressiveFingerprinting);
                    } catch (e) {
                        alert('Failed to save options');
                    }
                }}
                onFuzz={onFuzz}
                onSaveProject={onSaveProject}
                onLoadProject={onLoadProject}
                fuzzOptions={fuzzOptions}
                onFuzzOptionsChange={setFuzzOptions}
                spiderOptions={spiderOptions}
                onUpdateSpiderOptions={async (partial) => {
                    try {
                        const res = await setOptions(partial)
                        setSpiderOptions({
                            spiderDepth: Number(res.spiderDepth ?? spiderOptions.spiderDepth),
                            spiderMaxPerSeed: Number(res.spiderMaxPerSeed ?? spiderOptions.spiderMaxPerSeed),
                            spiderSameOriginOnly: !!res.spiderSameOriginOnly,
                            spiderTimeoutMs: Number(res.spiderTimeoutMs ?? spiderOptions.spiderTimeoutMs),
                            spiderRequestsPerSec: Number(res.spiderRequestsPerSec ?? spiderOptions.spiderRequestsPerSec),
                            spiderRespectRobots: !!res.spiderRespectRobots,
                        })
                    } catch (e) {
                        alert('Failed to save options');
                    }
                }}
                spiderEnabledAtStart={spiderEnabledAtStart}
                onToggleSpiderAtStart={async (checked) => {
                    try {
                        const res = await setOptions({spiderEnabledAtStart: checked})
                        setSpiderEnabledAtStart(!!res.spiderEnabledAtStart)
                    } catch (e) {
                        alert('Failed to save options');
                    }
                }}
            />
            <RequestDetails request={selectedRequest} onClose={() => setSelectedRequest(null)}/>
        </div>
    )
}
