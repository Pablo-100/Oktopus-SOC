/*
=============================================================================
 Oktopus Dashboard — Alerts, UI Controller, Tabs, Clock, Filtering
=============================================================================
 Fichier : dashboard/js/alerts.js
 Rôle    : Orchestrateur principal du dashboard
           - Gestion des onglets
           - Horloge temps réel
           - Affichage des logs (table live)
           - Affichage des alertes (cards + bouton résoudre)
           - Affichage des agents
           - Filtrage
           - Connexion aux callbacks WebSocket
=============================================================================
*/

const SOCDashboard = (function () {
    // --- Limites ---
    const MAX_LOGS_DISPLAY = 500;
    const MAX_ALERTS_DISPLAY = 200;

    // --- State ---
    let allLogs = [];
    let allAlerts = [];
    let allAgents = [];
    let autoScroll = true;

    // --- Debounce search ---
    let _searchDebounceTimer = null;
    const SEARCH_DEBOUNCE_MS = 300;

    // IPS State
    let ipsBlockedIPs = [];
    let ipsHistory = [];
    let ipsStats = {};
    let ipsWhitelist = [];
    let ipsEnabled = true;

    // Agent System Stats State
    let agentStatsMap = {};  // {agent_id: {stats, timestamp}}

    // --- DOM refs (seront assignées au DOMContentLoaded) ---
    let tabButtons, tabContents;
    let clockEl;
    let statTotalLogs, statActiveAlerts, statConnectedAgents, statCritical;
    let alertBadge;
    let logsTableBody, logsCount;
    let alertsContainer, alertsTotalCount;
    let agentsTableBody, agentsCount;
    let filterLevel, filterAgent, filterSearch, filterSource, autoScrollCb;
    let alertFilterSeverity, alertFilterType;
    let detailOverlay, detailPanel, detailTitle, detailBody;

    // IPS DOM refs
    let ipsBadge;
    let ipsActiveBlocks, ipsTotalBlocks, ipsTotalUnblocks, ipsWhitelistSize;
    let ipsBlockedBody, ipsHistoryBody;
    let ipsToggle, ipsToggleText;
    let whitelistContainer, whitelistIpInput, btnAddWhitelist;

    // =========================================================================
    //  INITIALISATION
    // =========================================================================

    function init() {
        // Refs DOM
        tabButtons = document.querySelectorAll('.tab');
        tabContents = document.querySelectorAll('.tab-content');
        clockEl = document.getElementById('clock');

        statTotalLogs = document.getElementById('stat-total-logs');
        statActiveAlerts = document.getElementById('stat-active-alerts');
        statConnectedAgents = document.getElementById('stat-connected-agents');
        statCritical = document.getElementById('stat-critical');
        alertBadge = document.getElementById('alert-badge');

        logsTableBody = document.getElementById('logs-table-body');
        logsCount = document.getElementById('logs-count');

        alertsContainer = document.getElementById('alerts-container');
        alertsTotalCount = document.getElementById('alerts-total-count');

        agentsTableBody = document.getElementById('agents-table-body');
        agentsCount = document.getElementById('agents-count');

        filterLevel = document.getElementById('filter-level');
        filterAgent = document.getElementById('filter-agent');
        filterSearch = document.getElementById('filter-search');
        filterSource = document.getElementById('filter-source');
        autoScrollCb = document.getElementById('auto-scroll');

        alertFilterSeverity = document.getElementById('alert-filter-severity');
        alertFilterType = document.getElementById('alert-filter-type');

        detailOverlay = document.getElementById('detail-overlay');
        detailPanel = document.getElementById('detail-panel');
        detailTitle = document.getElementById('detail-title');
        detailBody = document.getElementById('detail-body');

        // IPS DOM refs
        ipsBadge = document.getElementById('ips-badge');
        ipsActiveBlocks = document.getElementById('ips-active-blocks');
        ipsTotalBlocks = document.getElementById('ips-total-blocks');
        ipsTotalUnblocks = document.getElementById('ips-total-unblocks');
        ipsWhitelistSize = document.getElementById('ips-whitelist-size');
        ipsBlockedBody = document.getElementById('ips-blocked-body');
        ipsHistoryBody = document.getElementById('ips-history-body');
        ipsToggle = document.getElementById('ips-toggle');
        ipsToggleText = document.getElementById('ips-toggle-text');
        whitelistContainer = document.getElementById('whitelist-container');
        whitelistIpInput = document.getElementById('whitelist-ip-input');
        btnAddWhitelist = document.getElementById('btn-add-whitelist');

        // Tabs
        tabButtons.forEach(function (btn) {
            btn.addEventListener('click', function () {
                switchTab(this.dataset.tab);
            });
        });

        // Filtres logs
        if (filterLevel) filterLevel.addEventListener('change', renderFilteredLogs);
        if (filterAgent) filterAgent.addEventListener('change', renderFilteredLogs);
        if (filterSource) filterSource.addEventListener('change', renderFilteredLogs);
        // Recherche avec debounce 300ms
        if (filterSearch) filterSearch.addEventListener('input', function () {
            clearTimeout(_searchDebounceTimer);
            _searchDebounceTimer = setTimeout(renderFilteredLogs, SEARCH_DEBOUNCE_MS);
        });
        if (autoScrollCb) autoScrollCb.addEventListener('change', function () {
            autoScroll = this.checked;
        });

        // Boutons export CSV et JSON
        var btnExportCSV = document.getElementById('btn-export-csv');
        var btnExportJSON = document.getElementById('btn-export-json');
        if (btnExportCSV) btnExportCSV.addEventListener('click', exportLogsCSV);
        if (btnExportJSON) btnExportJSON.addEventListener('click', exportLogsJSON);

        // Filtre alertes
        if (alertFilterSeverity) alertFilterSeverity.addEventListener('change', renderFilteredAlerts);
        if (alertFilterType) alertFilterType.addEventListener('change', renderFilteredAlerts);

        // Checkbox "Afficher résolues"
        var showResolvedCb = document.getElementById('show-resolved');
        if (showResolvedCb) showResolvedCb.addEventListener('change', renderFilteredAlerts);

        // IPS toggle
        if (ipsToggle) ipsToggle.addEventListener('change', function () {
            var enabled = this.checked;
            ipsEnabled = enabled;
            if (ipsToggleText) ipsToggleText.textContent = enabled ? 'Activé' : 'Désactivé';
            SOCWebSocket.toggleIPS(enabled);
        });

        // IPS whitelist add button
        if (btnAddWhitelist) btnAddWhitelist.addEventListener('click', function () {
            var ip = whitelistIpInput ? whitelistIpInput.value.trim() : '';
            if (ip) {
                SOCWebSocket.addWhitelist(ip);
                if (whitelistIpInput) whitelistIpInput.value = '';
            }
        });

        // Fermer le detail panel en cliquant sur l'overlay
        if (detailOverlay) detailOverlay.addEventListener('click', closeDetail);

        // Horloge
        updateClock();
        setInterval(updateClock, 1000);

        // Initialiser le graphique
        SOCCharts.init('timeline-chart');

        // Brancher les callbacks WebSocket
        SOCWebSocket.onStats(handleStatsWithIPS);
        SOCWebSocket.onLog(handleNewLog);
        SOCWebSocket.onAlert(handleNewAlert);
        SOCWebSocket.onAgents(handleAgents);
        SOCWebSocket.onTimeline(handleTimeline);
        SOCWebSocket.onAlertResolved(handleAlertResolved);
        SOCWebSocket.onInitialLogs(handleInitialLogs);
        SOCWebSocket.onInitialAlerts(handleInitialAlerts);

        // IPS callbacks
        SOCWebSocket.onIPSEvent(handleIPSEvent);
        SOCWebSocket.onInitialIPS(handleInitialIPS);

        // Agent System Stats callbacks
        SOCWebSocket.onAgentStats(handleAgentStats);
        SOCWebSocket.onInitialAgentStats(handleInitialAgentStats);

        // Geo-IP callbacks
        SOCWebSocket.onGeoEvent(function (data) {
            if (typeof SOCCharts !== 'undefined' && SOCCharts.addGeoEvent) {
                SOCCharts.addGeoEvent(data);
            }
        });
        SOCWebSocket.onInitialGeo(function (data) {
            if (typeof SOCCharts !== 'undefined' && SOCCharts.setGeoEvents) {
                SOCCharts.setGeoEvents(data);
            }
        });

        // Lancer la connexion WebSocket
        SOCWebSocket.connect();
    }

    // =========================================================================
    //  TABS
    // =========================================================================

    function switchTab(tabId) {
        tabButtons.forEach(function (btn) {
            btn.classList.toggle('active', btn.dataset.tab === tabId);
        });
        tabContents.forEach(function (content) {
            content.classList.toggle('active', content.id === 'tab-' + tabId);
        });
    }

    // =========================================================================
    //  HORLOGE
    // =========================================================================

    function updateClock() {
        if (!clockEl) return;
        const now = new Date();
        const h = String(now.getHours()).padStart(2, '0');
        const m = String(now.getMinutes()).padStart(2, '0');
        const s = String(now.getSeconds()).padStart(2, '0');
        clockEl.textContent = h + ':' + m + ':' + s;
    }

    // =========================================================================
    //  STATS
    // =========================================================================

    function handleStats(stats) {
        if (!stats) return;
        if (statTotalLogs) statTotalLogs.textContent = formatNumber(stats.total_logs_today || stats.total_logs || 0);
        if (statActiveAlerts) statActiveAlerts.textContent = formatNumber(stats.active_alerts || 0);
        if (statConnectedAgents) statConnectedAgents.textContent = formatNumber(stats.connected_agents || stats.active_agents || 0);
        if (statCritical) statCritical.textContent = formatNumber(stats.critical_last_hour || 0);

        // Badge alertes
        const activeCount = stats.active_alerts || 0;
        if (alertBadge) {
            if (activeCount > 0) {
                alertBadge.textContent = activeCount;
                alertBadge.classList.remove('hidden');
            } else {
                alertBadge.classList.add('hidden');
            }
        }
    }

    // =========================================================================
    //  LOGS
    // =========================================================================

    function handleInitialLogs(logs) {
        if (!Array.isArray(logs)) return;
        allLogs = logs;
        updateAgentFilterOptions();
        renderFilteredLogs();
    }

    function handleNewLog(log) {
        if (!log) return;
        allLogs.push(log);

        // Limiter la taille
        if (allLogs.length > MAX_LOGS_DISPLAY) {
            allLogs = allLogs.slice(-MAX_LOGS_DISPLAY);
        }

        // Mettre à jour les options agent
        updateAgentFilterOptions();

        // Vérifier si le log passe les filtres
        if (matchesLogFilter(log)) {
            appendLogRow(log);
        }
    }

    function renderFilteredLogs() {
        if (!logsTableBody) return;
        logsTableBody.innerHTML = '';

        var filtered = allLogs.filter(matchesLogFilter);
        filtered.forEach(appendLogRow);

        // Afficher le nombre de résultats avec indication de recherche
        if (logsCount) {
            var searchTerm = (filterSearch && filterSearch.value) ? filterSearch.value.trim() : '';
            if (searchTerm) {
                logsCount.textContent = 'Résultats : ' + filtered.length + ' / ' + allLogs.length + ' logs';
            } else {
                logsCount.textContent = filtered.length + ' / ' + allLogs.length + ' logs';
            }
        }
    }

    function matchesLogFilter(log) {
        // Filtre niveau
        if (filterLevel && filterLevel.value && filterLevel.value !== 'all') {
            if ((log.level || '').toLowerCase() !== filterLevel.value.toLowerCase()) {
                return false;
            }
        }
        // Filtre agent
        if (filterAgent && filterAgent.value && filterAgent.value !== 'all') {
            if (log.agent_id !== filterAgent.value) {
                return false;
            }
        }
        // Filtre source
        if (filterSource && filterSource.value && filterSource.value !== 'all' && filterSource.value !== '') {
            if ((log.source || '').toLowerCase() !== filterSource.value.toLowerCase()) {
                return false;
            }
        }
        // Filtre recherche full-text — cherche dans TOUS les champs
        if (filterSearch && filterSearch.value) {
            var term = filterSearch.value.toLowerCase();
            var fields = [
                log.timestamp || '',
                log.agent_id || '',
                log.agent_ip || log.ip || '',
                log.agent_os || log.os || '',
                log.level || '',
                log.source || '',
                log.category || '',
                log.message || '',
                log.raw || ''
            ];
            var found = false;
            for (var i = 0; i < fields.length; i++) {
                if (fields[i].toLowerCase().indexOf(term) !== -1) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }

    /**
     * Met en surbrillance le terme recherché dans un texte.
     * Retourne du HTML avec le terme entouré d'un <mark>.
     */
    function highlightTerm(text, term) {
        if (!term || !text) return escapeHtml(text || '');
        var escaped = escapeHtml(text);
        var escapedTerm = escapeHtml(term);
        // Recherche insensible à la casse
        var regex = new RegExp('(' + escapedTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'gi');
        return escaped.replace(regex, '<mark class="search-highlight">$1</mark>');
    }

    function appendLogRow(log) {
        if (!logsTableBody) return;

        var tr = document.createElement('tr');
        var level = (log.level || 'INFO').toUpperCase();
        var levelClass = getLevelClass(level);

        // Terme de recherche courant pour le highlight
        var searchTerm = (filterSearch && filterSearch.value) ? filterSearch.value : '';

        // Colonne message avec highlight si recherche active
        var msgText = truncate(log.message || log.raw || '-', 80);
        var msgHtml = searchTerm
            ? highlightTerm(msgText, searchTerm)
            : escapeHtml(msgText);

        tr.className = 'log-row clickable';
        tr.innerHTML =
            '<td class="ts-cell">' + escapeHtml(formatTimestamp(log.timestamp)) + '</td>' +
            '<td>' + escapeHtml(log.agent_id || '-') + '</td>' +
            '<td class="ip-cell">' + escapeHtml(log.agent_ip || log.ip || '-') + '</td>' +
            '<td>' + escapeHtml(log.agent_os || log.os || '-') + '</td>' +
            '<td><span class="level-badge ' + levelClass + '">' + escapeHtml(level) + '</span></td>' +
            '<td>' + escapeHtml(log.source || '-') + '</td>' +
            '<td><span class="category-badge">' + escapeHtml(log.category || '-') + '</span></td>' +
            '<td class="msg-cell" title="' + escapeHtml(log.message || log.raw || '') + '">' + msgHtml + '</td>';

        // Click to show log detail
        tr.addEventListener('click', function () {
            showLogDetail(log);
        });

        logsTableBody.appendChild(tr);

        // Auto-scroll
        if (autoScroll) {
            var container = logsTableBody.closest('.table-container');
            if (container) {
                container.scrollTop = container.scrollHeight;
            }
        }

        // Mettre à jour compteur
        if (logsCount) {
            var rows = logsTableBody.querySelectorAll('tr');
            logsCount.textContent = rows.length + ' / ' + allLogs.length + ' logs';
        }
    }

    function updateAgentFilterOptions() {
        if (!filterAgent) return;
        var currentAgent = filterAgent.value;
        var agents = new Set();
        var sources = new Set();
        allLogs.forEach(function (l) {
            if (l.agent_id) agents.add(l.agent_id);
            if (l.source && l.source.trim() !== '') sources.add(l.source);
        });

        // Agents
        var existingAgents = new Set();
        filterAgent.querySelectorAll('option').forEach(function (opt) {
            existingAgents.add(opt.value);
        });
        agents.forEach(function (a) {
            if (!existingAgents.has(a)) {
                var opt = document.createElement('option');
                opt.value = a;
                opt.textContent = a;
                filterAgent.appendChild(opt);
            }
        });
        filterAgent.value = currentAgent;

        // Sources
        if (filterSource) {
            var currentSource = filterSource.value;
            var existingSources = new Set();
            filterSource.querySelectorAll('option').forEach(function (opt) {
                existingSources.add(opt.value);
            });
            sources.forEach(function (s) {
                if (s && s.trim() !== '' && !existingSources.has(s)) {
                    var opt = document.createElement('option');
                    opt.value = s;
                    opt.textContent = s;
                    filterSource.appendChild(opt);
                }
            });
            filterSource.value = currentSource;
        }
    }

    // =========================================================================
    //  ALERTES
    // =========================================================================

    function handleInitialAlerts(alerts) {
        if (!Array.isArray(alerts)) return;
        allAlerts = alerts;
        renderFilteredAlerts();
        if (typeof SOCCharts !== 'undefined' && SOCCharts.updateMitreChart) {
            SOCCharts.updateMitreChart(allAlerts);
        }
    }

    function handleNewAlert(alert) {
        if (!alert) return;
        allAlerts.unshift(alert); // Newest first
        if (allAlerts.length > MAX_ALERTS_DISPLAY) {
            allAlerts = allAlerts.slice(0, MAX_ALERTS_DISPLAY);
        }
        renderFilteredAlerts();
        if (typeof SOCCharts !== 'undefined' && SOCCharts.updateMitreChart) {
            SOCCharts.updateMitreChart(allAlerts);
        }

        // Toast notification for HIGH and CRITICAL alerts
        var sev = (alert.severity || '').toUpperCase();
        if (sev === 'CRITICAL' || sev === 'HIGH') {
            showToast(
                sev === 'CRITICAL' ? 'critical' : 'high',
                getTypeIcon(alert.rule_name || alert.type) + ' ' + (alert.rule_name || alert.type || 'ALERT'),
                truncate(alert.message || alert.description || '', 80)
            );
        }
    }

    function handleAlertResolved(data) {
        if (!data || !data.alert_id) return;
        // Marquer comme résolue dans le state local
        allAlerts.forEach(function (a) {
            if (a.id === data.alert_id || a.id === parseInt(data.alert_id)) {
                a.status = 'resolved';
                a.resolved = 1;
            }
        });
        renderFilteredAlerts();
    }

    function renderFilteredAlerts() {
        if (!alertsContainer) return;
        alertsContainer.innerHTML = '';

        let filtered = allAlerts;

        // Filtre severité
        if (alertFilterSeverity && alertFilterSeverity.value && alertFilterSeverity.value !== 'all') {
            filtered = filtered.filter(function (a) {
                return (a.severity || '').toLowerCase() === alertFilterSeverity.value.toLowerCase();
            });
        }

        // Filtre type
        if (alertFilterType && alertFilterType.value && alertFilterType.value !== 'all' && alertFilterType.value !== '') {
            filtered = filtered.filter(function (a) {
                return (a.type || a.rule_name || '').toUpperCase().indexOf(alertFilterType.value.toUpperCase()) !== -1;
            });
        }

        // Filtre resolved — check both 'status' (runtime) and 'resolved' (from DB: 0/1)
        var showResolved = document.getElementById('show-resolved');
        if (showResolved && !showResolved.checked) {
            filtered = filtered.filter(function (a) {
                return a.status !== 'resolved' && a.resolved !== 1 && a.resolved !== '1';
            });
        }

        if (filtered.length === 0) {
            alertsContainer.innerHTML = '<div class="empty-msg">Aucune alerte</div>';
        } else {
            filtered.forEach(function (alert) {
                alertsContainer.appendChild(createAlertCard(alert));
            });
        }

        if (alertsTotalCount) {
            alertsTotalCount.textContent = filtered.length + ' alerte(s)';
        }
    }

    function createAlertCard(alert) {
        var severity = (alert.severity || 'medium').toLowerCase();
        var isResolved = (alert.status === 'resolved' || alert.resolved === 1 || alert.resolved === '1');
        var alertType = alert.type || alert.rule_name || 'UNKNOWN';

        var div = document.createElement('div');
        div.className = 'alert-item severity-' + severity + (isResolved ? ' resolved' : '') + ' clickable';
        div.dataset.alertId = alert.id;

        var typeIcon = getTypeIcon(alertType);

        // MITRE ATT&CK badges
        var mitreBadges = '';
        if (alert.mitre_technique_id) {
            mitreBadges =
                '<a class="mitre-technique-badge" href="https://attack.mitre.org/techniques/' +
                    escapeHtml(alert.mitre_technique_id.replace('.', '/')) + '/" target="_blank" ' +
                    'title="' + escapeHtml(alert.mitre_technique_name || '') + '" onclick="event.stopPropagation()">' +
                    escapeHtml(alert.mitre_technique_id) +
                '</a>' +
                (alert.mitre_tactic
                    ? '<span class="mitre-tactic-badge">' + escapeHtml(alert.mitre_tactic) + '</span>'
                    : '');
        }

        div.innerHTML =
            '<div class="alert-info">' +
                '<div class="alert-header">' +
                    '<span class="alert-type-icon">' + typeIcon + '</span>' +
                    '<span class="alert-rule">' + escapeHtml(alert.rule_name || alert.rule || 'Inconnu') + '</span>' +
                    '<span class="alert-severity ' + severity + '">' + severity.toUpperCase() + '</span>' +
                    '<span class="alert-type-badge">' + escapeHtml(alertType) + '</span>' +
                    mitreBadges +
                '</div>' +
                '<div class="alert-message">' + escapeHtml(alert.message || alert.description || '-') + '</div>' +
                '<div class="alert-meta">' +
                    '<span>🕐 ' + escapeHtml(formatTimestampFull(alert.timestamp || alert.created_at)) + '</span>' +
                    (alert.agent_id ? '<span>🖥️ ' + escapeHtml(alert.agent_id) + '</span>' : '') +
                    (alert.source_ip ? '<span>🌐 ' + escapeHtml(alert.source_ip) + '</span>' : '') +
                    (alert.log_id ? '<span>📄 Log #' + alert.log_id + '</span>' : '') +
                '</div>' +
            '</div>' +
            '<div class="alert-actions">' +
                (isResolved
                    ? '<span class="resolved-badge">✓ Résolue</span>'
                    : '<button class="btn btn-small btn-success" onclick="event.stopPropagation(); SOCDashboard.resolveAlert(' + alert.id + ')">Résoudre</button>'
                ) +
            '</div>';

        // Click pour détails
        div.addEventListener('click', function () {
            showAlertDetail(alert);
        });

        return div;
    }

    function getTypeIcon(type) {
        var t = (type || '').toUpperCase();
        if (t.indexOf('BRUTE') !== -1) return '🔓';
        if (t.indexOf('PORT_SCAN') !== -1 || t.indexOf('SCAN') !== -1) return '🔍';
        if (t.indexOf('SQL') !== -1) return '💉';
        if (t.indexOf('XSS') !== -1) return '⚡';
        if (t.indexOf('COMMAND_INJECTION') !== -1) return '💻';
        if (t.indexOf('LDAP') !== -1) return '📂';
        if (t.indexOf('XXE') !== -1 || t.indexOf('XML') !== -1) return '📄';
        if (t.indexOf('LFI') !== -1 || t.indexOf('PATH_TRAVERSAL') !== -1) return '📁';
        if (t.indexOf('MALWARE') !== -1) return '🦠';
        if (t.indexOf('REVERSE_SHELL') !== -1) return '🐚';
        if (t.indexOf('C2') !== -1 || t.indexOf('BEACON') !== -1) return '📡';
        if (t.indexOf('LATERAL') !== -1) return '⇆';
        if (t.indexOf('PERSISTENCE') !== -1 || t.indexOf('REGISTRY') !== -1) return '🔩';
        if (t.indexOf('PRIVILEGE') !== -1 || t.indexOf('PRIV_ESC') !== -1) return '👑';
        if (t.indexOf('EXFILTRATION') !== -1) return '📤';
        if (t.indexOf('POWERSHELL') !== -1 || t.indexOf('SCRIPT') !== -1) return '📜';
        if (t.indexOf('TOR') !== -1) return '🪤';
        if (t.indexOf('VPN') !== -1) return '🔐';
        if (t.indexOf('DNS') !== -1) return '🌐';
        if (t.indexOf('MALFORMED_DATA') !== -1) return '🔥';
        if (t.indexOf('DDOS') !== -1 || t.indexOf('FLOOD') !== -1) return '🌊';
        if (t.indexOf('SMB') !== -1) return '📀';
        if (t.indexOf('LOG_TAMPER') !== -1) return '🗑️';
        if (t.indexOf('SUSPICIOUS') !== -1) return '⚠️';
        if (t.indexOf('ANOMALY') !== -1) return '📊';
        if (t.indexOf('TOKEN') !== -1) return '🎫';
        if (t.indexOf('ENUMERATION') !== -1 || t.indexOf('RECON') !== -1) return '🗺️';
        return '🚨';
    }

    function resolveAlert(alertId) {
        SOCWebSocket.resolveAlert(alertId);
    }

    // =========================================================================
    //  AGENTS
    // =========================================================================

    function handleAgents(agents) {
        if (!Array.isArray(agents)) return;
        allAgents = agents;
        renderAgents();
    }

    function renderAgents() {
        if (!agentsTableBody) return;
        agentsTableBody.innerHTML = '';

        if (allAgents.length === 0) {
            agentsTableBody.innerHTML = '<tr><td colspan="6" class="empty-msg">Aucun agent enregistré</td></tr>';
        } else {
            allAgents.forEach(function (agent) {
                const tr = document.createElement('tr');
                const isOnline = (agent.status === 'active' || agent.status === 'online');
                const statusClass = isOnline ? 'status-online' : 'status-offline';
                const statusText = isOnline ? 'En ligne' : 'Hors ligne';

                tr.innerHTML =
                    '<td><span class="' + statusClass + '">' + statusText + '</span></td>' +
                    '<td>' + escapeHtml(agent.agent_id || agent.id || '-') + '</td>' +
                    '<td>' + escapeHtml(agent.ip || agent.ip_address || '-') + '</td>' +
                    '<td><span class="os-badge">' + escapeHtml(agent.os || agent.os_type || '-') + '</span></td>' +
                    '<td>' + escapeHtml(formatTimestamp(agent.first_seen || agent.registered_at)) + '</td>' +
                    '<td>' + escapeHtml(formatTimestamp(agent.last_heartbeat || agent.last_seen)) + '</td>';

                agentsTableBody.appendChild(tr);
            });
        }

        if (agentsCount) {
            const online = allAgents.filter(function (a) {
                return a.status === 'active' || a.status === 'online';
            }).length;
            agentsCount.textContent = online + ' / ' + allAgents.length + ' agents';
        }
    }

    // =========================================================================
    //  AGENT SYSTEM STATS — Monitoring temps réel
    // =========================================================================

    /**
     * Reçoit les stats initiales de tous les agents (au chargement)
     */
    function handleInitialAgentStats(dataArray) {
        if (!Array.isArray(dataArray)) return;
        dataArray.forEach(function (item) {
            if (item && item.agent_id && item.stats) {
                agentStatsMap[item.agent_id] = {
                    stats: (typeof item.stats === 'string') ? JSON.parse(item.stats) : item.stats,
                    timestamp: item.timestamp || new Date().toISOString()
                };
            }
        });
        renderAgentMonitoring();
    }

    /**
     * Reçoit une mise à jour de stats d'un agent (temps réel)
     */
    function handleAgentStats(data) {
        if (!data || !data.agent_id) return;
        agentStatsMap[data.agent_id] = {
            stats: (typeof data.stats === 'string') ? JSON.parse(data.stats) : data.stats,
            timestamp: data.timestamp || new Date().toISOString()
        };
        renderAgentMonitoring();
    }

    /**
     * Rendu complet de la section monitoring agents
     */
    function renderAgentMonitoring() {
        var container = document.getElementById('agent-stats-container');
        if (!container) return;

        var agentIds = Object.keys(agentStatsMap);

        if (agentIds.length === 0) {
            container.innerHTML = '<div class="empty-msg">Aucune donnée système reçue des agents</div>';
            return;
        }

        var html = '';
        agentIds.forEach(function (agentId) {
            var entry = agentStatsMap[agentId];
            html += createAgentCard(agentId, entry.stats, entry.timestamp);
        });

        container.innerHTML = html;
    }

    /**
     * Crée la carte HTML complète d'un agent
     */
    function createAgentCard(agentId, stats, timestamp) {
        if (!stats) return '';

        var cpu = stats.cpu || {};
        var ram = stats.ram || {};
        var swap = stats.swap || {};
        var disks = stats.disks || [];
        var net = stats.network || {};
        var osInfo = stats.os_info || {};
        var uptime = stats.uptime || {};
        var topProcs = stats.top_processes || [];

        // Trouver l'agent dans la liste pour le status
        var agentInfo = allAgents.find(function(a) {
            return (a.agent_id || a.id) === agentId;
        });
        var isOnline = agentInfo && (agentInfo.status === 'active' || agentInfo.status === 'online');
        var statusDot = isOnline ? '<span class="agent-status-dot online"></span>' : '<span class="agent-status-dot offline"></span>';

        var html = '<div class="agent-monitor-card" data-agent="' + escapeHtml(agentId) + '">';

        // === Header ===
        var isAndroid = (osInfo.system && osInfo.system.toLowerCase() === 'android');
        var agentIcon = isAndroid ? '📱' : '🖥️';
        html += '<div class="agent-card-header">';
        html += statusDot;
        html += '<span class="agent-card-title">' + agentIcon + ' ' + escapeHtml(agentId) + '</span>';
        if (osInfo.system) {
            var osTagClass = isAndroid ? 'agent-os-tag android-tag' : 'agent-os-tag';
            html += '<span class="' + osTagClass + '">' + escapeHtml(osInfo.system);
            if (osInfo.architecture) html += ' ' + escapeHtml(osInfo.architecture);
            html += '</span>';
        }
        html += '</div>';

        // === Barres CPU / RAM / Swap ===
        html += '<div class="agent-card-section">';
        html += '<div class="agent-section-title">⚡ Ressources</div>';

        // CPU
        var cpuPct = cpu.percent || 0;
        html += createStatBar('CPU', cpuPct, cpuPct.toFixed(1) + '%');
        if (cpu.cores_physical) {
            html += '<div class="stat-detail">Cœurs: ' + cpu.cores_physical + ' physiques / ' + (cpu.cores_logical || '-') + ' logiques';
            if (cpu.frequency_mhz) html += ' — ' + cpu.frequency_mhz + ' MHz';
            html += '</div>';
        }

        // RAM
        var ramPct = ram.percent || 0;
        var ramLabel = ramPct.toFixed(1) + '% (' + (ram.used_gb || 0).toFixed(1) + ' / ' + (ram.total_gb || 0).toFixed(1) + ' Go)';
        html += createStatBar('RAM', ramPct, ramLabel);

        // Batterie (Android uniquement)
        var battery = stats.battery || {};
        if (isAndroid && battery && battery.percent !== undefined && battery.percent >= 0) {
            var battPct = battery.percent;
            var battCharging = battery.charging || battery.plugged || false;
            var battIcon = battCharging ? '⚡' : '🔋';
            var battLabel = battPct.toFixed(0) + '%' + (battCharging ? ' ⚡ En charge' : '');
            var battColor = 'green';
            if (battPct < 20) battColor = 'red';
            else if (battPct < 50) battColor = 'orange';
            html += createStatBar(battIcon + ' Batterie', battPct, battLabel);
        }

        // Swap (pas sur Android)
        if (!isAndroid && swap && swap.total_gb > 0) {
            var swapPct = swap.percent || 0;
            var swapLabel = swapPct.toFixed(1) + '% (' + (swap.used_gb || 0).toFixed(1) + ' / ' + (swap.total_gb || 0).toFixed(1) + ' Go)';
            html += createStatBar('Swap', swapPct, swapLabel);
        }

        html += '</div>'; // fin section ressources

        // === Disques (pas sur Android) ===
        if (!isAndroid && disks.length > 0) {
            html += '<div class="agent-card-section">';
            html += '<div class="agent-section-title">💾 Disques</div>';
            disks.forEach(function (d) {
                var diskPct = d.percent || 0;
                var diskLabel = diskPct.toFixed(1) + '% (' + (d.used_gb || 0).toFixed(1) + ' / ' + (d.total_gb || 0).toFixed(1) + ' Go)';
                html += createStatBar(escapeHtml(d.mountpoint || d.device || '?'), diskPct, diskLabel);
            });
            html += '</div>';
        }

        // === Réseau ===
        html += '<div class="agent-card-section">';
        html += '<div class="agent-section-title">🌐 Réseau</div>';
        html += '<div class="agent-info-grid">';
        html += '<div class="info-item"><span class="info-label">⬆ Envoyé</span><span class="info-value">' + (net.bytes_sent_mb || 0).toFixed(1) + ' Mo</span></div>';
        html += '<div class="info-item"><span class="info-label">⬇ Reçu</span><span class="info-value">' + (net.bytes_recv_mb || 0).toFixed(1) + ' Mo</span></div>';
        html += '<div class="info-item"><span class="info-label">Connexions</span><span class="info-value">' + (net.active_connections || 0) + '</span></div>';
        html += '</div>';
        html += '</div>';

        // === OS / Uptime ===
        html += '<div class="agent-card-section">';
        html += '<div class="agent-section-title">ℹ️ Système</div>';
        html += '<div class="agent-info-grid">';
        if (osInfo.hostname) html += '<div class="info-item"><span class="info-label">Hostname</span><span class="info-value">' + escapeHtml(osInfo.hostname) + '</span></div>';
        if (osInfo.version) html += '<div class="info-item"><span class="info-label">Version</span><span class="info-value">' + escapeHtml(truncate(osInfo.version, 40)) + '</span></div>';
        if (osInfo.machine) html += '<div class="info-item"><span class="info-label">Machine</span><span class="info-value">' + escapeHtml(osInfo.machine) + '</span></div>';
        if (uptime.uptime_human) html += '<div class="info-item"><span class="info-label">Uptime</span><span class="info-value">' + escapeHtml(uptime.uptime_human) + '</span></div>';
        html += '</div>';
        html += '</div>';

        // === Top 5 Processus ===
        if (topProcs.length > 0) {
            html += '<div class="agent-card-section">';
            html += '<div class="agent-section-title">📊 Top 5 Processus (CPU)</div>';
            html += '<table class="process-mini-table">';
            html += '<thead><tr><th>Nom</th><th>PID</th><th>CPU%</th><th>MEM%</th></tr></thead><tbody>';
            topProcs.forEach(function (p) {
                html += '<tr>';
                html += '<td>' + escapeHtml(truncate(p.name || '-', 20)) + '</td>';
                html += '<td>' + (p.pid || '-') + '</td>';
                html += '<td>' + (p.cpu_percent || 0).toFixed(1) + '</td>';
                html += '<td>' + (p.memory_percent || 0).toFixed(1) + '</td>';
                html += '</tr>';
            });
            html += '</tbody></table>';
            html += '</div>';
        }

        // === CPU par cœur (mini barres) ===
        if (cpu.per_core && cpu.per_core.length > 0) {
            html += '<div class="agent-card-section">';
            html += '<div class="agent-section-title">🔲 CPU par cœur</div>';
            html += '<div class="cpu-cores-grid">';
            cpu.per_core.forEach(function (pct, idx) {
                var color = getBarColor(pct);
                html += '<div class="core-bar-item">';
                html += '<span class="core-label">C' + idx + '</span>';
                html += '<div class="stat-bar mini"><div class="bar-fill bar-' + color + '" style="width:' + Math.min(pct, 100) + '%"></div></div>';
                html += '<span class="core-pct">' + pct.toFixed(0) + '%</span>';
                html += '</div>';
            });
            html += '</div>';
            html += '</div>';
        }

        // === Footer avec timestamp ===
        html += '<div class="agent-card-footer">';
        html += '<span class="last-update">Dernière mise à jour : ' + escapeHtml(formatTimestamp(timestamp)) + '</span>';
        html += '</div>';

        html += '</div>'; // fin agent-monitor-card

        return html;
    }

    /**
     * Crée une barre de progression colorée
     */
    function createStatBar(label, percent, valueText) {
        var color = getBarColor(percent);
        var pct = Math.min(percent, 100);
        var html = '<div class="stat-bar-row">';
        html += '<span class="stat-bar-label">' + label + '</span>';
        html += '<div class="stat-bar"><div class="bar-fill bar-' + color + '" style="width:' + pct + '%"></div></div>';
        html += '<span class="stat-bar-value">' + valueText + '</span>';
        html += '</div>';
        return html;
    }

    /**
     * Retourne la couleur selon le pourcentage : vert < 60, orange 60-80, rouge > 80
     */
    function getBarColor(percent) {
        if (percent >= 80) return 'red';
        if (percent >= 60) return 'orange';
        return 'green';
    }

    // =========================================================================
    //  DETAIL PANEL
    // =========================================================================

    function showLogDetail(log) {
        if (!detailPanel || !detailBody || !detailTitle) return;
        detailTitle.textContent = '📋 Détail du Log';

        var level = (log.level || 'INFO').toUpperCase();
        var levelClass = getLevelClass(level);
        var ips = extractIPsFromString(log.message || log.raw || '');

        var html =
            '<div class="detail-section">' +
                '<div class="detail-label">ID</div>' +
                '<div class="detail-value">#' + (log.id || '-') + '</div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Timestamp</div>' +
                '<div class="detail-value">' + escapeHtml(log.timestamp || '-') + '</div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Niveau</div>' +
                '<div class="detail-value"><span class="level-badge ' + levelClass + '">' + escapeHtml(level) + '</span></div>' +
            '</div>' +
            '<div class="detail-divider"></div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Agent</div>' +
                '<div class="detail-value">' + escapeHtml(log.agent_id || '-') + '</div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Adresse IP</div>' +
                '<div class="detail-value mono">' + escapeHtml(log.agent_ip || log.ip || '-') + '</div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Système</div>' +
                '<div class="detail-value"><span class="os-badge">' + escapeHtml(log.agent_os || log.os || '-') + '</span></div>' +
            '</div>' +
            '<div class="detail-divider"></div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Source</div>' +
                '<div class="detail-value">' + escapeHtml(log.source || '-') + '</div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Catégorie</div>' +
                '<div class="detail-value"><span class="category-badge">' + escapeHtml(log.category || '-') + '</span></div>' +
            '</div>';

        if (ips.length > 0) {
            html +=
                '<div class="detail-divider"></div>' +
                '<div class="detail-section">' +
                    '<div class="detail-label">IPs extraites</div>' +
                    '<div class="detail-value">' +
                        ips.map(function(ip) {
                            return '<span class="ip-tag">' + escapeHtml(ip) + '</span>';
                        }).join(' ') +
                    '</div>' +
                '</div>';
        }

        html +=
            '<div class="detail-divider"></div>' +
            '<div class="detail-section full-width">' +
                '<div class="detail-label">Message complet</div>' +
                '<div class="detail-value detail-message-full">' + escapeHtml(log.message || '-') + '</div>' +
            '</div>';

        if (log.raw && log.raw !== log.message) {
            html +=
                '<div class="detail-section full-width">' +
                    '<div class="detail-label">Données brutes</div>' +
                    '<pre class="detail-raw">' + escapeHtml(log.raw || log.raw_json || '-') + '</pre>' +
                '</div>';
        }

        detailBody.innerHTML = html;
        openDetail();
    }

    function showAlertDetail(alert) {
        if (!detailPanel || !detailBody || !detailTitle) return;
        var severity = (alert.severity || 'medium').toLowerCase();
        var typeIcon = getTypeIcon(alert.type || alert.rule_name || '');
        detailTitle.textContent = typeIcon + ' Détail de l\'Alerte';

        var isResolved = (alert.status === 'resolved');

        var html =
            '<div class="detail-alert-banner severity-' + severity + '">' +
                '<div class="detail-alert-rule">' + escapeHtml(alert.rule_name || alert.rule || 'Inconnu') + '</div>' +
                '<span class="alert-severity ' + severity + '">' + severity.toUpperCase() + '</span>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">ID Alerte</div>' +
                '<div class="detail-value">#' + (alert.id || '-') + '</div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Timestamp</div>' +
                '<div class="detail-value">' + escapeHtml(alert.timestamp || alert.created_at || '-') + '</div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Type</div>' +
                '<div class="detail-value"><span class="alert-type-badge">' + escapeHtml(alert.type || '-') + '</span></div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Sévérité</div>' +
                '<div class="detail-value"><span class="alert-severity ' + severity + '">' + severity.toUpperCase() + '</span></div>' +
            '</div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Statut</div>' +
                '<div class="detail-value">' + (isResolved ? '<span class="resolved-badge">✓ Résolue</span>' : '<span class="active-badge">● Active</span>') + '</div>' +
            '</div>' +
            '<div class="detail-divider"></div>' +
            '<div class="detail-section">' +
                '<div class="detail-label">Agent</div>' +
                '<div class="detail-value">' + escapeHtml(alert.agent_id || '-') + '</div>' +
            '</div>';

        // MITRE ATT&CK section
        if (alert.mitre_technique_id) {
            html +=
                '<div class="detail-divider"></div>' +
                '<div class="detail-section full-width">' +
                    '<div class="detail-label">🛡️ MITRE ATT&CK</div>' +
                    '<div class="detail-value">' +
                        '<a class="mitre-technique-badge" href="https://attack.mitre.org/techniques/' +
                            escapeHtml(alert.mitre_technique_id.replace('.', '/')) + '/" target="_blank">' +
                            escapeHtml(alert.mitre_technique_id) +
                        '</a> ' +
                        '<span class="mitre-tactic-badge">' + escapeHtml(alert.mitre_tactic || '') + '</span>' +
                        '<br><span style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 4px; display: inline-block;">' +
                            escapeHtml(alert.mitre_technique_name || '') +
                        '</span>' +
                    '</div>' +
                '</div>';
        }

        if (alert.source_ip) {
            html +=
                '<div class="detail-section">' +
                    '<div class="detail-label">IP source</div>' +
                    '<div class="detail-value mono"><span class="ip-tag">' + escapeHtml(alert.source_ip) + '</span></div>' +
                '</div>';
        }

        if (alert.log_id) {
            html +=
                '<div class="detail-section">' +
                    '<div class="detail-label">Log associé</div>' +
                    '<div class="detail-value">#' + alert.log_id + '</div>' +
                '</div>';
        }

        html +=
            '<div class="detail-divider"></div>' +
            '<div class="detail-section full-width">' +
                '<div class="detail-label">Description</div>' +
                '<div class="detail-value detail-message-full">' + escapeHtml(alert.message || alert.description || '-') + '</div>' +
            '</div>';

        // Actions
        if (!isResolved) {
            html +=
                '<div class="detail-divider"></div>' +
                '<div class="detail-actions">' +
                    '<button class="btn btn-success" onclick="SOCDashboard.resolveAlert(' + alert.id + '); SOCDashboard.closeDetail();">✓ Marquer comme résolue</button>' +
                '</div>';
        }

        // Recommandations
        var recommendations = getRecommendations(alert.type || alert.rule_name || '');
        if (recommendations.length > 0) {
            html +=
                '<div class="detail-divider"></div>' +
                '<div class="detail-section full-width">' +
                    '<div class="detail-label">💡 Recommandations</div>' +
                    '<ul class="detail-recommendations">';
            recommendations.forEach(function (r) {
                html += '<li>' + escapeHtml(r) + '</li>';
            });
            html += '</ul></div>';
        }

        detailBody.innerHTML = html;
        openDetail();
    }

    function getRecommendations(type) {
        var t = (type || '').toUpperCase();
        if (t.indexOf('BRUTE') !== -1) return [
            'Vérifier les comptes ciblés et forcer un changement de mot de passe',
            'Activer le verrouillage de compte après N tentatives',
            'Bloquer l\'IP source dans le firewall',
            'Vérifier si une connexion a réussi après les tentatives'
        ];
        if (t.indexOf('PORT_SCAN') !== -1 || t.indexOf('SCAN') !== -1 || t.indexOf('RECONNAISSANCE') !== -1) return [
            'Identifier la source du scan (interne/externe)',
            'Bloquer l\'IP source si externe',
            'Vérifier les ports ouverts sur la cible',
            'Analyser les logs réseau pour d\'autres activités suspectes'
        ];
        if (t.indexOf('SQL') !== -1) return [
            'Vérifier et patcher l\'application web vulnérable',
            'Activer un WAF (Web Application Firewall)',
            'Analyser les requêtes SQL suspectes dans les logs applicatifs',
            'Vérifier l\'intégrité de la base de données'
        ];
        if (t.indexOf('XSS') !== -1) return [
            'Sanitiser les entrées utilisateur dans l\'application',
            'Implémenter une Content Security Policy (CSP)',
            'Vérifier les cookies de session (HttpOnly, Secure)'
        ];
        if (t.indexOf('MALWARE') !== -1) return [
            'Isoler la machine compromise du réseau',
            'Lancer un scan antivirus complet',
            'Vérifier les processus en cours et les connexions réseau',
            'Analyser le fichier suspect dans un sandbox'
        ];
        if (t.indexOf('PRIVILEGE') !== -1) return [
            'Vérifier la légitimité de l\'élévation de privilèges',
            'Auditer les permissions des comptes concernés',
            'Vérifier les modifications récentes du système'
        ];
        if (t.indexOf('MALFORMED_DATA') !== -1) return [
            'Identifier l\'IP source — possible scanner (nmap, masscan)',
            'Bloquer l\'IP au niveau du firewall',
            'Capturer le trafic avec tcpdump/Wireshark pour analyse',
            'Vérifier si l\'IP est connue sur AbuseIPDB / VirusTotal'
        ];
        if (t.indexOf('SUSPICIOUS') !== -1) return [
            'Identifier le processus utilisant ce port',
            'Vérifier si c\'est un service légitime',
            'Capturer le trafic réseau pour analyse'
        ];
        return [
            'Analyser le contexte de l\'alerte',
            'Vérifier les logs associés pour plus d\'informations',
            'Escalader si nécessaire'
        ];
    }

    function extractIPsFromString(str) {
        if (!str) return [];
        var matches = str.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g);
        if (!matches) return [];
        // Dédupliquer
        return matches.filter(function(ip, i, arr) {
            return arr.indexOf(ip) === i && ip !== '0.0.0.0' && ip !== '127.0.0.1';
        });
    }

    function openDetail() {
        if (detailOverlay) detailOverlay.classList.remove('hidden');
        if (detailPanel) detailPanel.classList.remove('hidden');
        // Empêcher le scroll du body
        document.body.style.overflow = 'hidden';
    }

    function closeDetail() {
        if (detailOverlay) detailOverlay.classList.add('hidden');
        if (detailPanel) detailPanel.classList.add('hidden');
        document.body.style.overflow = '';
    }

    // =========================================================================
    //  IPS — Intrusion Prevention System
    // =========================================================================

    function handleInitialIPS(data) {
        if (!data) return;
        ipsBlockedIPs = data.blocked_ips || [];
        ipsHistory = data.history || [];
        ipsStats = data.stats || {};
        ipsWhitelist = data.whitelist || [];
        ipsEnabled = data.enabled !== false;

        // Mettre à jour le toggle
        if (ipsToggle) ipsToggle.checked = ipsEnabled;
        if (ipsToggleText) ipsToggleText.textContent = ipsEnabled ? 'Activé' : 'Désactivé';

        updateIPSStats();
        renderIPSBlocked();
        renderIPSHistory();
        renderWhitelist();
    }

    function handleIPSEvent(data) {
        if (!data) return;

        var event = data.event;

        if (event === 'ip_blocked') {
            // Ajouter à la liste des IPs bloquées
            ipsBlockedIPs.unshift(data);
            ipsHistory.unshift(data);
            if (ipsHistory.length > 200) ipsHistory = ipsHistory.slice(0, 200);
            updateIPSStats();
            renderIPSBlocked();
            renderIPSHistory();
            updateIPSBadge();
            // Toast for IPS block
            showToast('critical', '🚫 IP Blocked', (data.ip || '?') + ' — ' + (data.reason || 'IPS'));
        }
        else if (event === 'ip_unblocked') {
            // Retirer de la liste des IPs bloquées
            ipsBlockedIPs = ipsBlockedIPs.filter(function (b) {
                return b.id !== data.id;
            });
            // Mettre à jour l'historique
            ipsHistory.forEach(function (h) {
                if (h.id === data.id) {
                    h.status = 'unblocked';
                    h.unblock_reason = data.reason;
                }
            });
            ipsHistory.unshift({
                ip: data.ip,
                action: 'unblock',
                reason: data.reason,
                status: 'unblocked',
                timestamp: data.timestamp,
                agent_id: data.agent_id
            });
            updateIPSStats();
            renderIPSBlocked();
            renderIPSHistory();
            updateIPSBadge();
        }
        else if (event === 'ips_toggled') {
            ipsEnabled = data.enabled !== false;
            if (ipsToggle) ipsToggle.checked = ipsEnabled;
            if (ipsToggleText) ipsToggleText.textContent = ipsEnabled ? 'Activé' : 'Désactivé';
        }
        else if (event === 'whitelist_updated') {
            ipsWhitelist = data.whitelist || [];
            renderWhitelist();
            updateIPSStats();
        }
        // handle unblock result (from ips_unblock_result)
        else if (data.action_id && data.success !== undefined) {
            // Refresh IPS data
            SOCWebSocket.requestIPSData();
        }
    }

    function updateIPSStats() {
        var active = ipsBlockedIPs.length;
        if (ipsActiveBlocks) ipsActiveBlocks.textContent = active;
        if (ipsTotalBlocks) ipsTotalBlocks.textContent = ipsStats.total_blocks || active;
        if (ipsTotalUnblocks) ipsTotalUnblocks.textContent = ipsStats.total_unblocks || 0;
        if (ipsWhitelistSize) ipsWhitelistSize.textContent = ipsWhitelist.length;
    }

    function updateIPSBadge() {
        var count = ipsBlockedIPs.length;
        if (ipsBadge) {
            if (count > 0) {
                ipsBadge.textContent = count;
                ipsBadge.classList.remove('hidden');
            } else {
                ipsBadge.classList.add('hidden');
            }
        }
    }

    function renderIPSBlocked() {
        if (!ipsBlockedBody) return;
        ipsBlockedBody.innerHTML = '';

        if (ipsBlockedIPs.length === 0) {
            ipsBlockedBody.innerHTML = '<tr><td colspan="9" class="empty-msg">Aucune IP bloquée</td></tr>';
            return;
        }

        ipsBlockedIPs.forEach(function (block) {
            var tr = document.createElement('tr');
            var sev = (block.severity || 'medium').toLowerCase();
            var durStr = block.duration_minutes > 0 ? block.duration_minutes + ' min' : 'Permanent';
            var expiresStr = block.expires_at ? formatTimestamp(block.expires_at) : '-';
            var blockedAt = formatTimestampFull(block.timestamp);

            tr.className = 'ips-blocked-row';
            tr.innerHTML =
                '<td class="ip-cell">' + escapeHtml(block.ip || '-') + '</td>' +
                '<td class="msg-cell" title="' + escapeHtml(block.reason || '') + '">' + escapeHtml(truncate(block.reason || '-', 40)) + '</td>' +
                '<td><span class="alert-severity ' + sev + '">' + sev.toUpperCase() + '</span></td>' +
                '<td><span class="alert-type-badge">' + escapeHtml(block.alert_type || '-') + '</span></td>' +
                '<td>' + escapeHtml(block.agent_id || '-') + '</td>' +
                '<td>' + escapeHtml(durStr) + '</td>' +
                '<td>' + escapeHtml(expiresStr) + '</td>' +
                '<td class="ts-cell">' + escapeHtml(blockedAt) + '</td>' +
                '<td><button class="btn btn-small btn-danger ips-unblock-btn" data-id="' + block.id + '">Débloquer</button></td>';

            // Unblock button handler
            var btn = tr.querySelector('.ips-unblock-btn');
            if (btn) {
                btn.addEventListener('click', function () {
                    var actionId = this.dataset.id;
                    if (confirm('Débloquer cette IP ?')) {
                        SOCWebSocket.unblockIP(parseInt(actionId));
                    }
                });
            }

            ipsBlockedBody.appendChild(tr);
        });
    }

    function renderIPSHistory() {
        if (!ipsHistoryBody) return;
        ipsHistoryBody.innerHTML = '';

        if (ipsHistory.length === 0) {
            ipsHistoryBody.innerHTML = '<tr><td colspan="7" class="empty-msg">Aucun historique</td></tr>';
            return;
        }

        ipsHistory.slice(0, 100).forEach(function (entry) {
            var tr = document.createElement('tr');
            var sev = (entry.severity || '-').toLowerCase();
            var action = entry.action || 'block';
            var status = entry.status || 'active';

            var actionBadge = action === 'block'
                ? '<span class="ips-action-block">BLOCK</span>'
                : '<span class="ips-action-unblock">UNBLOCK</span>';

            var statusBadge = status === 'active'
                ? '<span class="active-badge">Active</span>'
                : '<span class="resolved-badge">Terminé</span>';

            tr.innerHTML =
                '<td class="ip-cell">' + escapeHtml(entry.ip || '-') + '</td>' +
                '<td>' + actionBadge + '</td>' +
                '<td class="msg-cell" title="' + escapeHtml(entry.reason || '') + '">' + escapeHtml(truncate(entry.reason || '-', 50)) + '</td>' +
                '<td><span class="alert-severity ' + sev + '">' + (sev !== '-' ? sev.toUpperCase() : '-') + '</span></td>' +
                '<td><span class="alert-type-badge">' + escapeHtml(entry.alert_type || '-') + '</span></td>' +
                '<td>' + statusBadge + '</td>' +
                '<td class="ts-cell">' + escapeHtml(formatTimestampFull(entry.timestamp)) + '</td>';

            ipsHistoryBody.appendChild(tr);
        });
    }

    function renderWhitelist() {
        if (!whitelistContainer) return;
        whitelistContainer.innerHTML = '';

        if (ipsWhitelist.length === 0) {
            whitelistContainer.innerHTML = '<span class="empty-msg">Aucune IP en whitelist</span>';
            return;
        }

        ipsWhitelist.forEach(function (ip) {
            var tag = document.createElement('span');
            tag.className = 'whitelist-tag';
            tag.innerHTML = escapeHtml(ip) +
                ' <button class="whitelist-remove" data-ip="' + escapeHtml(ip) + '" title="Retirer">&times;</button>';

            var removeBtn = tag.querySelector('.whitelist-remove');
            if (removeBtn) {
                removeBtn.addEventListener('click', function () {
                    var ipToRemove = this.dataset.ip;
                    SOCWebSocket.removeWhitelist(ipToRemove);
                });
            }

            whitelistContainer.appendChild(tag);
        });
    }

    // Also update stats handler to include IPS stats from periodic broadcast
    var _origHandleStats = handleStats;
    function handleStatsWithIPS(stats) {
        _origHandleStats(stats);
        // Si les stats contiennent des infos IPS, mettre à jour
        if (stats && stats.ips) {
            ipsStats = stats.ips;
            if (ipsActiveBlocks) ipsActiveBlocks.textContent = stats.ips.active_blocks || 0;
            if (ipsTotalBlocks) ipsTotalBlocks.textContent = stats.ips.total_blocks_db || stats.ips.total_blocks || 0;
            if (ipsTotalUnblocks) ipsTotalUnblocks.textContent = stats.ips.total_unblocks || 0;
            if (ipsWhitelistSize) ipsWhitelistSize.textContent = stats.ips.whitelist_size || 0;
            updateIPSBadge();
        }
    }

    // =========================================================================
    //  TIMELINE (chart)
    // =========================================================================

    function handleTimeline(data) {
        SOCCharts.updateTimeline(data);
    }

    // =========================================================================
    //  UTILITAIRES
    // =========================================================================

    function formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(n);
    }

    function formatTimestamp(ts) {
        if (!ts) return '-';
        if (typeof ts === 'string' && ts.length > 10) {
            try {
                var d = new Date(ts);
                if (!isNaN(d.getTime())) {
                    return String(d.getHours()).padStart(2, '0') + ':' +
                           String(d.getMinutes()).padStart(2, '0') + ':' +
                           String(d.getSeconds()).padStart(2, '0');
                }
            } catch (e) {}
        }
        return String(ts);
    }

    function formatTimestampFull(ts) {
        if (!ts) return '-';
        if (typeof ts === 'string' && ts.length > 10) {
            try {
                var d = new Date(ts);
                if (!isNaN(d.getTime())) {
                    return String(d.getFullYear()) + '-' +
                           String(d.getMonth() + 1).padStart(2, '0') + '-' +
                           String(d.getDate()).padStart(2, '0') + ' ' +
                           String(d.getHours()).padStart(2, '0') + ':' +
                           String(d.getMinutes()).padStart(2, '0') + ':' +
                           String(d.getSeconds()).padStart(2, '0');
                }
            } catch (e) {}
        }
        return String(ts);
    }

    function getLevelClass(level) {
        switch ((level || '').toUpperCase()) {
            case 'CRITICAL': return 'critical';
            case 'HIGH': return 'high';
            case 'WARNING': return 'warning';
            case 'INFO':
            default: return 'info';
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function truncate(str, max) {
        if (!str) return '';
        if (str.length <= max) return str;
        return str.substring(0, max) + '...';
    }

    // =========================================================================
    //  TOAST NOTIFICATION SYSTEM
    // =========================================================================

    function showToast(level, title, message, duration) {
        var container = document.getElementById('toast-container');
        if (!container) return;

        duration = duration || (level === 'critical' ? 8000 : 5000);

        var toast = document.createElement('div');
        toast.className = 'toast toast-' + level;

        var iconMap = { critical: '🚨', high: '⚠️', success: '✅', info: 'ℹ️' };

        toast.innerHTML =
            '<span class="toast-icon">' + (iconMap[level] || '🚨') + '</span>' +
            '<div class="toast-content">' +
                '<div class="toast-title">' + escapeHtml(title) + '</div>' +
                '<div class="toast-message">' + escapeHtml(message) + '</div>' +
            '</div>' +
            '<button class="toast-close">&times;</button>';

        // Close button
        toast.querySelector('.toast-close').addEventListener('click', function () {
            dismissToast(toast);
        });

        container.appendChild(toast);

        // Auto-dismiss
        var timer = setTimeout(function () {
            dismissToast(toast);
        }, duration);

        toast._timer = timer;

        // Max 5 toasts visible
        while (container.children.length > 5) {
            dismissToast(container.children[0]);
        }
    }

    function dismissToast(toast) {
        if (!toast || !toast.parentNode) return;
        if (toast._timer) clearTimeout(toast._timer);
        toast.classList.add('toast-out');
        setTimeout(function () {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 300);
    }

    // =========================================================================
    //  EXPORT CSV / JSON
    // =========================================================================

    /**
     * Génère la date formatée pour les noms de fichiers d'export.
     * Format : YYYY-MM-DD_HHmmss
     */
    function getExportDateString() {
        var d = new Date();
        return d.getFullYear() + '-' +
               String(d.getMonth() + 1).padStart(2, '0') + '-' +
               String(d.getDate()).padStart(2, '0') + '_' +
               String(d.getHours()).padStart(2, '0') +
               String(d.getMinutes()).padStart(2, '0') +
               String(d.getSeconds()).padStart(2, '0');
    }

    /**
     * Échappe une valeur pour inclusion dans un fichier CSV.
     * Gère les virgules, guillemets et retours à la ligne.
     */
    function csvEscape(value) {
        if (value === null || value === undefined) return '';
        var str = String(value);
        // Si contient virgule, guillemet ou retour à la ligne → entourer de guillemets
        if (str.indexOf(',') !== -1 || str.indexOf('"') !== -1 ||
            str.indexOf('\n') !== -1 || str.indexOf('\r') !== -1) {
            return '"' + str.replace(/"/g, '""') + '"';
        }
        return str;
    }

    /**
     * Télécharge un contenu texte sous forme de fichier.
     */
    function downloadFile(content, filename, mimeType) {
        try {
            var blob = new Blob([content], { type: mimeType });
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        } catch (e) {
            console.error('Erreur téléchargement fichier:', e);
        }
    }

    /**
     * Retourne les filtres actuellement appliqués (pour métadonnées export).
     */
    function getCurrentFilters() {
        return {
            level: (filterLevel && filterLevel.value) ? filterLevel.value : 'ALL',
            agent: (filterAgent && filterAgent.value) ? filterAgent.value : 'ALL',
            source: (filterSource && filterSource.value) ? filterSource.value : 'ALL',
            search: (filterSearch && filterSearch.value) ? filterSearch.value : ''
        };
    }

    /**
     * Export CSV — Exporte tous les logs actuellement affichés (après filtrage).
     * Colonnes : Timestamp, Agent, OS, Level, Source, Category, Message
     * Fichier : oktopus_logs_{date}.csv
     */
    function exportLogsCSV() {
        try {
            var filtered = allLogs.filter(matchesLogFilter);

            if (filtered.length === 0) {
                showToast('info', 'Export CSV', 'Aucun log à exporter');
                return;
            }

            // En-tête CSV
            var header = ['Timestamp', 'Agent', 'OS', 'Level', 'Source', 'Category', 'Message'];
            var lines = [header.join(',')];

            // Lignes de données
            filtered.forEach(function (log) {
                var row = [
                    csvEscape(log.timestamp || ''),
                    csvEscape(log.agent_id || ''),
                    csvEscape(log.agent_os || log.os || ''),
                    csvEscape((log.level || 'INFO').toUpperCase()),
                    csvEscape(log.source || ''),
                    csvEscape(log.category || ''),
                    csvEscape(log.message || log.raw || '')
                ];
                lines.push(row.join(','));
            });

            var csvContent = '\uFEFF' + lines.join('\r\n'); // BOM UTF-8 pour Excel
            var filename = 'oktopus_logs_' + getExportDateString() + '.csv';

            downloadFile(csvContent, filename, 'text/csv;charset=utf-8;');

            showToast('success', 'Export CSV réussi', filtered.length + ' logs exportés');
        } catch (e) {
            console.error('Erreur export CSV:', e);
            showToast('critical', 'Erreur Export', 'Échec de l\'export CSV : ' + e.message);
        }
    }

    /**
     * Export JSON — Exporte tous les logs actuellement affichés (après filtrage).
     * Format JSON pretty-print avec métadonnées.
     * Fichier : oktopus_logs_{date}.json
     */
    function exportLogsJSON() {
        try {
            var filtered = allLogs.filter(matchesLogFilter);

            if (filtered.length === 0) {
                showToast('info', 'Export JSON', 'Aucun log à exporter');
                return;
            }

            var filters = getCurrentFilters();

            var exportData = {
                export_date: new Date().toISOString(),
                total_logs: filtered.length,
                filters_applied: {
                    level: filters.level || 'ALL',
                    agent: filters.agent || 'ALL',
                    source: filters.source || 'ALL',
                    search: filters.search || ''
                },
                logs: filtered.map(function (log) {
                    return {
                        id: log.id || null,
                        timestamp: log.timestamp || '',
                        agent_id: log.agent_id || '',
                        agent_os: log.agent_os || log.os || '',
                        level: (log.level || 'INFO').toUpperCase(),
                        source: log.source || '',
                        category: log.category || '',
                        message: log.message || log.raw || ''
                    };
                })
            };

            var jsonContent = JSON.stringify(exportData, null, 2);
            var filename = 'oktopus_logs_' + getExportDateString() + '.json';

            downloadFile(jsonContent, filename, 'application/json;charset=utf-8;');

            showToast('success', 'Export JSON réussi', filtered.length + ' logs exportés');
        } catch (e) {
            console.error('Erreur export JSON:', e);
            showToast('critical', 'Erreur Export', 'Échec de l\'export JSON : ' + e.message);
        }
    }

    // =========================================================================
    //  LANCEMENT
    // =========================================================================

    document.addEventListener('DOMContentLoaded', init);

    // --- API publique ---
    return {
        resolveAlert: resolveAlert,
        switchTab: switchTab,
        closeDetail: closeDetail,
        showLogDetail: showLogDetail,
        showAlertDetail: showAlertDetail,
        showToast: showToast,
        unblockIP: function(actionId) { SOCWebSocket.unblockIP(actionId); },
        exportLogsCSV: exportLogsCSV,
        exportLogsJSON: exportLogsJSON
    };
})();
