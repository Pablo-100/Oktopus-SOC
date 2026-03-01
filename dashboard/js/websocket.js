/*
=============================================================================
 Oktopus Dashboard — WebSocket Client
=============================================================================
 Fichier : dashboard/js/websocket.js
 Rôle    : Connexion WebSocket au serveur Oktopus (port 8765)
           Réception et dispatch des messages (logs, alertes, stats, agents)
           Reconnexion automatique avec backoff exponentiel
=============================================================================
*/

const SOCWebSocket = (function () {
    // --- Configuration ---
    const WS_URL = 'ws://localhost:8765';
    const RECONNECT_BASE = 1000;   // 1s
    const RECONNECT_MAX = 30000;   // 30s max
    let reconnectDelay = RECONNECT_BASE;
    let ws = null;
    let connected = false;

    // --- DOM refs ---
    const wsStatusEl = document.getElementById('ws-status');
    const wsTextEl = document.getElementById('ws-text');

    // --- Callbacks ---
    let onStatsUpdate = null;
    let onLogReceived = null;
    let onAlertReceived = null;
    let onAgentsUpdate = null;
    let onTimelineUpdate = null;
    let onAlertResolved = null;
    let onInitialLogs = null;
    let onInitialAlerts = null;
    let onIPSEvent = null;
    let onInitialIPS = null;
    let onAgentStats = null;
    let onInitialAgentStats = null;
    let onGeoEvent = null;
    let onInitialGeo = null;

    // --- Connexion ---
    function connect() {
        if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
            return;
        }

        ws = new WebSocket(WS_URL);

        ws.onopen = function () {
            connected = true;
            reconnectDelay = RECONNECT_BASE;
            updateStatus(true);
            console.log('[WS] Connecté au serveur SOC');
        };

        ws.onclose = function () {
            connected = false;
            updateStatus(false);
            console.log('[WS] Déconnecté — reconnexion dans ' + (reconnectDelay / 1000) + 's');
            scheduleReconnect();
        };

        ws.onerror = function (err) {
            console.error('[WS] Erreur:', err);
            ws.close();
        };

        ws.onmessage = function (event) {
            try {
                const msg = JSON.parse(event.data);
                handleMessage(msg);
            } catch (e) {
                console.error('[WS] Parse error:', e, event.data);
            }
        };
    }

    // --- Reconnexion avec backoff exponentiel ---
    function scheduleReconnect() {
        setTimeout(function () {
            console.log('[WS] Tentative de reconnexion...');
            connect();
            reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX);
        }, reconnectDelay);
    }

    // --- Mise à jour de l'indicateur de statut ---
    function updateStatus(isConnected) {
        if (!wsStatusEl) return;
        if (isConnected) {
            wsStatusEl.className = 'ws-status connected';
            if (wsTextEl) wsTextEl.textContent = 'CONNECTÉ';
        } else {
            wsStatusEl.className = 'ws-status disconnected';
            if (wsTextEl) wsTextEl.textContent = 'DÉCONNECTÉ';
        }
    }

    // --- Dispatch des messages reçus ---
    function handleMessage(msg) {
        switch (msg.type) {
            // --- Données initiales (format combiné legacy) ---
            case 'initial_data':
                if (msg.stats && onStatsUpdate) onStatsUpdate(msg.stats);
                if (msg.logs && onInitialLogs) onInitialLogs(msg.logs);
                if (msg.alerts && onInitialAlerts) onInitialAlerts(msg.alerts);
                if (msg.agents && onAgentsUpdate) onAgentsUpdate(msg.agents);
                if (msg.timeline && onTimelineUpdate) onTimelineUpdate(msg.timeline);
                break;

            // --- Stats globales (broadcast périodique) ---
            case 'stats':
                if (onStatsUpdate) onStatsUpdate(msg.data);
                break;

            // --- Logs initiaux envoyés à la connexion ---
            case 'initial_logs':
                if (onInitialLogs) onInitialLogs(msg.data);
                break;

            // --- Alertes initiales envoyées à la connexion ---
            case 'initial_alerts':
                if (onInitialAlerts) onInitialAlerts(msg.data);
                break;

            // --- Nouveau log (broadcast temps réel) ---
            case 'log':
            case 'new_log':
                if (onLogReceived) onLogReceived(msg.data);
                break;

            // --- Nouvelle alerte (broadcast temps réel) ---
            case 'alert':
            case 'new_alert':
                if (onAlertReceived) onAlertReceived(msg.data);
                break;

            // --- Mise à jour des agents ---
            case 'agents':
                if (onAgentsUpdate) onAgentsUpdate(msg.data);
                break;

            // --- Timeline mise à jour ---
            case 'timeline':
                if (onTimelineUpdate) onTimelineUpdate(msg.data);
                break;

            // --- Alerte résolue ---
            case 'alert_resolved':
                if (onAlertResolved) onAlertResolved(msg.data);
                break;

            // --- Logs filtrés (réponse à get_logs) ---
            case 'filtered_logs':
                if (onInitialLogs) onInitialLogs(msg.data);
                break;

            // --- IPS : données initiales ---
            case 'initial_ips':
            case 'ips_data':
                if (onInitialIPS) onInitialIPS(msg.data);
                break;

            // --- IPS : événement temps réel ---
            case 'ips_event':
                if (onIPSEvent) onIPSEvent(msg.data);
                break;

            // --- IPS : résultat déblocage ---
            case 'ips_unblock_result':
                if (onIPSEvent) onIPSEvent(msg.data);
                break;

            // --- Stats système d'un agent (temps réel) ---
            case 'agent_stats':
                if (onAgentStats) onAgentStats(msg.data);
                break;

            // --- Stats système initiales de tous les agents ---
            case 'initial_agent_stats':
                if (onInitialAgentStats) onInitialAgentStats(msg.data);
                break;

            // --- Geo-IP : événement temps réel ---
            case 'geo_event':
                if (onGeoEvent) onGeoEvent(msg.data);
                break;

            // --- Geo-IP : données initiales ---
            case 'initial_geo':
                if (onInitialGeo) onInitialGeo(msg.data);
                break;

            default:
                console.warn('[WS] Type de message inconnu:', msg.type);
        }
    }

    // --- Envoi de commandes au serveur ---
    function send(command) {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            console.error('[WS] Non connecté, impossible d\'envoyer la commande');
            return false;
        }
        ws.send(JSON.stringify(command));
        return true;
    }

    // --- Commande : résoudre une alerte ---
    function resolveAlert(alertId) {
        return send({
            command: 'resolve_alert',
            alert_id: alertId
        });
    }

    // --- Commande : demander les stats ---
    function requestStats() {
        return send({ command: 'get_stats' });
    }

    // --- Commande : demander les logs ---
    function requestLogs(limit) {
        return send({
            command: 'get_logs',
            limit: limit || 200
        });
    }

    // --- Commande : demander les agents ---
    function requestAgents() {
        return send({ command: 'get_agents' });
    }

    // --- Commande : demander la timeline ---
    function requestTimeline() {
        return send({ command: 'get_timeline' });
    }

    // --- Commande : débloquer une IP (IPS) ---
    function unblockIP(actionId, reason) {
        return send({
            command: 'unblock_ip',
            action_id: actionId,
            reason: reason || 'manual_dashboard'
        });
    }

    // --- Commande : activer/désactiver l'IPS ---
    function toggleIPS(enabled) {
        return send({
            command: 'toggle_ips',
            enabled: enabled
        });
    }

    // --- Commande : demander les données IPS ---
    function requestIPSData() {
        return send({ command: 'get_ips_data' });
    }

    // --- Commande : ajouter à la whitelist ---
    function addWhitelist(ip) {
        return send({
            command: 'add_whitelist',
            ip: ip
        });
    }

    // --- Commande : retirer de la whitelist ---
    function removeWhitelist(ip) {
        return send({
            command: 'remove_whitelist',
            ip: ip
        });
    }

    // --- Commande : demander les stats système des agents ---
    function requestAgentStats(agentId) {
        var cmd = { command: 'get_agent_stats' };
        if (agentId) cmd.agent_id = agentId;
        return send(cmd);
    }

    // --- Commande : demander les événements Geo-IP ---
    function requestGeoEvents() {
        return send({ command: 'get_geo_events' });
    }

    // --- API publique ---
    return {
        connect: connect,
        send: send,
        resolveAlert: resolveAlert,
        requestStats: requestStats,
        requestLogs: requestLogs,
        requestAgents: requestAgents,
        requestTimeline: requestTimeline,
        unblockIP: unblockIP,
        toggleIPS: toggleIPS,
        requestIPSData: requestIPSData,
        addWhitelist: addWhitelist,
        removeWhitelist: removeWhitelist,
        requestAgentStats: requestAgentStats,
        requestGeoEvents: requestGeoEvents,

        isConnected: function () { return connected; },

        // Enregistrement des callbacks
        onStats: function (cb) { onStatsUpdate = cb; },
        onLog: function (cb) { onLogReceived = cb; },
        onAlert: function (cb) { onAlertReceived = cb; },
        onAgents: function (cb) { onAgentsUpdate = cb; },
        onTimeline: function (cb) { onTimelineUpdate = cb; },
        onAlertResolved: function (cb) { onAlertResolved = cb; },
        onInitialLogs: function (cb) { onInitialLogs = cb; },
        onInitialAlerts: function (cb) { onInitialAlerts = cb; },
        onIPSEvent: function (cb) { onIPSEvent = cb; },
        onInitialIPS: function (cb) { onInitialIPS = cb; },
        onAgentStats: function (cb) { onAgentStats = cb; },
        onInitialAgentStats: function (cb) { onInitialAgentStats = cb; },
        onGeoEvent: function (cb) { onGeoEvent = cb; },
        onInitialGeo: function (cb) { onInitialGeo = cb; }
    };
})();
