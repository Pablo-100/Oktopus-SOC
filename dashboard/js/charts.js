/*
=============================================================================
 Oktopus Dashboard — Charts (Canvas API)
=============================================================================
 Fichier : dashboard/js/charts.js
 Rôle    : 1) Graphique timeline 24h (Logs / Alertes)
           2) Carte monde Geo-IP (Canvas Mercator)
           3) Graphique MITRE ATT&CK (barres horizontales)
           Tout en Canvas API natif — 0 librairie externe
=============================================================================
*/

const SOCCharts = (function () {

    // =====================================================================
    //  1. TIMELINE CHART
    // =====================================================================
    let canvas = null;
    let ctx = null;
    let timelineData = [];

    const COLORS = {
        bg: 'rgba(17, 25, 50, 0.0)',
        grid: 'rgba(30, 58, 95, 0.3)',
        axis: '#64748b',
        labelText: '#94a3b8',
        logLine: '#00d4ff',
        logFill: 'rgba(0, 212, 255, 0.08)',
        alertLine: '#ff4757',
        alertFill: 'rgba(255, 71, 87, 0.08)',
        tooltip: '#e2e8f0'
    };

    function init(canvasId) {
        canvas = document.getElementById(canvasId);
        if (!canvas) {
            console.error('[Charts] Canvas introuvable:', canvasId);
            return;
        }
        ctx = canvas.getContext('2d');
        resizeCanvas();
        window.addEventListener('resize', function () {
            resizeCanvas();
            resizeMapCanvas();
            resizeMitreCanvas();
        });
        canvas.addEventListener('mousemove', handleMouseMove);
        canvas.addEventListener('mouseleave', handleMouseLeave);

        // Init map & MITRE
        initMap('geo-map-canvas');
        initMitre('mitre-chart-canvas');
    }

    function resizeCanvas() {
        if (!canvas) return;
        const rect = canvas.parentElement.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        canvas.width = rect.width * dpr;
        canvas.height = 250 * dpr;
        canvas.style.width = rect.width + 'px';
        canvas.style.height = '250px';
        ctx.scale(dpr, dpr);
        draw();
    }

    function updateTimeline(data) {
        if (!data || !Array.isArray(data)) return;
        timelineData = data;
        draw();
    }

    function draw() {
        if (!ctx || !canvas) return;
        const w = canvas.clientWidth;
        const h = canvas.clientHeight;
        const margin = { top: 20, right: 20, bottom: 40, left: 50 };
        const chartW = w - margin.left - margin.right;
        const chartH = h - margin.top - margin.bottom;
        ctx.clearRect(0, 0, w, h);

        if (timelineData.length === 0) {
            drawEmptyState(w, h);
            return;
        }

        let maxVal = 0;
        timelineData.forEach(function (d) {
            maxVal = Math.max(maxVal, d.logs || d.count || 0, d.alerts || 0);
        });
        if (maxVal === 0) maxVal = 1;
        maxVal = Math.ceil(maxVal * 1.15);

        drawGrid(margin, chartW, chartH, maxVal);
        drawAxes(margin, chartW, chartH, maxVal);
        drawCurve(margin, chartW, chartH, maxVal, 'logs', COLORS.logLine, COLORS.logFill);
        drawCurve(margin, chartW, chartH, maxVal, 'alerts', COLORS.alertLine, COLORS.alertFill);
        drawLegend(w, margin);
    }

    function drawEmptyState(w, h) {
        ctx.font = '13px JetBrains Mono, monospace';
        ctx.fillStyle = COLORS.labelText;
        ctx.textAlign = 'center';
        ctx.fillText('En attente de données...', w / 2, h / 2);
    }

    function drawGrid(margin, chartW, chartH, maxVal) {
        const steps = 5;
        ctx.strokeStyle = COLORS.grid;
        ctx.lineWidth = 0.5;
        for (let i = 0; i <= steps; i++) {
            const y = margin.top + chartH - (chartH / steps) * i;
            ctx.beginPath();
            ctx.moveTo(margin.left, y);
            ctx.lineTo(margin.left + chartW, y);
            ctx.stroke();
            const val = Math.round((maxVal / steps) * i);
            ctx.fillStyle = COLORS.labelText;
            ctx.font = '10px JetBrains Mono, monospace';
            ctx.textAlign = 'right';
            ctx.fillText(val.toString(), margin.left - 8, y + 3);
        }
    }

    function drawAxes(margin, chartW, chartH) {
        ctx.fillStyle = COLORS.labelText;
        ctx.font = '10px JetBrains Mono, monospace';
        ctx.textAlign = 'center';
        const step = Math.max(1, Math.floor(timelineData.length / 12));
        timelineData.forEach(function (d, i) {
            if (i % step !== 0 && i !== timelineData.length - 1) return;
            const x = margin.left + (i / (timelineData.length - 1 || 1)) * chartW;
            ctx.fillText(extractHour(d.hour), x, margin.top + chartH + 20);
        });
    }

    function drawCurve(margin, chartW, chartH, maxVal, key, lineColor, fillColor) {
        if (timelineData.length < 2) return;
        const points = [];
        timelineData.forEach(function (d, i) {
            const val = (key === 'logs') ? (d.logs || d.count || 0) : (d[key] || 0);
            points.push({
                x: margin.left + (i / (timelineData.length - 1)) * chartW,
                y: margin.top + chartH - (val / maxVal) * chartH
            });
        });

        ctx.beginPath();
        ctx.moveTo(points[0].x, margin.top + chartH);
        points.forEach(function (p) { ctx.lineTo(p.x, p.y); });
        ctx.lineTo(points[points.length - 1].x, margin.top + chartH);
        ctx.closePath();
        ctx.fillStyle = fillColor;
        ctx.fill();

        ctx.beginPath();
        ctx.moveTo(points[0].x, points[0].y);
        for (let i = 1; i < points.length; i++) {
            const xc = (points[i - 1].x + points[i].x) / 2;
            const yc = (points[i - 1].y + points[i].y) / 2;
            ctx.quadraticCurveTo(points[i - 1].x, points[i - 1].y, xc, yc);
        }
        ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
        ctx.strokeStyle = lineColor;
        ctx.lineWidth = 2;
        ctx.stroke();

        points.forEach(function (p) {
            ctx.beginPath();
            ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
            ctx.fillStyle = lineColor;
            ctx.fill();
        });
    }

    function drawLegend(w, margin) {
        const y = margin.top + 2;
        ctx.font = '11px JetBrains Mono, monospace';
        ctx.fillStyle = COLORS.logLine;
        ctx.fillRect(w - 180, y - 4, 12, 3);
        ctx.fillStyle = COLORS.labelText;
        ctx.textAlign = 'left';
        ctx.fillText('Logs', w - 164, y);
        ctx.fillStyle = COLORS.alertLine;
        ctx.fillRect(w - 100, y - 4, 12, 3);
        ctx.fillStyle = COLORS.labelText;
        ctx.fillText('Alertes', w - 84, y);
    }

    let tooltipIndex = -1;

    function handleMouseMove(e) {
        if (!canvas || timelineData.length === 0) return;
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const margin = { top: 20, right: 20, bottom: 40, left: 50 };
        const chartW = canvas.clientWidth - margin.left - margin.right;
        const ratio = (mx - margin.left) / chartW;
        const idx = Math.round(ratio * (timelineData.length - 1));
        if (idx >= 0 && idx < timelineData.length && idx !== tooltipIndex) {
            tooltipIndex = idx;
            draw();
            drawTooltip(idx, margin, chartW);
        }
    }

    function handleMouseLeave() {
        tooltipIndex = -1;
        draw();
    }

    function drawTooltip(idx, margin, chartW) {
        const d = timelineData[idx];
        const logs = d.logs || d.count || 0;
        const alerts = d.alerts || 0;
        const x = margin.left + (idx / (timelineData.length - 1 || 1)) * chartW;

        ctx.strokeStyle = 'rgba(226, 232, 240, 0.2)';
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(x, margin.top);
        ctx.lineTo(x, canvas.clientHeight - margin.bottom);
        ctx.stroke();
        ctx.setLineDash([]);

        const label = extractHour(d.hour);
        const text1 = 'Logs: ' + logs;
        const text2 = 'Alertes: ' + alerts;
        ctx.font = '11px JetBrains Mono, monospace';
        const tw = Math.max(ctx.measureText(label).width, ctx.measureText(text1).width, ctx.measureText(text2).width) + 20;
        const th = 56;
        let tx = x + 10;
        if (tx + tw > canvas.clientWidth) tx = x - tw - 10;
        const ty = margin.top + 10;

        ctx.fillStyle = 'rgba(17, 24, 39, 0.95)';
        ctx.strokeStyle = COLORS.grid;
        ctx.lineWidth = 1;
        roundRect(ctx, tx, ty, tw, th, 6);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = COLORS.tooltip;
        ctx.textAlign = 'left';
        ctx.fillText(label, tx + 10, ty + 16);
        ctx.fillStyle = COLORS.logLine;
        ctx.fillText(text1, tx + 10, ty + 32);
        ctx.fillStyle = COLORS.alertLine;
        ctx.fillText(text2, tx + 10, ty + 48);
    }

    // =====================================================================
    //  2. GEO-IP WORLD MAP (Canvas Mercator)
    // =====================================================================
    let mapCanvas = null;
    let mapCtx = null;
    let geoEvents = [];
    let mapAnimFrame = null;
    let mapHoverEvent = null;

    // Simplified continent polygons (lon, lat pairs)
    const CONTINENTS = [
        // North America
        [[-130,50],[-125,60],[-100,65],[-80,60],[-60,50],[-70,30],[-85,10],[-105,18],[-118,33],[-130,50]],
        // South America
        [[-80,10],[-60,5],[-35,-5],[-35,-20],[-50,-30],[-55,-40],[-70,-55],[-75,-20],[-80,0],[-80,10]],
        // Europe
        [[-10,36],[0,43],[5,48],[10,55],[25,60],[35,70],[40,60],[30,45],[25,35],[10,36],[-10,36]],
        // Africa
        [[-15,35],[-17,15],[-5,5],[10,5],[15,-5],[30,-15],[40,-25],[35,-35],[20,-35],[12,-20],[10,0],[5,5],[-5,5],[-15,10],[-15,35]],
        // Asia
        [[25,35],[40,40],[50,45],[60,55],[80,60],[100,65],[130,55],[145,50],[140,35],[120,25],[105,10],[95,10],[80,15],[70,25],[55,25],[40,30],[25,35]],
        // Oceania / Australia
        [[115,-10],[130,-12],[150,-15],[155,-25],[150,-35],[135,-35],[115,-30],[113,-22],[115,-10]],
        // Greenland
        [[-55,60],[-45,62],[-20,70],[-20,80],[-40,82],[-55,78],[-55,60]],
        // Indonesia (simplified)
        [[95,5],[110,2],[120,-2],[130,-5],[140,-6],[135,-8],[120,-8],[105,-7],[95,-2],[95,5]],
        // Japan (simplified)
        [[130,31],[132,34],[136,36],[140,40],[142,44],[145,44],[141,38],[140,35],[136,34],[130,31]]
    ];

    const SEVERITY_COLORS = {
        'CRITICAL': '#ff4444',
        'HIGH': '#ff8c00',
        'MEDIUM': '#ffcc00',
        'LOW': '#00d4ff'
    };

    function initMap(canvasId) {
        mapCanvas = document.getElementById(canvasId);
        if (!mapCanvas) return;
        mapCtx = mapCanvas.getContext('2d');
        resizeMapCanvas();
        mapCanvas.addEventListener('mousemove', handleMapMouseMove);
        mapCanvas.addEventListener('mouseleave', handleMapMouseLeave);
        startMapAnimation();
    }

    function resizeMapCanvas() {
        if (!mapCanvas) return;
        const rect = mapCanvas.parentElement.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        const h = 350;
        mapCanvas.width = rect.width * dpr;
        mapCanvas.height = h * dpr;
        mapCanvas.style.width = rect.width + 'px';
        mapCanvas.style.height = h + 'px';
        mapCtx.scale(dpr, dpr);
    }

    // Mercator projection
    function lonToX(lon, w, pad) {
        return pad + ((lon + 180) / 360) * (w - 2 * pad);
    }
    function latToY(lat, h, pad) {
        const latRad = lat * Math.PI / 180;
        const mercN = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
        const yNorm = (1 - mercN / Math.PI) / 2;
        return pad + yNorm * (h - 2 * pad);
    }

    function drawMap() {
        if (!mapCtx || !mapCanvas) return;
        const w = mapCanvas.clientWidth;
        const h = mapCanvas.clientHeight;
        const pad = 15;

        mapCtx.clearRect(0, 0, w, h);

        // Background
        mapCtx.fillStyle = '#0a0e1a';
        mapCtx.fillRect(0, 0, w, h);

        // Grid lines (latitude/longitude)
        mapCtx.strokeStyle = 'rgba(30, 58, 95, 0.2)';
        mapCtx.lineWidth = 0.5;
        for (let lon = -180; lon <= 180; lon += 30) {
            const x = lonToX(lon, w, pad);
            mapCtx.beginPath();
            mapCtx.moveTo(x, pad);
            mapCtx.lineTo(x, h - pad);
            mapCtx.stroke();
        }
        for (let lat = -60; lat <= 80; lat += 20) {
            const y = latToY(lat, h, pad);
            mapCtx.beginPath();
            mapCtx.moveTo(pad, y);
            mapCtx.lineTo(w - pad, y);
            mapCtx.stroke();
        }

        // Draw continents
        mapCtx.fillStyle = 'rgba(30, 58, 95, 0.35)';
        mapCtx.strokeStyle = 'rgba(0, 212, 255, 0.2)';
        mapCtx.lineWidth = 1;
        CONTINENTS.forEach(function (poly) {
            mapCtx.beginPath();
            poly.forEach(function (p, i) {
                const x = lonToX(p[0], w, pad);
                const y = latToY(p[1], h, pad);
                if (i === 0) mapCtx.moveTo(x, y);
                else mapCtx.lineTo(x, y);
            });
            mapCtx.closePath();
            mapCtx.fill();
            mapCtx.stroke();
        });

        // Draw attack dots
        const now = Date.now();
        geoEvents.forEach(function (ev) {
            if (ev.lat == null || ev.lon == null) return;
            const x = lonToX(ev.lon, w, pad);
            const y = latToY(ev.lat, h, pad);
            const color = SEVERITY_COLORS[(ev.severity || '').toUpperCase()] || '#ffcc00';
            const evTime = ev.timestamp ? new Date(ev.timestamp).getTime() : 0;
            const age = now - evTime;
            const isRecent = age < 300000; // < 5 min

            // Pulse ring for recent attacks
            if (isRecent) {
                const pulse = (now % 2000) / 2000; // 0..1 cycle
                const pulseR = 5 + pulse * 18;
                const pulseAlpha = 0.6 * (1 - pulse);
                mapCtx.beginPath();
                mapCtx.arc(x, y, pulseR, 0, Math.PI * 2);
                mapCtx.strokeStyle = color.replace(')', ',' + pulseAlpha + ')').replace('rgb', 'rgba').replace('#', '');
                // Hex to rgba for pulse
                mapCtx.strokeStyle = hexToRgba(color, pulseAlpha);
                mapCtx.lineWidth = 1.5;
                mapCtx.stroke();
            }

            // Dot with glow
            mapCtx.beginPath();
            mapCtx.arc(x, y, isRecent ? 5 : 3.5, 0, Math.PI * 2);
            mapCtx.fillStyle = color;
            mapCtx.shadowColor = color;
            mapCtx.shadowBlur = isRecent ? 12 : 6;
            mapCtx.fill();
            mapCtx.shadowBlur = 0;
        });

        // Draw tooltip if hovering
        if (mapHoverEvent) {
            drawMapTooltip(mapHoverEvent, w, h, pad);
        }

        // Legend
        drawMapLegend(w, h);
    }

    function hexToRgba(hex, alpha) {
        hex = hex.replace('#', '');
        const r = parseInt(hex.substring(0, 2), 16);
        const g = parseInt(hex.substring(2, 4), 16);
        const b = parseInt(hex.substring(4, 6), 16);
        return 'rgba(' + r + ',' + g + ',' + b + ',' + alpha + ')';
    }

    function drawMapLegend(w, h) {
        const legendX = w - 160;
        const legendY = h - 70;
        mapCtx.fillStyle = 'rgba(10, 14, 26, 0.85)';
        roundRect(mapCtx, legendX, legendY, 145, 60, 6);
        mapCtx.fill();
        mapCtx.strokeStyle = 'rgba(30, 58, 95, 0.5)';
        mapCtx.lineWidth = 1;
        mapCtx.stroke();

        mapCtx.font = '9px JetBrains Mono, monospace';
        mapCtx.textAlign = 'left';
        const items = [
            { label: 'CRITICAL', color: '#ff4444' },
            { label: 'HIGH', color: '#ff8c00' },
            { label: 'MEDIUM', color: '#ffcc00' },
            { label: 'LOW', color: '#00d4ff' }
        ];
        items.forEach(function (item, i) {
            const iy = legendY + 12 + i * 12;
            mapCtx.beginPath();
            mapCtx.arc(legendX + 12, iy, 3, 0, Math.PI * 2);
            mapCtx.fillStyle = item.color;
            mapCtx.fill();
            mapCtx.fillStyle = '#94a3b8';
            mapCtx.fillText(item.label, legendX + 22, iy + 3);
        });
    }

    function drawMapTooltip(ev, w, h, pad) {
        const x = lonToX(ev.lon, w, pad);
        const y = latToY(ev.lat, h, pad);

        const flag = ev.flag || '';
        const lines = [
            (flag ? flag + ' ' : '') + (ev.country || 'Inconnu'),
            ev.city || '',
            'IP: ' + (ev.ip || '??'),
            'Type: ' + (ev.alert_type || '??'),
            'Sévérité: ' + (ev.severity || '??')
        ].filter(function(l) { return l.length > 0; });

        mapCtx.font = '10px JetBrains Mono, monospace';
        let maxTw = 0;
        lines.forEach(function (l) {
            maxTw = Math.max(maxTw, mapCtx.measureText(l).width);
        });
        const tw = maxTw + 20;
        const th = lines.length * 14 + 12;
        let tx = x + 12;
        let ty = y - th - 5;
        if (tx + tw > w) tx = x - tw - 12;
        if (ty < 5) ty = y + 12;

        mapCtx.fillStyle = 'rgba(17, 24, 39, 0.95)';
        mapCtx.strokeStyle = 'rgba(0, 212, 255, 0.3)';
        mapCtx.lineWidth = 1;
        roundRect(mapCtx, tx, ty, tw, th, 6);
        mapCtx.fill();
        mapCtx.stroke();

        mapCtx.fillStyle = '#e2e8f0';
        mapCtx.textAlign = 'left';
        lines.forEach(function (l, i) {
            mapCtx.fillText(l, tx + 10, ty + 14 + i * 14);
        });
    }

    function handleMapMouseMove(e) {
        if (!mapCanvas || geoEvents.length === 0) return;
        const rect = mapCanvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const w = mapCanvas.clientWidth;
        const h = mapCanvas.clientHeight;
        const pad = 15;

        let closest = null;
        let closestDist = Infinity;
        geoEvents.forEach(function (ev) {
            if (ev.lat == null || ev.lon == null) return;
            const x = lonToX(ev.lon, w, pad);
            const y = latToY(ev.lat, h, pad);
            const dist = Math.sqrt((mx - x) * (mx - x) + (my - y) * (my - y));
            if (dist < 15 && dist < closestDist) {
                closestDist = dist;
                closest = ev;
            }
        });
        mapHoverEvent = closest;
        mapCanvas.style.cursor = closest ? 'pointer' : 'default';
    }

    function handleMapMouseLeave() {
        mapHoverEvent = null;
        if (mapCanvas) mapCanvas.style.cursor = 'default';
    }

    function startMapAnimation() {
        function loop() {
            drawMap();
            mapAnimFrame = requestAnimationFrame(loop);
        }
        loop();
    }

    function addGeoEvent(data) {
        if (!data) return;
        geoEvents.unshift(data);
        if (geoEvents.length > 500) geoEvents = geoEvents.slice(0, 500);
    }

    function setGeoEvents(events) {
        if (!Array.isArray(events)) return;
        geoEvents = events;
    }


    // =====================================================================
    //  3. MITRE ATT&CK BAR CHART (horizontal)
    // =====================================================================
    let mitreCanvas = null;
    let mitreCtx = null;
    let mitreTacticCounts = {};

    // MITRE ATT&CK kill chain order
    const MITRE_TACTICS_ORDER = [
        'Reconnaissance',
        'Resource Development',
        'Initial Access',
        'Execution',
        'Persistence',
        'Privilege Escalation',
        'Defense Evasion',
        'Credential Access',
        'Discovery',
        'Lateral Movement',
        'Collection',
        'Command and Control',
        'Exfiltration',
        'Impact'
    ];

    const MITRE_COLORS = {
        low:  '#2ed573',   // green < 3
        mid:  '#ffa502',   // orange < 7
        high: '#ff4757'    // red >= 7
    };

    function initMitre(canvasId) {
        mitreCanvas = document.getElementById(canvasId);
        if (!mitreCanvas) return;
        mitreCtx = mitreCanvas.getContext('2d');
        resizeMitreCanvas();
        mitreCanvas.addEventListener('mousemove', handleMitreMouseMove);
        mitreCanvas.addEventListener('mouseleave', handleMitreMouseLeave);
    }

    let mitreHoverIndex = -1;

    function resizeMitreCanvas() {
        if (!mitreCanvas) return;
        const rect = mitreCanvas.parentElement.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        const numTactics = MITRE_TACTICS_ORDER.length;
        const h = Math.max(300, numTactics * 28 + 50);
        mitreCanvas.width = rect.width * dpr;
        mitreCanvas.height = h * dpr;
        mitreCanvas.style.width = rect.width + 'px';
        mitreCanvas.style.height = h + 'px';
        mitreCtx.scale(dpr, dpr);
        drawMitre();
    }

    function updateMitreChart(alerts) {
        if (!Array.isArray(alerts)) return;
        mitreTacticCounts = {};
        alerts.forEach(function (a) {
            const tactic = a.mitre_tactic || '';
            if (tactic) {
                mitreTacticCounts[tactic] = (mitreTacticCounts[tactic] || 0) + 1;
            }
        });
        drawMitre();
    }

    function drawMitre() {
        if (!mitreCtx || !mitreCanvas) return;
        const w = mitreCanvas.clientWidth;
        const h = mitreCanvas.clientHeight;
        mitreCtx.clearRect(0, 0, w, h);

        const labelW = 150;
        const pad = { top: 10, right: 50, bottom: 10, left: labelW + 10 };
        const barAreaW = w - pad.left - pad.right;
        const barH = 18;
        const barGap = 8;
        const numTactics = MITRE_TACTICS_ORDER.length;

        // Find max count
        let maxCount = 0;
        MITRE_TACTICS_ORDER.forEach(function (t) {
            maxCount = Math.max(maxCount, mitreTacticCounts[t] || 0);
        });
        if (maxCount === 0) maxCount = 1;

        // Check if empty
        const totalCount = Object.values(mitreTacticCounts).reduce(function (s, v) { return s + v; }, 0);
        if (totalCount === 0) {
            mitreCtx.font = '13px JetBrains Mono, monospace';
            mitreCtx.fillStyle = COLORS.labelText;
            mitreCtx.textAlign = 'center';
            mitreCtx.fillText('En attente d\'alertes MITRE ATT&CK...', w / 2, h / 2);
            return;
        }

        MITRE_TACTICS_ORDER.forEach(function (tactic, i) {
            const count = mitreTacticCounts[tactic] || 0;
            const y = pad.top + i * (barH + barGap);

            // Tactic label
            mitreCtx.font = '10px JetBrains Mono, monospace';
            mitreCtx.fillStyle = (mitreHoverIndex === i) ? '#e2e8f0' : '#94a3b8';
            mitreCtx.textAlign = 'right';
            const displayLabel = tactic.length > 20 ? tactic.substring(0, 18) + '..' : tactic;
            mitreCtx.fillText(displayLabel, pad.left - 8, y + barH / 2 + 4);

            // Bar background
            mitreCtx.fillStyle = 'rgba(30, 58, 95, 0.2)';
            roundRect(mitreCtx, pad.left, y, barAreaW, barH, 4);
            mitreCtx.fill();

            if (count > 0) {
                // Bar fill
                const barW = Math.max(4, (count / maxCount) * barAreaW);
                const color = count < 3 ? MITRE_COLORS.low : (count < 7 ? MITRE_COLORS.mid : MITRE_COLORS.high);

                // Gradient
                const grad = mitreCtx.createLinearGradient(pad.left, 0, pad.left + barW, 0);
                grad.addColorStop(0, hexToRgba(color, 0.8));
                grad.addColorStop(1, color);
                mitreCtx.fillStyle = grad;
                roundRect(mitreCtx, pad.left, y, barW, barH, 4);
                mitreCtx.fill();

                // Glow on hover
                if (mitreHoverIndex === i) {
                    mitreCtx.shadowColor = color;
                    mitreCtx.shadowBlur = 8;
                    roundRect(mitreCtx, pad.left, y, barW, barH, 4);
                    mitreCtx.fill();
                    mitreCtx.shadowBlur = 0;
                }

                // Count text
                mitreCtx.font = '10px JetBrains Mono, monospace';
                mitreCtx.fillStyle = '#e2e8f0';
                mitreCtx.textAlign = 'left';
                mitreCtx.fillText(count.toString(), pad.left + barW + 6, y + barH / 2 + 4);
            }
        });
    }

    function handleMitreMouseMove(e) {
        if (!mitreCanvas) return;
        const rect = mitreCanvas.getBoundingClientRect();
        const my = e.clientY - rect.top;
        const barH = 18;
        const barGap = 8;
        const pad = { top: 10 };
        const idx = Math.floor((my - pad.top) / (barH + barGap));
        if (idx >= 0 && idx < MITRE_TACTICS_ORDER.length && idx !== mitreHoverIndex) {
            mitreHoverIndex = idx;
            drawMitre();
        } else if (idx < 0 || idx >= MITRE_TACTICS_ORDER.length) {
            mitreHoverIndex = -1;
            drawMitre();
        }
    }

    function handleMitreMouseLeave() {
        mitreHoverIndex = -1;
        drawMitre();
    }

    // =====================================================================
    //  UTILS
    // =====================================================================
    function roundRect(c, x, y, w, h, r) {
        c.beginPath();
        c.moveTo(x + r, y);
        c.lineTo(x + w - r, y);
        c.arcTo(x + w, y, x + w, y + r, r);
        c.lineTo(x + w, y + h - r);
        c.arcTo(x + w, y + h, x + w - r, y + h, r);
        c.lineTo(x + r, y + h);
        c.arcTo(x, y + h, x, y + h - r, r);
        c.lineTo(x, y + r);
        c.arcTo(x, y, x + r, y, r);
        c.closePath();
    }

    function extractHour(hourStr) {
        if (!hourStr) return '??';
        const parts = hourStr.split(' ');
        if (parts.length >= 2) return parts[1].replace(':00', 'h');
        return hourStr;
    }

    // =====================================================================
    //  PUBLIC API
    // =====================================================================
    return {
        init: init,
        updateTimeline: updateTimeline,
        refresh: draw,
        // Geo-IP
        addGeoEvent: addGeoEvent,
        setGeoEvents: setGeoEvents,
        // MITRE
        updateMitreChart: updateMitreChart
    };
})();
