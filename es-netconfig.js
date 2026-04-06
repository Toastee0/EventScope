// es-netconfig.js -- EventScope v5 -- Network configuration view
'use strict';

// S.netconfig = { adapters[], profiles[], loaded }

// ── PARSER ────────────────────────────────────────────────────────────────────

async function loadNetFile(file) {
    const text = (await file.text()).replace(/^\uFEFF/, '');
    const lines = text.split(/\r?\n/);
    if (!lines.length) return null;

    const headers = parseCSVLine(lines[0]);
    const ci = {};
    headers.forEach((h, i) => { ci[h.trim()] = i; });

    const g = (f, ...names) => {
        for (const n of names) if (n in ci) return (f[ci[n]] || '').trim();
        return '';
    };

    const rows = [];
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        const f = parseCSVLine(line);
        rows.push(f);
    }

    // Detect which file type by headers
    if ('IPAddress' in ci || 'DhcpServer' in ci) {
        return { type: 'adapters', ci, rows };
    }
    if ('DateCreated' in ci || 'DateLastConnected' in ci) {
        return { type: 'profiles', ci, rows };
    }
    return null;
}

async function loadNetconfigFile(file) {
    const result = await loadNetFile(file);
    if (!result) {
        showToast('Unrecognised file -- expected network-adapters.csv or network-profiles.csv');
        return;
    }

    if (!S.netconfig) S.netconfig = { adapters: [], profiles: [], loaded: false };

    const { type, ci, rows } = result;
    const g = (f, ...names) => {
        for (const n of names) if (n in ci) return (f[ci[n]] || '').trim();
        return '';
    };

    if (type === 'adapters') {
        S.netconfig.adapters = rows.map(f => ({
            name:            g(f, 'Name'),
            description:     g(f, 'Description'),
            ifType:          g(f, 'Type'),
            mac:             g(f, 'MAC'),
            status:          g(f, 'Status'),
            ip:              g(f, 'IPAddress'),
            prefix:          g(f, 'PrefixLength'),
            ipv6:            g(f, 'IPv6Address'),
            gateway:         g(f, 'Gateway'),
            dns:             g(f, 'DNS'),
            dhcpEnabled:     g(f, 'DHCPEnabled').toLowerCase() === 'true',
            dhcpServer:      g(f, 'DhcpServer'),
            networkHint:     g(f, 'DhcpNetworkHint'),
            leaseObtained:   g(f, 'LeaseObtained'),
            leaseExpires:    g(f, 'LeaseExpires'),
            regLastWrite:    g(f, 'RegLastWrite'),
        }));
        showToast('Loaded ' + S.netconfig.adapters.length + ' adapters');
    } else {
        S.netconfig.profiles = rows.map(f => ({
            profileName:       g(f, 'ProfileName'),
            description:       g(f, 'Description'),
            category:          g(f, 'Category'),
            type:              g(f, 'Type'),
            dateCreated:       g(f, 'DateCreated'),
            dateLastConnected: g(f, 'DateLastConnected'),
            gatewayMac:        g(f, 'DefaultGatewayMac'),
            managed:           g(f, 'Managed').toLowerCase() === 'true',
            regLastWrite:      g(f, 'RegLastWrite'),
        }));
        showToast('Loaded ' + S.netconfig.profiles.length + ' network profiles');
    }

    S.netconfig.loaded = S.netconfig.adapters.length > 0 || S.netconfig.profiles.length > 0;
    document.getElementById('netconfigDropzone').style.display = 'none';
    document.getElementById('netconfigContent').style.display = '';
    rNetconfig();
}

// ── RENDER ────────────────────────────────────────────────────────────────────

function rNetconfig() {
    if (!S.netconfig?.loaded) return;
    _renderAdapters();
    _renderProfiles();
    _updateNetconfigStatus();
}

function _updateNetconfigStatus() {
    const el = document.getElementById('netconfigStatus');
    if (!el) return;
    const parts = [];
    if (S.netconfig.adapters.length) parts.push(S.netconfig.adapters.length + ' adapters');
    if (S.netconfig.profiles.length) parts.push(S.netconfig.profiles.length + ' network profiles');
    el.textContent = parts.join(', ');
}

function _ifIcon(ifType) {
    if (!ifType) return '';
    const t = ifType.toLowerCase();
    if (t.includes('wireless') || t.includes('802.11') || t.includes('wifi')) return '( ) ';
    if (t.includes('ethernet') || t.includes('802.3'))  return '[=] ';
    if (t.includes('bluetooth'))                         return '[B] ';
    if (t.includes('loopback'))                          return '[L] ';
    return '';
}

function _renderAdapters() {
    const wrap = document.getElementById('netAdaptersWrap');
    if (!wrap) return;

    const adapters = S.netconfig.adapters;
    if (!adapters.length) {
        wrap.innerHTML = '<div style="color:var(--text-dim);font-family:var(--mono);font-size:12px;padding:16px">No adapter data loaded -- drop network-adapters.csv</div>';
        return;
    }

    // Active adapters first, then disconnected
    const sorted = [...adapters].sort((a, b) => {
        const aUp = a.status.toLowerCase() === 'up' ? 0 : 1;
        const bUp = b.status.toLowerCase() === 'up' ? 0 : 1;
        return aUp - bUp;
    });

    const rows = sorted.map(a => {
        const up      = a.status.toLowerCase() === 'up';
        const statusCls = up ? 'color:var(--success)' : 'color:var(--text-dim)';
        const ip      = a.ip ? a.ip + (a.prefix ? '/' + a.prefix : '') : '<span style="color:var(--text-dim)">--</span>';
        const gw      = a.gateway || '<span style="color:var(--text-dim)">--</span>';
        const dns     = a.dns     || '<span style="color:var(--text-dim)">--</span>';
        const dhcp    = a.dhcpEnabled
            ? '<span style="color:var(--info)">DHCP</span>'
            : '<span style="color:var(--warn)">Static</span>';
        const hint    = a.networkHint ? `<span style="color:var(--text-dim);font-size:11px">${eH(a.networkHint)}</span>` : '';
        const lease   = a.leaseObtained
            ? `<span style="color:var(--text-dim);font-size:11px">${eH(a.leaseObtained)} UTC &rarr; ${eH(a.leaseExpires)} UTC</span>`
            : '';
        const regWrite = a.regLastWrite
            ? `<span style="color:var(--text-dim);font-size:11px">${eH(a.regLastWrite)} UTC</span>`
            : '';

        return `<tr>
            <td style="font-weight:600">${eH(_ifIcon(a.ifType))}${eH(a.name)}</td>
            <td style="color:var(--text-dim)">${eH(a.description)}</td>
            <td style="${statusCls};font-weight:600">${eH(a.status)}</td>
            <td style="font-family:var(--mono)">${ip}</td>
            <td style="font-family:var(--mono)">${eH(a.ipv6) || '<span style="color:var(--text-dim)">--</span>'}</td>
            <td style="font-family:var(--mono)">${gw}</td>
            <td style="font-family:var(--mono);color:var(--text-dim)">${eH(a.mac)}</td>
            <td>${dhcp}</td>
            <td style="font-family:var(--mono);color:var(--text-dim)">${eH(a.dhcpServer) || '--'}</td>
            <td>${hint}</td>
            <td>${lease}</td>
            <td>${regWrite}</td>
        </tr>`;
    }).join('');

    wrap.innerHTML = `<table class="data-table">
        <thead><tr>
            <th>Adapter</th>
            <th>Hardware</th>
            <th>Status</th>
            <th>IPv4</th>
            <th>IPv6</th>
            <th>Gateway</th>
            <th>MAC</th>
            <th>Mode</th>
            <th>DHCP Server</th>
            <th>Network (hint)</th>
            <th>DHCP Lease</th>
            <th>Reg LastWrite</th>
        </tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}

function _renderProfiles() {
    const wrap = document.getElementById('netProfilesWrap');
    if (!wrap) return;

    const profiles = S.netconfig.profiles;
    if (!profiles.length) {
        wrap.innerHTML = '<div style="color:var(--text-dim);font-family:var(--mono);font-size:12px;padding:16px">No profile data loaded -- drop network-profiles.csv</div>';
        return;
    }

    // Sort by DateLastConnected desc
    const sorted = [...profiles].sort((a, b) => {
        const ta = a.dateLastConnected || a.dateCreated || '';
        const tb = b.dateLastConnected || b.dateCreated || '';
        return tb.localeCompare(ta);
    });

    // Find newest gateway MACs -- if a profile's gateway MAC appears in the SRUM
    // NetworkConnections that's a useful cross-reference, but for now just flag
    // profiles that have appeared more than once (same SSID, different MAC = roamed)
    const macsBySsid = {};
    sorted.forEach(p => {
        if (!macsBySsid[p.profileName]) macsBySsid[p.profileName] = new Set();
        if (p.gatewayMac) macsBySsid[p.profileName].add(p.gatewayMac);
    });

    const rows = sorted.map(p => {
        const typeIcon = p.type === 'Wireless' ? '( ) ' : p.type === 'Wired' ? '[=] ' : '';
        const catCls = p.category === 'Domain'  ? 'color:var(--warn);font-weight:600'
                     : p.category === 'Private' ? 'color:var(--info)'
                     : 'color:var(--text-dim)';
        const macCount = macsBySsid[p.profileName]?.size || 1;
        const macFlag  = macCount > 1
            ? `<span style="color:var(--warn);font-size:10px;margin-left:6px" title="${macCount} different gateway MACs for this SSID">${macCount} MACs</span>`
            : '';
        const managedFlag = p.managed
            ? '<span style="color:var(--warn);font-size:10px;margin-left:6px">MANAGED</span>'
            : '';

        return `<tr>
            <td style="font-weight:600">${typeIcon}${eH(p.profileName)}${managedFlag}</td>
            <td style="${catCls}">${eH(p.category)}</td>
            <td>${eH(p.type)}</td>
            <td style="font-family:var(--mono);color:var(--info)">${eH(p.dateCreated)}</td>
            <td style="font-family:var(--mono)">${eH(p.dateLastConnected)}</td>
            <td style="font-family:var(--mono);color:var(--text-dim)">${eH(p.gatewayMac)}${macFlag}</td>
            <td style="font-family:var(--mono);color:var(--text-dim);font-size:11px">${eH(p.regLastWrite)}</td>
        </tr>`;
    }).join('');

    wrap.innerHTML = `<table class="data-table">
        <thead><tr>
            <th>Network / SSID</th>
            <th>Category</th>
            <th>Type</th>
            <th>First Seen (UTC)</th>
            <th>Last Connected (UTC)</th>
            <th>Gateway MAC</th>
            <th>Reg LastWrite</th>
        </tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}
