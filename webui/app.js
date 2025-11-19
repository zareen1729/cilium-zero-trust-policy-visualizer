async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch ' + url);
  return await res.json();
}

function renderPolicy(rules) {
  const tbody = document.querySelector('#policy-table tbody');
  tbody.innerHTML = '';
  for (const r of rules) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${r.src_ip}</td>
      <td>${r.dst_ip}</td>
      <td>${r.dst_port}</td>
      <td>${r.proto}</td>
      <td class="${r.action === 'allow' ? 'badge-allow' : 'badge-deny'}">${r.action}</td>
    `;
    tbody.appendChild(tr);
  }
}

function renderFlows(flows) {
  const tbody = document.querySelector('#flows-table tbody');
  tbody.innerHTML = '';
  for (const f of flows) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${f.src_ip}</td>
      <td>${f.dst_ip}</td>
      <td>${f.src_port}</td>
      <td>${f.dst_port}</td>
      <td>${f.proto}</td>
      <td>${f.allowed}</td>
      <td>${f.denied}</td>
    `;
    tbody.appendChild(tr);
  }
}

async function refresh() {
  try {
    const [rules, flows] = await Promise.all([
      fetchJSON('/api/policy'),
      fetchJSON('/api/flows')
    ]);
    renderPolicy(rules);
    renderFlows(flows);
  } catch (err) {
    console.error(err);
  }
}

setInterval(refresh, 3000);
refresh();
