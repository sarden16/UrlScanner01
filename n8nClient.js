export async function fetchScan(url, webhookUrl) {
  const endpoint = webhookUrl || import.meta.env.VITE_WEBHOOK_URL;
  if (!endpoint) throw new Error('VITE_WEBHOOK_URL is not defined');

  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => '');
    throw new Error(`Scan request failed: HTTP ${resp.status} ${text}`);
  }

  const data = await resp.json().catch(() => null);
  return data;
}