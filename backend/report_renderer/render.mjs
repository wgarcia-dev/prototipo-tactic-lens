import puppeteer from 'puppeteer';
import { stdin, stdout } from 'node:process';

const chunks = [];
for await (const chunk of stdin) chunks.push(chunk);
const report = JSON.parse(Buffer.concat(chunks).toString('utf8'));
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function table(columns, rows) {
  if (!rows.length) return '';
  return '<table><thead><tr>'+columns.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(row=>'<tr>'+row.map(v=>'<td>'+esc(v)+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
}
function activityChart(counts) {
  const types = Object.entries(counts).sort((a,b) => b[1]-a[1]);
  const total = types.reduce((sum, [,n]) => sum+n, 0);
  if (!total) return '';
  const rows = types.map(([type,n]) => {
    const share = 100*n/total;
    return '<tr><td>'+esc(type)+'</td><td><div class="track"><i style="width:'+share+'%"></i></div></td><td>'+n+'</td><td>'+share.toLocaleString('es',{maximumFractionDigits:1})+' %</td></tr>';
  });
  const accepted = counts['cowrie.login.success'] || 0;
  const failed = counts['cowrie.login.failed'] || 0;
  return '<table><thead><tr><th>Tipo de evento</th><th>Proporción</th><th>Registros</th><th>% del total</th></tr></thead><tbody>'+rows.join('')+'</tbody></table><p>Autenticaciones registradas por Cowrie: '+accepted+' aceptadas y '+failed+' fallidas. Entradas de comandos: '+(counts['cowrie.command.input'] || 0)+'.</p>';
}
const sections = report.sections.map(s => {
  const chart = s.columns[0] === 'Tipo de evento' && report.event_counts ? activityChart(report.event_counts) : '';
  return '<section><h2>'+esc(s.title)+'</h2>'+s.paragraphs.map(p=>'<p>'+esc(p)+'</p>').join('')+(chart || table(s.columns,s.rows))+'</section>';
});
const html = `<!doctype html><html lang="es"><meta charset="utf-8"><title>${esc(report.title)}</title><style>
*{box-sizing:border-box}body{margin:0;color:#182e40;font:10pt/1.48 Arial,sans-serif}header{border-top:5pt solid #167678;padding-top:12pt}small{color:#27676d;font-weight:bold}h1{font:32pt/1.05 Georgia,serif;margin:14pt 0}h2{font:18pt Georgia,serif;border-bottom:1px solid #a8c0c4;padding-bottom:5pt;break-after:avoid}p{max-width:80ch;white-space:pre-line}dl{display:grid;grid-template-columns:1fr 1fr;gap:9pt;background:#eff5f5;padding:14pt}dt{color:#466570}dd{margin:0;font-weight:600}dd,td{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:9pt}th{text-align:left;background:#193f48;color:white}td,th{padding:4pt;vertical-align:top;border-bottom:1px solid #cad8da}tbody tr:nth-child(even){background:#f3f7f7}tr{break-inside:avoid}.track{height:7pt;min-width:70pt;background:#e1eded}.track i{display:block;height:100%;background:#167678}thead{display:table-header-group}p{orphans:2;widows:2}</style>
<header><small>TacticLens / Observatorio Cowrie</small><h1>${esc(report.title)}</h1><p>${esc(report.status)}</p></header><dl>${report.metadata.map(([k,v])=>'<div><dt>'+esc(k)+'</dt><dd>'+esc(v)+'</dd></div>').join('')}</dl>${sections.join('')}</html>`;
const browser = await puppeteer.launch({headless:'shell', pipe:true});
try {
  const page = await browser.newPage();
  await page.setJavaScriptEnabled(false);
  await page.setOfflineMode(true);
  await page.setContent(html);
  const pdf = await page.pdf({format:'A4',printBackground:true,displayHeaderFooter:true,headerTemplate:'<span></span>',footerTemplate:'<div style="width:100%;margin:0 17mm;font:8px Arial;color:#42616b">TacticLens · '+esc(report.reference)+' · <span class="pageNumber"></span> / <span class="totalPages"></span></div>',margin:{top:'17mm',bottom:'18mm',left:'17mm',right:'17mm'}});
  stdout.write(Buffer.from(pdf));
} finally { await browser.close(); }
