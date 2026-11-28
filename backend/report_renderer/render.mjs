import puppeteer from 'puppeteer';
import { stdin, stdout } from 'node:process';

const chunks = [];
for await (const chunk of stdin) chunks.push(chunk);
const report = JSON.parse(Buffer.concat(chunks).toString('utf8'));
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function table(columns, rows) {
  if (!rows.length) return '';
  return '<table><thead><tr>'+columns.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr></thead><tbody>'+rows.map(row=>'<tr>'+row.map(v=>'<td>'+esc(v).replace(/\r?\n/g,'<br>')+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
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
const sections = report.sections.map((s,index) => {
  const chart = s.columns[0] === 'Tipo de evento' && report.event_counts ? activityChart(report.event_counts) : '';
  return '<section id="section-'+index+'" class="'+esc(s.kind || 'evidence')+'"><h2>'+esc(s.title)+'</h2>'+s.paragraphs.map(p=>'<p>'+esc(p)+'</p>').join('')+(chart || table(s.columns,s.rows))+'</section>';
});
const html = `<!doctype html><html lang="es"><meta charset="utf-8"><title>${esc(report.title)}</title><style>
*{box-sizing:border-box}body{margin:0;color:#203447;font:10.5pt/1.6 Arial,sans-serif}header{border-top:6pt solid #137c80;padding:20pt 0 14pt}small{color:#137c80;font-size:9pt;font-weight:bold;letter-spacing:1.2pt;text-transform:uppercase}h1{font:30pt/1.12 Georgia,serif;color:#102d40;margin:18pt 0 12pt;max-width:17ch}h2{font:18pt/1.25 Georgia,serif;color:#102d40;margin:24pt 0 12pt;border-bottom:1px solid #b6cbd0;padding-bottom:7pt;break-after:avoid}p{white-space:pre-line;margin:9pt 0;orphans:3;widows:3}dl{display:grid;grid-template-columns:1fr 1fr;gap:12pt;background:#edf4f5;padding:16pt;margin:12pt 0 20pt;border-left:3pt solid #137c80;font-size:9pt}dt{color:#4d6977;font-size:8pt;text-transform:uppercase;letter-spacing:.4pt}dd{margin:3pt 0 0;font-weight:600}dd,td{overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;font-size:9pt;line-height:1.5;margin:12pt 0}th{text-align:left;background:#153b4b;color:white}td,th{padding:7pt;vertical-align:top;border:1px solid #d2dfe2}tbody tr:nth-child(even){background:#f2f6f7}tr{break-inside:avoid}.track{height:7pt;min-width:65pt;background:#e1eded}.track i{display:block;height:100%;background:#167678}thead{display:table-header-group}.executive{background:#edf5f3;border-left:3pt solid #198478;padding:1pt 14pt 10pt;margin:18pt 0}.executive h2{margin-top:14pt}.finding{border-left:2pt solid #9ebcc4;padding-left:13pt}.finding h2{font: bold 13pt/1.4 Arial,sans-serif}.response h2{font:bold 13pt/1.4 Arial,sans-serif}.subtitle{font:14pt Georgia,serif;color:#42616b}.status{font-size:9pt;color:#416773}h2,th{print-color-adjust:exact}a{color:#137c80}</style>
<header><small>TacticLens / Inteligencia y respuesta</small><h1>${esc(report.title)}</h1><p class="subtitle">${esc(report.subtitle || '')}</p><p class="status">${esc(report.status)} · Uso restringido al equipo de seguridad</p></header><dl>${report.metadata.map(([k,v])=>'<div><dt>'+esc(k)+'</dt><dd>'+esc(v)+'</dd></div>').join('')}</dl>${sections.join('')}</html>`;
const browser = await puppeteer.launch({headless:'shell', pipe:true});
try {
  const page = await browser.newPage();
  await page.setJavaScriptEnabled(false);
  await page.setOfflineMode(true);
  await page.setContent(html);
  const preview = process.argv.find(arg=>arg.startsWith('--preview='));
  if(preview){
    await page.setViewport({width:794,height:1123,deviceScaleFactor:1});
    await page.emulateMediaType('print');
    const previewPath=preview.slice('--preview='.length);
    await page.screenshot({path:previewPath});
    if(await page.evaluate(()=>document.body.scrollHeight)>2246){
      await page.screenshot({path:previewPath.replace(/\.png$/, '-body.png'),clip:{x:0,y:1123,width:794,height:1123}});
    }
  }
  const pdf = await page.pdf({format:'A4',printBackground:true,displayHeaderFooter:true,headerTemplate:'<span></span>',footerTemplate:'<div style="width:100%;margin:0 17mm;font:8px Arial;color:#42616b">TacticLens · '+esc(report.reference)+' · <span class="pageNumber"></span> / <span class="totalPages"></span></div>',margin:{top:'17mm',bottom:'18mm',left:'17mm',right:'17mm'}});
  stdout.write(Buffer.from(pdf));
} finally { await browser.close(); }
