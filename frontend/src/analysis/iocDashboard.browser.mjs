import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {join,resolve} from 'node:path'
import {createRequire} from 'node:module'

assert.ok(process.env.TACTICLENS_EXP_STATIC,'Set TACTICLENS_EXP_STATIC to the temporary Vite output directory')
const build=resolve(process.env.TACTICLENS_EXP_STATIC)
const require=createRequire(resolve('backend/report_renderer/package.json'))
const browser=await require('puppeteer').launch({headless:'shell',pipe:true})
const origin='http://tacticlens.invalid'
const date='2026-11-24T16:00:00Z'
const session='fixture-session'
const event='9981723456789012'
const link={id_evento:event,id_sesion:session,fecha_hora:date,ingresado_en:date,numero_secuencia:7,tipo_evento:'cowrie.session.file_download'}
const base={primera_observacion:date,ultima_observacion:date,estado_revision:'pendiente',alcance:null,
  observaciones:4,observaciones_verificables:4,eventos:4,sesiones:2,tecnicas:1}
const url={...base,id_ioc:'url-test',tipo:'URL',valor:'https://packages.example.invalid/release.bin'}
const ip={...base,id_ioc:'ip-test',tipo:'IP',valor:'10.50.1.4',alcance:'privada',observaciones:12,
  observaciones_verificables:12,eventos:12,sesiones:4,tecnicas:0}
const hash={...base,id_ioc:'hash-test',tipo:'Hash',valor:'ac'.repeat(32),observaciones:1,
  observaciones_verificables:1,eventos:1,sesiones:1,estado_revision:'confirmado',tecnicas:0}
const scope=[url,ip,hash]
const auth={etapa:'completa',usuario:{id_usuario:'tester',nombres:'Usuario',apellidos:'de prueba',
  nombre_usuario:'examinador',correo:'test@example.invalid',rol:'administrador'}}
const mapping={id_mapeo:'map-test',codigo_tecnica:'T1105',tecnica:'Ingress Tool Transfer',tactica:'Command and Control',
  codigo_tactica:'TA0011',estado_revision:'pendiente',rag_procedencia:{clasificacion:'identificada_automaticamente'},
  grado_evidencia:'resultado_en_honeypot',justificacion:'Cowrie registró la descarga en el señuelo.',
  estado:'contextual',fundamento:'La técnica y la detección citan el mismo evento.',limitaciones:[],eventos:[link]}
const raw={eventid:link.tipo_evento,url:url.valor,shasum:hash.valor,token:'[REDACTED]'}
const observation={...link,id_observacion:'obs-test',cowrie_session_id:'cowrie-fixture',sensor:'Cowrie Shell de prueba',
  modalidad:'cowrie_shell',estado_relacion:'directa',estado_revision:'pendiente',datos_originales:raw,
  correlaciones:[{tipo:'url_archivo',estado:'directa',observable:hash,eventos:[link],limitaciones:[],
    justificacion:'URL y SHA-256 registrados en el mismo evento de Cowrie.'}],
  acciones:[{id_accion:'action-test',id_analisis:'analysis-test',tipo_accion:'Descarga registrada',estado:'directa',
    interpretacion:'Se observó una recepción en el señuelo.',justificacion:'Coincide con el evento citado.',
    limitaciones:[],eventos:[link],tecnicas:[mapping]}],
  detalles:[{campo:'url',metodo:'campo_cowrie',comportamiento:'descarga_registrada',grado_evidencia:'resultado_registrado',
    valor_original:url.valor,limitacion:'El sensor registró la recepción. La ejecución del archivo queda sin verificar.'}]}
const summary={totales:{observables:3,observaciones:17,eventos:14,sesiones:4,verificables:3,con_mitre:1},
  tipos:scope.map(row=>({categoria:row.tipo,observables:1,observaciones:row.observaciones})),
  modalidades:[{categoria:'cowrie_shell',observables:3,observaciones:14},{categoria:'desconocido',observables:1,observaciones:3}],
  estados:[{categoria:'pendiente',observables:2},{categoria:'confirmado',observables:1}],
  alcances:[{categoria:'privada',observables:1}],evolucion:[{categoria:'2026-11-23',observaciones:5},{categoria:'2026-11-24',observaciones:12}],
  recurrentes:scope}

try {
  const page=await browser.newPage()
  const calls=[],errors=[]
  let failSummary=false, viewer='administrador'
  page.on('pageerror',error=>errors.push(error.message))
  await page.setViewport({width:1536,height:1000,deviceScaleFactor:1.5})
  await page.emulateTimezone('Asia/Tokyo')
  await page.evaluateOnNewDocument(()=>{window.WebSocket=class extends EventTarget{static OPEN=1;readyState=3;close(){}}})
  await page.setRequestInterception(true)
  page.on('request',async request=>{
    const target=new URL(request.url()), path=target.pathname
    if(target.origin!==origin)return request.abort()
    if(!path.startsWith('/api/')){
      const file=path.startsWith('/assets/')?resolve(build,'.'+path):join(build,'index.html')
      assert.ok(file.startsWith(build))
      return request.respond({status:200,contentType:file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html',body:await readFile(file)})
    }
    calls.push([path,target.search])
    if(failSummary&&path==='/api/iocs/resumen')return request.respond({status:503,contentType:'application/json',body:'{"detail":"Resumen de prueba no disponible"}'})
    const selected=scope.find(row=>path.startsWith('/api/iocs/'+row.id_ioc+'/'))
    let result=[]
    if(path==='/api/auth/me')result={...auth,usuario:{...auth.usuario,rol:viewer}}
    else if(path==='/api/auth/csrf')result={csrf_token:'fixture'}
    else if(path==='/api/iocs/resumen') result=summary
    else if(path==='/api/iocs/explorar') result=scope.filter(row=>!target.searchParams.has('q')||row.valor.includes(target.searchParams.get('q')))
    else if(selected&&path.endsWith('/perfil')){
      if(selected===ip)await new Promise(resolve=>setTimeout(resolve,300))
      result={...selected,clasificacion:selected===ip?{version_ip:4,alcance:'privada'}:selected===hash?{algoritmo:'SHA-256'}:
        {esquema:'https',host:'packages.example.invalid',ruta_segura:'/release.bin'},
        comportamiento:{modalidades:['cowrie_shell'],sensores:[observation.sensor],ultima_revision:null,
          ...(selected===url?{comandos:2,descargas:1,intentos_descarga:2,acciones:1,tecnicas:1}:{conexiones:1})},
        artefactos:[],enriquecimiento:{estado:'sin_configuracion_registrada',resultados:[]}}
    } else if(selected&&path.endsWith('/sesiones'))result=[{id_sesion:session,cowrie_session_id:observation.cowrie_session_id,
      modalidad:'cowrie_shell',sensor:observation.sensor,ip_origen:ip.valor,fecha_inicio:date,fecha_fin:null,duracion_segundos:null,
      observaciones:2,eventos:12,acciones:1,tecnicas:['T1105'],estado_analisis:'analizada',observaciones_verificables:2,analisis:{id_analisis:'analysis-test'}}]
    else if(selected&&path.endsWith('/observaciones')&&target.searchParams.get('categoria')!=='desconexiones')result=[observation]
    if(request.isInterceptResolutionHandled())return
    return request.respond({status:200,contentType:'application/json',body:JSON.stringify(result)})
  })
  const wait=(text,selector='main')=>page.waitForFunction((text,selector)=>document.querySelector(selector)?.innerText.includes(text),{timeout:7000},text,selector)
  const click=(selector,label)=>page.evaluate((selector,label)=>[...document.querySelectorAll(selector)].find(node=>
    node.innerText.trim().includes(label))?.click(),selector,label)
  const region=label=>'[aria-label="'+label+'"]'
  async function capture(selector,file){
    const element=await page.$(selector)
    assert.ok(element,selector)
    await element.screenshot({path:join(build,file+'.png')})
  }

  await page.goto(origin+'/iocs',{waitUntil:'domcontentloaded'})
  await wait('Actividad registrada')
  await wait(url.valor,region('Explorador de observables'))
  await page.screenshot({path:join(build,'01-vista-general.png')})
  await click('summary','Distribución y evolución')
  await wait('Observables recurrentes')
  await capture(region('Gráficos de observables'),'02-indicadores-graficos')
  await click('summary','Distribución y evolución')
  const overview=region('Explorador de observables')
  await click(overview+' button',ip.valor)
  await click(overview+' button',url.valor)
  await wait(url.valor,region('Perfil del observable'))
  assert.doesNotMatch(await page.$eval(region('Perfil del observable'),node=>node.innerText),/10\.50\.1\.4/)
  await page.type('input[name=q]','packages')
  await click('form button','Aplicar filtros')
  await wait('Valor o sesión · packages')
  await wait(url.valor,overview)
  await capture(overview,'03-explorador-filtrado')
  await click(overview+' button',url.valor)
  await wait('Severidad no determinada')
  await capture(region('Perfil del observable'),'04-perfil')
  await capture(region('Comportamiento registrado'),'05-comportamiento')
  await click('summary','Reputación y enriquecimiento')
  await wait('Enriquecimiento externo no configurado')
  await click('nav button','Sesiones')
  await wait('12 eventos de sesión')
  await capture(region('Sesiones del observable'),'06-sesiones')
  await click('nav button','Evidencias')
  await wait('Evidencias prioritarias')
  await wait('Campo de Cowrie')
  assert.ok(calls.some(([path,query])=>path.endsWith('/observaciones')&&query.includes('vista_segura=true')))
  await click('summary','Ver JSON del evento')
  await wait('[REDACTED]')
  await capture('#ioc-observations','07-evidencia-original')
  await click('summary','Procedencia y revisión')
  await wait('Confirmar relevancia')
  assert.equal(await page.$$eval('button',nodes=>nodes.filter(node=>node.innerText==='Confirmar relevancia').length),1)
  await capture('#ioc-observations','10-procedencia-revision')
  await click('nav button','Relaciones')
  await wait('Ingress Tool Transfer')
  assert.ok(await page.$('a[href="/mitre?mapeo=map-test&tecnica=T1105&sesion_id=fixture-session"]'))
  await capture('#ioc-observations','08-correlacion-mitre')
  await capture('#ioc-observations ul li section','09-observables-relacionados')
  await page.click('a[href="/iocs?ioc=hash-test&evento=9981723456789012"]')
  await wait('Evidencia de Cowrie')
  await click('nav button','Perfil')
  await wait('SHA-256',region('Perfil del observable'))
  await page.setViewport({width:390,height:844})
  await page.waitForFunction(()=>document.documentElement.scrollWidth<=window.innerWidth,{timeout:4000})
  await capture(region('Perfil del observable'),'11-perfil-movil')
  viewer='analista'
  await page.goto(origin+'/iocs?ioc=url-test&evento='+event,{waitUntil:'domcontentloaded'})
  await wait('Campo de Cowrie')
  await click('summary','Procedencia y revisión')
  assert.equal(await page.$$eval('button',nodes=>nodes.filter(node=>node.innerText==='Confirmar relevancia').length),0)
  await click('nav button','Relaciones')
  await wait('Red de correlaciones')
  await page.select('#ioc-observations select','desconexiones')
  await wait('Sin observaciones en esta categoría o página.')
  failSummary=true
  await page.goto(origin+'/iocs',{waitUntil:'domcontentloaded'})
  await wait('Resumen de prueba no disponible')
  assert.deepEqual(errors,[])
  console.log('Chromium: filtros, selección rápida, sesión, relación exacta, rol, vacíos, error y móvil verificados.',build)
} finally { await browser.close() }
