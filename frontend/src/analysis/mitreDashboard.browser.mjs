import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {join,resolve} from 'node:path'
import {createRequire} from 'node:module'
// Run from the repository root against a temporary Vite build.
assert.ok(process.env.TACTICLENS_EXP_STATIC,'Set TACTICLENS_EXP_STATIC to the temporary Vite output directory')
const require=createRequire(resolve('backend/report_renderer/package.json'))
const browser=await require('puppeteer').launch({headless:'shell',pipe:true})
const build=resolve(process.env.TACTICLENS_EXP_STATIC)
const origin='http://tacticlens.invalid', d='2026-11-23T15:00:00Z'
const count={mapeos:2,automaticas:1,confirmadas:0,pendientes:1,descartadas:0,con_citas:1,sin_citas:1}
const technique={...count,codigo_tecnica:'T1033',tecnica:'System Owner/User Discovery',tacticas:['Discovery'],sesiones:2,primera_aparicion:d,ultima_aparicion:d}
const overview={version_catalogo:'20.1',totales:{...count,tecnicas:1,tacticas:1,sesiones:2,acciones:2,eventos_citados:1,ips:2,observables:0,
  primera_aparicion:d,ultima_aparicion:'2026-11-24T10:00:00Z'},
  tacticas:[{...count,codigo_tactica:'TA0007',tactica:'Discovery'}],modalidades:[{...count,modalidad:'cowrie_shell'}],
  estados:[{...count,mapeos:1,estado_identificacion:'automatica'},{...count,mapeos:1,estado_identificacion:'historica_pendiente'}],
  recurrentes:[technique],evolucion:[{...count,mapeos:1,fecha:'2026-11-23',origen_fecha:'evento_citado'},{...count,mapeos:1,fecha:'2026-11-24',origen_fecha:'inicio_sesion'}]}
const session={...count,id_sesion:'session1',cowrie_session_id:'cowrie-one',modalidades:['cowrie_shell'],fecha_inicio:d,
  fecha_fin:null,ip_origen:'192.0.2.42',sensor:'Sensor de prueba',eventos:3,acciones:2,estados_analisis:['completado']}
const mapping={...technique,id_sesion:'session1',cowrie_session_id:'cowrie-one',id_analisis:'analysis1',id_mapeo:'map1',id_accion:'action1',
  estado_revision:'pendiente',codigo_tactica:'TA0007',tactica:'Discovery',tipo_accion:'Comando registrado',descripcion_accion:'Orden whoami',
  fecha_analisis:d,modalidad:'cowrie_shell',grado_evidencia:'intento',justificacion:'Cita exacta verificada.',
  rag_procedencia:{clasificacion:'identificada_automaticamente',version_contrato:'1'},
  eventos:[{id_evento:'9981723456789012',id_sesion:'session1',fecha_hora:d,ingresado_en:d,numero_secuencia:1,tipo_evento:'cowrie.command.input',comando:'whoami'}]}
const cells=[{...technique,codigo_tactica:'TA0007',tactica:'Discovery',tecnica_padre_id:null,estado_catalogo:'vigente',relacion_vigente:true},
  {...count,mapeos:0,automaticas:0,pendientes:0,sesiones:0,codigo_tecnica:'T9999.001',tecnica:'Subtécnica de prueba',codigo_tactica:'TA0007',
    tactica:'Discovery',tecnica_padre_id:'T1033',estado_catalogo:'vigente',relacion_vigente:true}]
const catalogo={codigo_tecnica:'T1033',nombre:technique.tecnica,descripcion:'Descripción oficial de prueba.',plataformas:['Linux'],
  stix_id:'attack-pattern--fixture',version_attack:'20.1',version_objeto:'1.0',estado_catalogo:'vigente',
  tacticas:[{codigo_tactica:'TA0007',nombre:'Discovery',activa_en_catalogo:true}],subtecnicas:[]}
const auth={csrf_token:'fixture',usuario:{id_usuario:'test',nombres:'Analista',apellidos:'Demo',nombre_usuario:'analista',
  correo:'test@example.invalid',rol:'administrador'},etapa:'completa'}
try {
  const page=await browser.newPage()
  const calls=[],errors=[]
  page.on('pageerror',e=>errors.push(e.message))
  await page.setViewport({width:1440,height:1000})
  await page.evaluateOnNewDocument(()=>{window.WebSocket=class extends EventTarget{static OPEN=1;readyState=3;close(){}}})
  await page.setRequestInterception(true)
  page.on('request',async r=>{
    const url=new URL(r.url()),path=url.pathname
    if(url.origin!==origin)return r.abort()
    if(!path.startsWith('/api/')){
      const file=path.startsWith('/assets/')?resolve(build,'.'+path):join(build,'index.html')
      assert.ok(file.startsWith(build))
      return r.respond({status:200,contentType:file.endsWith('.js')?'application/javascript':file.endsWith('.css')?'text/css':'text/html',body:await readFile(file)})
    }
    calls.push([path,url.search])
    const data={
      '/api/auth/me':auth,'/api/auth/csrf':auth,'/api/health':{},
      '/api/mitre/clasificadores':{version:'fixture',clasificadores:[]},
      '/api/mitre/resumen':overview,'/api/mitre/matriz':url.searchParams.get('catalogo')==='true'?cells:cells.slice(0,1),
      '/api/mitre/tecnicas':[technique],'/api/mitre/tecnicas/T1033':{...overview,catalogo},
      '/api/mitre/tecnicas/T1033/sesiones':[session],'/api/mitre/mapeos':[mapping],
      '/api/mitre/mapeos/map1/observables':{mapeo:mapping,observables:[],hay_mas:false},
    }[path]??[]
    return r.respond({status:200,contentType:'application/json',body:JSON.stringify(data)})
  })
  const wait=text=>page.waitForFunction(value=>document.body.innerText.includes(value),{timeout:7000},text)
  const click=(tag,text)=>page.evaluate((tag,text)=>[...document.querySelectorAll(tag)].find(node=>node.innerText.trim().includes(text))?.click(),tag,text)
  await page.goto(origin+'/mitre',{waitUntil:'domcontentloaded'})
  await wait('ATT&CK Enterprise 20.1')
  await page.screenshot({path:join(build,'mitre-resumen.png')})
  await click('summary','Matriz MITRE ATT&CK')
  await wait('Incluir catálogo vigente')
  await page.click('input[type=checkbox]')
  await wait('Subtécnicas (1)')
  await click('summary','Subtécnicas (1)')
  await wait('Sin mapeos registrados')
  await (await page.$('[aria-label="Tácticas de la matriz ATT&CK"]')).screenshot({path:join(build,'mitre-matriz.png')})
  await click('[aria-label="Tácticas de la matriz ATT&CK"] button','T1033')
  await wait('Observables vinculados')
  await click('button','Ver hallazgos')
  await wait('Comando registrado')
  await click('[aria-label="Hallazgos de la sesión seleccionada"] button','Discovery')
  await wait('Cita exacta verificada.')
  assert.equal(await page.$$eval('a[href="/sesiones/session1?evento=9981723456789012"]',a=>a.length),1)
  await click('summary','Procedencia y validación')
  await wait('Contrato de evidencia')
  await click('summary','Revisión administrativa')
  assert.equal(await page.$$eval('button',nodes=>nodes.filter(n=>n.innerText.trim()==='Confirmar mapeo').length),1)
  await (await page.$('[aria-label="Detalle del hallazgo"]')).screenshot({path:join(build,'mitre-hallazgo.png')})
  await page.setViewport({width:390,height:844})
  await page.waitForFunction(()=>window.innerWidth===390)
  await page.screenshot({path:join(build,'mitre-movil.png')})
  await page.waitForFunction(()=>document.documentElement.scrollWidth<=window.innerWidth,{timeout:3000}).catch(async error=>{
    const overflow=await page.evaluate(()=>[...document.querySelectorAll('main *')].filter(element=>{
      const bounds=element.getBoundingClientRect()
      return bounds.right>window.innerWidth&&!element.closest('[aria-label="Tácticas de la matriz ATT&CK"]')
    }).slice(0,12).map(element=>[element.tagName,String(element.className),element.getBoundingClientRect().right]))
    console.error('Mobile overflow:',overflow)
    throw error
  })
  await (await page.$('[aria-label="Perfil de técnica"]')).screenshot({path:join(build,'mitre-perfil-movil.png')})
  await page.goto(origin+'/mitre?mapeo=map1&tecnica=T1033&sesion_id=session1',{waitUntil:'domcontentloaded'})
  await wait('Cita exacta verificada.')
  await wait('cowrie-one')
  assert.ok(calls.some(([path,query])=>path.endsWith('/sesiones')&&query.includes('id_sesion=session1')))
  await page.type('input[name=q]','T1033')
  await click('button','Aplicar filtros')
  await page.waitForFunction(()=>new URLSearchParams(location.search).get('q')==='T1033',{timeout:7000})
  assert.deepEqual(errors,[])
  console.log('Flujo Chromium verificado. Capturas:',build)
} finally { await browser.close() }
