import assert from 'node:assert/strict'
import {readFile} from 'node:fs/promises'
import {extname,join,resolve} from 'node:path'
import {createRequire} from 'node:module'

const require=createRequire(resolve('backend/report_renderer/package.json'))
const browser=await require('puppeteer').launch({headless:'shell',pipe:true})
const build=resolve('frontend/dist')
const origin='http://respuesta-tacticlens.invalid'
const incident='00000000-0000-4000-8000-000000000011'
const id='00000000-0000-4000-8000-000000000012'
const historicalId='00000000-0000-4000-8000-000000000013'
const historicalAnalysis='00000000-0000-4000-8000-000000000014'
const historicalSession='00000000-0000-4000-8000-000000000015'
const draftId='00000000-0000-4000-8000-000000000016'
const historicalPath='/incidentes/'+historicalId+'/respuesta'
const noticeId='00000000-0000-4000-8000-000000000017'
const previewRevision='b4'.repeat(32)
const base='/incidentes/'+incident+'/respuesta'
const auth={csrf_token:'fixture',usuario:{id_usuario:'fixture',nombres:'Analista',apellidos:'Demo',
  nombre_usuario:'analista',correo:'test@example.invalid',rol:'administrador'},etapa:'completa'}
const evaluation={decision:'incidente_confirmado',titulo:'Incidente sintético',resumen:'Cobertura de laboratorio.',
  severidad:'S2',prioridad:'media',revision_actual:1,revision_evaluacion:1,evidencia_verificable:true,
  evaluado_en:'2026-11-28T12:00:00Z',clasificacion:'actividad_sospechosa',evidencia_sha256:'a3'.repeat(32),
  evidencias:[],detalle:{},alcance:{sesiones:[],recursos_confirmados:[]},eventos:[],historial:[],
  sesiones:[],iocs:[],mitre:[],analisis:[],correlaciones:[],limites:{hay_mas:false}}
let plan={id_incidente:incident,id_respuesta:null,estado:'sin_respuesta',elegible:true,desactualizada:false,
  revision_evaluacion_actual:1,revision_plan:null,revision_respuesta:null,evaluacion:evaluation}
let action={id_accion:id,id_incidente:incident,incidente_titulo:evaluation.titulo,fase:'verificacion',estado:'propuesta',
  medida:'Verificar registro sintético',objetivo:'Comprobar el alcance',justificacion:'Evidencia de laboratorio',
  criterio_verificacion:'Comparar las actas',id_responsable:null,responsable:null,revision_accion:1,
  revision_validada:1,revision_evaluacion_actual:1,estado_respuesta:'en_respuesta',desactualizada:false}
const history={items:[{id_cambio:'1',operacion:'aprobar',motivo:'Motivo sintético completo',actor:'analista',
  creado_en:'2026-11-28T12:00:00Z',revision_evaluacion:1,detalle:{}}],cursor:null}
const generated={id_borrador:draftId,estado:'disponible',vigente:true,historico:true,creado_en:evaluation.evaluado_en,
  versiones:[{version:1,creado_en:evaluation.evaluado_en,motivo:'Borrador generado por IA',decisiones:{},propuesta:{plan:{
    titulo:'Revisión de evidencia generada',objetivo:'Verificar los registros de prueba',resumen:'Se observó una interacción en el señuelo',
    alcance:'Sesión de laboratorio aislada',estrategia:'Contrastar el registro original',prioridad:'media',
    resultado_esperado:'Actividad documentada',criterio_resolucion:'Validar las referencias',criterio_cierre:'Documentar resultados',
    eventos:['123'],acciones:[{clave:'A1',fase:'investigacion',medida:'Revisar registro original',descripcion:'Contrastar evidencia',
      objetivo:'Confirmar el registro',justificacion:'Evento verificable',prioridad:'media',rol_sugerido:'indistinto',
      plazo_dias:1,dependencias:[],mitre:[],eventos:['123'],resultado_esperado:'Evidencia confirmada',criterio_verificacion:'Citar el registro'}]
  }}}]}
const pages=[]
const errors=[]
let transitions=0
let recoveries=0
let readNotices=0
let ownQueries=0
try {
  async function newPage(){
    const page=await browser.newPage()
    pages.push(page)
    page.on('pageerror',error=>errors.push(error.message))
    await page.setViewport({width:1440,height:1000})
    await page.evaluateOnNewDocument(()=>{
      Object.defineProperty(document,'visibilityState',{get:()=> 'visible'})
      window.WebSocket=class extends EventTarget {
        static OPEN=1
        readyState=0
        constructor(){super();window.fixtureSocket=this;queueMicrotask(()=>{
          this.readyState=1;this.dispatchEvent(new Event('open'))
          this.onmessage?.({data:JSON.stringify({tipo:'listo',epoca:'fixture',revision:0})})
        })}
        send(){}
        close(){this.readyState=3}
      }
    })
    await page.setRequestInterception(true)
    page.on('request',async req=>{
      const url=new URL(req.url())
      if(url.origin!==origin)return req.abort()
      const path=url.pathname
      if(!path.startsWith('/api/')){
        const file=path.startsWith('/assets/')?join(build,path):join(build,'index.html')
        const contentType={'.html':'text/html','.js':'text/javascript','.css':'text/css'}[extname(file)]??'application/octet-stream'
        return req.respond({status:200,contentType,body:await readFile(file)})
      }
      let value={}
      if(path==='/api/auth/me'||path==='/api/auth/csrf')value=auth
      if(path==='/api/incidentes')value={items:[{...evaluation,id_incidente:incident,modalidades:['cowrie_shell'],
        actualizado_en:evaluation.evaluado_en}],cursor:null}
      if(path==='/api/incidentes/resumen')value={total:1,distribucion:[{decision:evaluation.decision,total:1}],retrospectiva_disponible:true}
      if(path==='/api/incidentes/retrospectiva'){
        if(req.method()==='POST'){
          assert.equal(req.headers()['x-csrf-token'],'fixture')
          assert.equal(JSON.parse(req.postData()).revision_vista_previa,previewRevision)
          recoveries+=1
          value={incidentes:[historicalId]}
        }else{
          value={revision_vista_previa:previewRevision,resumen:{analisis_revisados:2,sesiones_revisadas:2,
            recuperable_directamente:0,recuperable_con_revision:1,requiere_reevaluacion:1,sesion_ya_registrada:0,
            sin_indicios_suficientes:0,salvaguardas_con_citas_compatibles:1},sesiones:[],seleccion:[{
            id_analisis:historicalAnalysis,id_sesion:historicalSession,actividad_desde:'2026-11-22T08:00:00Z',
            modalidad:'cowrie_shell',estado:'recuperable_con_revision',salvaguardas:[]}]}
        }
      }
      if(path==='/api/incidentes/'+incident)value={...evaluation,id_incidente:incident}
      if(path==='/api/incidentes/'+historicalId)value={...evaluation,id_incidente:historicalId,
        decision:'actividad_sospechosa',titulo:'Actividad histórica de prueba',registrado_en:'2026-11-28T12:00:00Z',
        detalle:{retrospectiva:[{id_analisis:historicalAnalysis,base_evidencia:'recibos_y_citas',
          actividad_desde:'2026-11-22T08:00:00Z',actividad_hasta:'2026-11-22T08:10:00Z'}]}}
      if(path==='/api'+historicalPath)value={...plan,id_incidente:historicalId,estado:'sin_respuesta',id_respuesta:null,
        automatizacion_disponible:true,elegible:false,evaluacion:{...evaluation,decision:'actividad_sospechosa',titulo:'Actividad histórica de prueba'}}
      if(path==='/api'+historicalPath+'/borradores')value={items:[generated],generacion_habilitada:true}
      if(path==='/api'+historicalPath+'/borradores/'+draftId)value=generated
      if(path==='/api/respuestas-incidentes/avisos')value={items:recoveries?[{id_aviso:noticeId,id_incidente:historicalId,id_accion:null,
        titulo:'Borrador generado por IA',creado_en:evaluation.evaluado_en,leido_en:readNotices?evaluation.evaluado_en:null}]:[],
        no_leidos:recoveries&&!readNotices?1:0,hay_mas:false}
      if(path==='/api/respuestas-incidentes/avisos/'+noticeId+'/leer'){
        assert.equal(req.headers()['x-csrf-token'],'fixture')
        readNotices+=1;value={actualizados:1}
      }
      if(path==='/api'+base){
        if(req.method()==='POST'){
          assert.equal(req.headers()['x-csrf-token'],'fixture')
          const body=JSON.parse(req.postData())
          assert.equal(body.revision_evaluacion,1)
          assert.equal(body.objetivo,'Comprobar evidencia')
          plan={...plan,id_respuesta:'fixture-plan',estado:'en_respuesta',revision_respuesta:1,revision_plan:1,...body}
        }
        value=plan
      }
      if(path==='/api/respuestas-incidentes/responsables')value=[]
      if(path==='/api/respuestas-incidentes/configuracion')value={wip_activo:true,limite_wip:5,revision_config:1}
      if(path==='/api/respuestas-incidentes/acciones'){
        if(url.searchParams.get('mias')==='true')ownQueries+=1
        const states=url.searchParams.getAll('estado')
        value={items:!states.length||states.includes(action.estado)?[action]:[],cursor:null}
      }
      if(path==='/api'+base+'/acciones/'+id)value={...action,evidencia:[]}
      if(path.endsWith('/historial'))value=history
      if(path.endsWith('/transiciones')){
        const body=JSON.parse(req.postData())
        assert.equal(body.operacion,'aprobar')
        assert.equal(body.revision_esperada,1)
        action={...action,estado:'aprobada',revision_accion:2}
        plan={...plan,revision_respuesta:2}
        transitions+=1
        value=action
      }
      await req.respond({status:200,contentType:'application/json',body:JSON.stringify(value)})
      if(path.endsWith('/transiciones'))await Promise.all(pages.map(tab=>tab.evaluate(()=>{
        window.fixtureSocket.onmessage?.({data:JSON.stringify({
          tipo:'cambio',epoca:'fixture',revision:1,dominios:['respuesta_incidentes']})})
      })))
    })
    return page
  }
  const first=await newPage()
  const wait=(page,selector,phrase)=>page.waitForFunction((s,p)=>document.querySelector(s)?.textContent.includes(p),
    {timeout:7000},selector,phrase)
  const click=(page,text)=>page.evaluate(value=>Array.from(document.querySelectorAll('button'))
    .find(node=>node.innerText.trim()===value)?.click(),text)
  await first.goto(origin+'/incidentes')
  await wait(first,'table[aria-label=Incidentes]',evaluation.titulo)
  await first.click('a[href="/incidentes/'+incident+'"]')
  await wait(first,'main','Abrir plan de respuesta')
  await first.click('a[href="'+base+'"]')
  await wait(first,'main','Crear plan')
  await click(first,'Crear plan')
  await first.waitForSelector('textarea[name=objetivo]')
  await first.type('textarea[name=objetivo]','Comprobar evidencia')
  await first.type('textarea[name=alcance]','Alcance de prueba autorizado')
  await first.type('textarea[name=criterio_cierre]','Contrastar los resultados')
  await click(first,'Abrir plan de respuesta')
  await wait(first,'main','Tablero de respuesta')
  const second=await newPage()
  await second.goto(origin+'/respuesta-incidentes')
  await wait(second,'[aria-label="Tarjetas de Por decidir"]',action.medida)
  await wait(first,'[aria-label="Tarjetas de Por decidir"]',action.medida)
  await first.bringToFront()
  await first.focus('button[aria-label="Mover Verificar registro sintético"]')
  await first.keyboard.press('Space')
  await first.waitForSelector('.kanban-preview',{timeout:7000})
  await first.keyboard.press('ArrowRight')
  await first.waitForSelector('.kanban-column[data-over="true"]',{timeout:7000})
  await first.keyboard.press('Space')
  await first.waitForSelector('dialog[open] textarea[name=motivo]',{timeout:7000})
  await first.type('dialog textarea[name=motivo]','Motivo sintético completo')
  await click(first,'Confirmar aprobar')
  await wait(second,'[aria-label="Tarjetas de Aprobadas"]',action.medida)
  assert.equal(transitions,1)
  await click(second,'Mis acciones')
  await wait(second,'h2','Mis acciones')
  await second.waitForFunction(()=>document.querySelector('button[aria-pressed=true]')?.innerText==='Todas las acciones')
  await first.goto(origin+'/incidentes')
  await wait(first,'main','Recuperar actividad histórica')
  await first.evaluate(()=>Array.from(document.querySelectorAll('summary')).find(n=>n.innerText==='Recuperar actividad histórica').click())
  await click(first,'Generar vista previa')
  await wait(first,'table[aria-label="Candidatos históricos"]',historicalAnalysis)
  await wait(first,'main','1 pendientes de reevaluación')
  assert.equal(recoveries,0)
  await first.type('details[open] textarea[name=motivo]','Recuperación histórica sintética')
  await click(first,'Registrar candidatos de esta vista previa')
  await first.waitForSelector('a[href="/incidentes/'+historicalId+'"]')
  assert.equal(recoveries,1)
  await first.click('a[href="/incidentes/'+historicalId+'"]')
  await wait(first,'main','Actividad original')
  await wait(first,'main','Registro del incidente')
  await first.click('a[href="'+historicalPath+'"]')
  await wait(first,'main','Revisión de evidencia generada')
  assert.equal(await first.evaluate(()=>Array.from(document.querySelectorAll('button')).some(item=>item.innerText==='Aprobar selección')),false)
  await first.evaluate(()=>window.fixtureSocket.onmessage?.({data:JSON.stringify({tipo:'cambio',epoca:'fixture',revision:5,dominios:['avisos_incidentes']})}))
  await first.waitForSelector('button[aria-label="Notificaciones. 1 sin leer"]')
  await first.click('button[aria-label="Notificaciones. 1 sin leer"]')
  await wait(first,'[aria-label="Historial de notificaciones"]','Borrador generado por IA')
  await click(first,'Marcar como leída')
  await first.waitForSelector('button[aria-label="Notificaciones. 0 sin leer"]')
  assert.equal(readNotices,1)
  assert.ok(ownQueries>0)
  assert.deepEqual(errors,[])
  console.log('Chromium: Kanban, sincronización entre clientes, Mis acciones, recuperación histórica, borrador y campana.')
} finally {
  await browser.close()
}
