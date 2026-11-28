import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import {fileURLToPath} from 'node:url'
import test from 'node:test'
import {build} from 'esbuild'
import {createElement} from 'react'
import {renderToStaticMarkup} from 'react-dom/server'
import {MemoryRouter} from 'react-router-dom'

async function load(...modules) {
  const {outputFiles}=await build({stdin:{contents:modules.map(path=> 'export * from '+JSON.stringify(path)).join('\n'),
    resolveDir:fileURLToPath(new URL('.',import.meta.url))},
    bundle:true,write:false,format:'cjs',platform:'node',packages:'external',jsx:'automatic',loader:{'.css':'empty'}})
  const compiled={exports:{}}
  new Function('module','exports','require',outputFiles[0].text)(compiled,compiled.exports,createRequire(import.meta.url))
  return compiled.exports
}

test('stored mappings render once with exact links, separately from history and RAG candidates',async()=>{
  const {MitreResults}=await load('./MitreResults.tsx')
  const automatic={id_mapeo:'mapping',codigo_tecnica:'T1033',tecnica:'Owner Discovery',tactica:'Discovery',estado_revision:'pendiente',
    grado_evidencia:'intento',justificacion:'Orden whoami registrada',
    rag_procedencia:{clasificacion:'identificada_automaticamente',modalidad:'cowrie_llm'},
    eventos:[{id_evento:'9234567890123456',id_sesion:'session',tipo_evento:'cowrie.command.input',fecha_hora:'2026-11-23T00:00:00Z'}]}
  const legacy={...automatic,id_mapeo:'historic',codigo_tecnica:'T1059.004',rag_procedencia:{},eventos:[]}
  const analysis={id_sesion:'session',estado:'completado',resultado_estructurado:{
    clasificacion_mitre:{estado:'identificada_automaticamente'},rag:{candidatos:[{codigo_tecnica:'T9999'}]},
  }}
  const render=(result,mappings)=>renderToStaticMarkup(createElement(MemoryRouter,null,createElement(MitreResults,{analysis:result,mappings})))
  const html=render(analysis,[automatic,automatic,legacy])
  assert.equal(html.match(/>T1033 · Owner Discovery<\/a>/g).length,1)
  assert.match(html,/href="\/sesiones\/session\?evento=9234567890123456"/)
  assert.match(html,/href="\/mitre\?mapeo=mapping&amp;tecnica=T1033&amp;sesion_id=session"/)
  assert.match(html,/Histórico · pendiente de revisión/)
  assert.match(html,/Intento · cowrie_llm/)
  assert.match(html,/Sin citas verificables/)
  assert.doesNotMatch(html,/T9999|Confirmar mapeo|Descartar mapeo/)
  assert.match(render({...analysis,resultado_estructurado:{clasificacion_mitre:{estado:'no_determinada',motivo:'Sin respaldo'}}},[]),/No determinada\..*Sin respaldo/)
  assert.match(render({...analysis,estado:'fallido'},[]),/Análisis fallido/)
})

test('analyzing loads the returned persisted result without requesting RAG candidates',async t=>{
  const {runSessionAnalysis}=await load('./sessionAnalysis.ts')
  const calls=[]
  let fail=false
  t.mock.method(globalThis,'fetch',async (url,options)=>{
    calls.push([url,options.method??'GET'])
    if(url==='/api/auth/csrf')return Response.json({csrf_token:'fixture'})
    if(url.includes('/analizar?'))return fail?Response.json({detail:'Proveedor indisponible'},{status:502}):Response.json({id_analisis:'saved',reutilizado:true})
    if(url==='/api/analisis/saved')return Response.json({id_analisis:'saved',id_sesion:'session',acciones:[{mitre:[{codigo_tecnica:'T1033'}]}]})
    if(url==='/api/sesiones/session')return Response.json({id_sesion:'session'})
    throw new Error('Unexpected request: '+url)
  })
  const result=await runSessionAnalysis('session',true,new AbortController().signal)
  assert.equal(result.reused,true)
  assert.equal(result.analysis.acciones[0].mitre[0].codigo_tecnica,'T1033')
  assert.deepEqual(calls,[['/api/auth/csrf','GET'],['/api/sesiones/session/analizar?actualizar_rag=true&actualizar_informe=true','POST'],
    ['/api/analisis/saved','GET'],['/api/sesiones/session','GET']])
  fail=true
  await assert.rejects(runSessionAnalysis('session',false,new AbortController().signal),/Análisis fallido. Proveedor indisponible/)
})

test('versioned summary and evaluations render with exact shared evidence links',async()=>{
  const {AnalysisNarrative,AuthProvider}=await load('./AnalysisNarrative.tsx','../auth/context.tsx')
  const assessment = {codigo_severidad:'S3',severidad_preliminar:'Alta',prioridad_investigacion:'alta',confianza_evaluacion:{nivel:'alta'}}
  const sections=[
    {title:'Impacto CIA',paragraphs:['Resultado acotado #9234567890123456'],columns:['Dimensión'],rows:[['Integridad']]},
    {title:'Asociaciones contextuales',paragraphs:[],columns:['Sesión asociada','Eventos de sesión asociada'],rows:[['related-session','#33']]},
  ]
  const result={id_analisis:'analysis',id_sesion:'session',resumen:'Síntesis validada',mensaje_error:null,
    salvaguardas:[{id:'task-id',title:'Auditar permisos',rows:[['Código','SG-00001'],['Riesgo inicial técnico','Alto'],['Evidencia','#33']]}],
    resultado_estructurado:{version_esquema:1,evaluacion_amenaza:assessment,informe:{
      contexto:'Captura del sensor',fases:[{fase:'Consultas de descubrimiento',orden:2,
        inicio_fase:'2026-11-26T12:00:00Z',fin_fase:'2026-11-26T12:00:03Z',estado_resultado:'intento',
        observado:'Se solicitó consultar el directorio de trabajo.',interpretacion:'Propósito literal',resultado:'Solicitud',eventos:[]}],
      hipotesis:[],conclusion:'Conclusión citada',limitaciones:[],recomendaciones:[]
    }},presentacion_analitica:sections}
  const html=renderToStaticMarkup(createElement(MemoryRouter,null,createElement(AuthProvider,null,createElement(AnalysisNarrative,{analysis:result}))))
  assert.match(html,/Síntesis validada/)
  assert.match(html,/S3 · Alta/)
  assert.match(html,/class="badge analysis-severity" data-severity="S3"/)
  assert.match(html,/Impacto CIA/)
  assert.match(html,/2\. Consultas de descubrimiento/)
  assert.match(html,/Solicitud documentada/)
  assert.match(html,/dateTime="2026-11-26T12:00:00Z"/)
  assert.match(html,/href="\/sesiones\/session\?evento=9234567890123456"/)
  assert.match(html,/href="\/sesiones\/related-session\?evento=33"/)
  assert.match(html,/href="\/salvaguardas\?id=task-id"/)
  assert.match(html,/Riesgo inicial técnico/)
  assert.doesNotMatch(html,/Evaluación automática de incidente|Riesgo organizacional|Evidencia de terminal y límites de cobertura/)
})

test('safeguard board renders accessible state columns, filters and indicators',async()=>{
  const {SafeguardsPage,AuthProvider}=await load('./SafeguardsPage.tsx','../auth/context.tsx')
  const html=renderToStaticMarkup(createElement(MemoryRouter,null,
    createElement(AuthProvider,null,createElement(SafeguardsPage))))
  assert.match(html,/aria-label="Tablero de salvaguardas"/)
  for(const state of ['Pendientes','En desarrollo','Realizadas']) assert.match(html,new RegExp('<h2[^>]*>'+state))
  assert.match(html,/Código o nombre/)
  assert.match(html,/Mis salvaguardas/)
  assert.match(html,/Vencidas/)
})
