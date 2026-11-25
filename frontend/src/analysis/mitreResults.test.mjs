import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import {fileURLToPath} from 'node:url'
import test from 'node:test'
import {build} from 'esbuild'
import {createElement} from 'react'
import {renderToStaticMarkup} from 'react-dom/server'
import {MemoryRouter} from 'react-router-dom'

async function load(relative) {
  const {outputFiles}=await build({entryPoints:[fileURLToPath(new URL(relative,import.meta.url))],
    bundle:true,write:false,format:'cjs',platform:'node',packages:'external',jsx:'automatic'})
  const compiled={exports:{}}
  new Function('module','exports','require',outputFiles[0].text)(compiled,compiled.exports,createRequire(import.meta.url))
  return compiled.exports
}

test('stored mappings render once with exact links, separately from history and RAG candidates',async()=>{
  const {MitreResults}=await load('./MitreResults.tsx')
  const automatic={id_mapeo:'mapping',codigo_tecnica:'T1033',tecnica:'Owner Discovery',tactica:'Discovery',estado_revision:'pendiente',
    grado_evidencia:'intento',justificacion:'Orden whoami registrada',rag_procedencia:{clasificacion:'identificada_automaticamente'},
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
