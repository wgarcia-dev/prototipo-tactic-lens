import {useEffect, useRef, useState} from 'react'
import {Link, useNavigate, useParams, useSearchParams} from 'react-router-dom'
import {ArrowLeft, CheckCircle2, Search, Workflow, X} from 'lucide-react'
import {api} from '../auth/client'
import {useAuth} from '../auth/context'
import {AnalysisNarrative, hasCurrentReport, type AnalysisPayload} from '../analysis/AnalysisNarrative'
import {useMonitorQuery as usePolling} from '../monitoring/Realtime'
import {sameSnapshot} from '../monitoring/polling'
import {RagCandidates} from '../analysis/RagCandidates'
import {MitreResults} from '../analysis/MitreResults'
import {useSessionAnalysisRun} from '../analysis/sessionAnalysis'
import {eventEvidencePath, sessionEvidencePath} from '../analysis/iocEvidence'
import {ObservableLinks, type MappingEvidence, type ObservableLink} from '../analysis/IocCorrelations'
import {SessionReport} from '../analysis/SessionReport'
import {AnalysisStatus, type AnalysisValidity, type AttemptStatus} from '../analysis/AnalysisStatus'
import {Header,Metric,ErrorBox,LiveStatus,SessionTable,PAGE_SIZE,usePagedData,Pager,date,analysisActionLabel,type Session,type Event} from './shared'

type AnalysisAction = {id_accion:string,tipo_accion:string,descripcion:string,confianza:number|null,eventos_texto:string[],observables:ObservableLink[],mitre:MappingEvidence[]}
type Analysis = {id_analisis:string,id_sesion:string,estado:string,resumen:string|null,mensaje_error:string|null,vigencia_analisis?:AnalysisValidity|null,estado_ultimo_intento?:AttemptStatus,resultado_estructurado?:AnalysisPayload,acciones:AnalysisAction[]}

const isRag=(analysis:Analysis)=>analysis.resultado_estructurado?.rag?.metodo==='deepseek_rag_mitre_v1'
function originBadge(analysis:Analysis) {
  const rag=analysis.resultado_estructurado?.rag
  const version=rag?.catalogo?.version
  return <span className="badge mb-3">{isRag(analysis)?[rag?.modelo_llm?.modelo,'RAG',version&&'ATT&CK '+version].filter(Boolean).join(' · '):'Análisis histórico guardado'}</span>
}
export function SessionsPage(){
  const navigate=useNavigate()
  const {session:authSession}=useAuth()
  const [params,setParams]=useSearchParams()
  const rawPage=Number(params.get('pagina')??1)
  const page=Number.isSafeInteger(rawPage)&&rawPage>=1&&rawPage<=1000000?rawPage-1:0
  const query=params.get('q')??''
  const [filter,setFilter]=useState(query.trim())
  useEffect(()=>{const timeout=window.setTimeout(()=>setFilter(query.trim()),250);return()=>window.clearTimeout(timeout)},[query])
  function setPage(next:number){
    const updated=new URLSearchParams(params)
    if(next)updated.set('pagina',String(next+1));else updated.delete('pagina')
    setParams(updated)
  }
  function setQuery(value:string){
    const updated=new URLSearchParams(params)
    if(value)updated.set('q',value);else updated.delete('q')
    updated.delete('pagina')
    setParams(updated,{replace:true})
  }
  const [busyId,setBusyId]=useState<string|null>(null)
  const [actionError,setActionError]=useState('')
  const {rows:sessions,hasNext,loading,error}=usePagedData<Session>('/sesiones?q='+encodeURIComponent(filter)+(params.get('modalidad')?'&modalidad='+encodeURIComponent(params.get('modalidad')!):''),page,PAGE_SIZE,1000)
  async function analyze(session:Session){
    setBusyId(session.id_sesion);setActionError('')
    try{
      await api('/sesiones/'+session.id_sesion+'/analizar',{method:'POST'})
      navigate('/sesiones/'+session.id_sesion)
    }catch(e){setActionError((e as Error).message)}
    finally{setBusyId(null)}
  }
  return <>
    <Header title="Sesiones y eventos" description="Historial y cronología de Cowrie" action={authSession?.usuario.rol==='administrador'?<Link className="btn" to="/importar">Importar archivo</Link>:undefined}/>
    {(error||actionError)&&<ErrorBox error={error||actionError}/>}
    <section className="panel p-5">
      <div className="flex flex-wrap gap-3 justify-between items-center mb-5">
        <div><h2 className="font-semibold">Historial de sesiones</h2><p className="muted text-xs mt-1">Busca por sesión o IP</p></div>
        <select aria-label="Modalidad de Cowrie" value={params.get('modalidad')??''} onChange={e=>{const next=new URLSearchParams(params);next.delete('pagina');if(e.target.value)next.set('modalidad',e.target.value);else next.delete('modalidad');setParams(next)}}><option value="">Todas las modalidades</option><option value="cowrie_shell">Shell</option><option value="cowrie_proxy">Proxy</option><option value="cowrie_llm">LLM</option><option value="desconocido">Origen desconocido</option></select>
        <div className="relative"><Search size={15} className="absolute left-3 top-3 muted"/><input aria-label="Buscar sesión o IP" className="bg-[#1a2e46] rounded-md text-sm pl-9 pr-3 py-2 outline-none border border-[#29415a]" placeholder="Filtrar sesión o IP" value={query} onChange={e=>setQuery(e.target.value)}/></div>
      </div>
      {loading?<p className="muted text-sm py-8 text-center">Cargando sesiones…</p>:<SessionTable sessions={sessions} onAnalyze={analyze} busyId={busyId}/>}
      <Pager page={page} pageSize={PAGE_SIZE} count={sessions.length} hasNext={hasNext} onChange={setPage} label="sesiones"/>
    </section>
  </>
}
function ActionEvidence({action,sessionId}: {action:AnalysisAction,sessionId:string}) {
  return <article className="border-t line pt-4 break-words">
    <div className="flex flex-wrap gap-2 items-baseline justify-between">
      <h4 className="text-sm font-semibold">{action.tipo_accion}</h4>
      {action.confianza!=null&&<span className="muted text-xs">{Math.round(action.confianza*100)}% confianza declarada</span>}
    </div>
    <p className="text-sm muted mt-1">{action.descripcion}</p>
    <div className="flex gap-x-2 gap-y-1 flex-wrap text-xs mt-2">
      <span className="muted">Eventos de la acción</span>
      {action.eventos_texto.map(event=><Link className="accent hover:underline" key={event} to={eventEvidencePath(sessionId,event)}>Evento #{event}</Link>)}
    </div>
    {action.observables.length>0&&<details className="text-xs mt-3">
      <summary className="cursor-pointer">Observables respaldados por la acción</summary>
      <ObservableLinks links={action.observables}/>
    </details>}
  </article>
}

export function SessionRoute(){
  const {id}=useParams()
  const [params]=useSearchParams()
  const event=params.get('evento')
  return id && event!==null ? <EventDetail key={id+':'+event} session={id} event={event}/> : <SessionDetail key={id+':'+(params.get('analisis')??'')}/>
}

function EventDetail({session,event}:{session:string,event:string}){
  const navigate=useNavigate()
  const heading=useRef<HTMLHeadingElement>(null)
  const [record,setRecord]=useState<Event|null>(null)
  const [loading,setLoading]=useState(true)
  const [error,setError]=useState('')
  const [attempt,setAttempt]=useState(0)
  const valid=/^(0|[1-9][0-9]{0,18})$/.test(event)&&BigInt(event)<=9223372036854775807n
  useEffect(()=>{
    heading.current?.focus()
    heading.current?.scrollIntoView({block:'start'})
  },[])
  useEffect(()=>{
    if(!valid)return
    const controller=new AbortController()
    setLoading(true);setError('')
    api<Event[]>('/sesiones/'+encodeURIComponent(session)+'/eventos?id_evento='+encodeURIComponent(event)+'&limit=1',{signal:controller.signal})
      .then(rows=>{if(!controller.signal.aborted)setRecord(rows.find(row=>row.id_evento_texto===event)??null)})
      .catch(e=>{if(!controller.signal.aborted)setError((e as Error).message)})
      .finally(()=>{if(!controller.signal.aborted)setLoading(false)})
    return ()=>controller.abort()
  },[session,event,attempt,valid])
  return <section className="panel p-5 space-y-4">
    <h1 ref={heading} tabIndex={-1} className="text-2xl font-bold">{valid?'Evento #'+event:'Referencia de evento inválida'}</h1>
    <div className="flex flex-wrap gap-3">
      {window.history.state?.idx>0&&<button className="btn-secondary" onClick={()=>navigate(-1)}>Volver</button>}
      <Link className="btn-secondary" to={sessionEvidencePath(session)}>Ver sesión completa</Link>
    </div>
    {valid&&(loading?<p role="status">Cargando evidencia…</p>:error?<><ErrorBox error={error}/><button className="btn-secondary" onClick={()=>setAttempt(n=>n+1)}>Reintentar</button></>:record?<article className="space-y-3">
      <h2 className="font-semibold">{record.tipo_evento}</h2><p className="muted">{date(record.fecha_hora)}</p>
      {typeof record.datos_originales.input==='string'&&<div><h3>Comando registrado</h3><pre className="whitespace-pre-wrap break-words">{record.datos_originales.input}</pre></div>}
      <details><summary>Ver campos del evento</summary><pre className="overflow-auto whitespace-pre-wrap break-words mt-2">{JSON.stringify(record.datos_originales,null,2)}</pre></details>
    </article>:<p role="status">No se encontró este evento en la sesión indicada.</p>)}
  </section>
}

function SessionDetail(){
  const {id}=useParams()
  const navigate=useNavigate()
  const [params]=useSearchParams()
  const requestedAnalysis=params.get('analisis')
  const requestedAction=params.get('accion')
  const [session,setSession]=useState<Session|null>(null)
  const [analysis,setAnalysis]=useState<Analysis|null>(null)
  const [error,setError]=useState('')
  const [page,setPage]=useState(0)
  const eventPath='/sesiones/'+id+'/eventos'
  const {rows:events,hasNext,loading,error:eventError}=usePagedData<Event>(eventPath,page,10,1000,session?.eventos??-1)
  useEffect(()=>setPage(0),[id])
  const epoch=useRef(0)
  const submission=useSessionAnalysisRun<Analysis,Session>(id,(detail,current)=>{
    epoch.current++
    setSession(current);setAnalysis(detail)
  })
  useEffect(()=>{setSession(null);setAnalysis(null)},[id,requestedAnalysis])
  usePolling(async signal=>{
    if(!id)return
    const revision=epoch.current
    try{
      const current=await api<Session>('/sesiones/'+id,{signal})
      if(signal.aborted||revision!==epoch.current)return
      setSession(previous=>sameSnapshot(previous,current))
      const key=requestedAnalysis??current.analisis?.id_analisis??null
      const detail=key?await api<Analysis>('/analisis/'+encodeURIComponent(key),{signal}):null
      if(signal.aborted||revision!==epoch.current)return
      if(detail&&detail.id_sesion!==id)throw new Error('El análisis seleccionado pertenece a otra sesión.')
      setAnalysis(previous=>sameSnapshot(previous,detail))
      setError('')
    }catch(failure){if(!signal.aborted&&revision===epoch.current)setError((failure as Error).message);throw failure}
  },5000,[id,requestedAnalysis],['sesiones','analisis','iocs','mitre','salvaguardas'])
  const actions=analysis?.acciones.filter(action=>!requestedAction||action.id_accion===requestedAction)??[]
  const analysisInProgress=submission.busy||session?.estado_analisis==='en_proceso'
  const reportAnalysisId=requestedAnalysis??session?.analisis?.id_analisis
  return <div className="session-workspace">
    <Header title={'Sesión '+(session?.cowrie_session_id||'')} description={session ? "Cronología y evidencia · " + (session.modalidad ?? "desconocido") : "Cronología y evidencia"} action={<button className="btn-secondary flex gap-2 items-center" onClick={()=>window.history.state?.idx>0?navigate(-1):navigate('/sesiones',{replace:true})}><ArrowLeft size={16}/> Volver</button>}/>
    {(submission.error||error)&&<ErrorBox error={submission.error||error}/>}
    {eventError&&<ErrorBox error={eventError}/>}
    {submission.notice&&<div role="status" aria-live="polite" className="flex items-start gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 mb-5 text-sm text-emerald-100">
      <CheckCircle2 size={19} aria-hidden className="shrink-0 mt-0.5 text-emerald-400"/>
      <p className="flex-1">{submission.notice}</p>
      <button type="button" aria-label="Cerrar confirmación" className="shrink-0 rounded p-1 text-emerald-200 hover:bg-emerald-400/15 focus-visible:outline focus-visible:outline-2 focus-visible:outline-emerald-300" onClick={submission.clearNotice}><X size={16} aria-hidden/></button>
    </div>}
    {analysisInProgress&&<div role="status" aria-live="polite" className="panel p-4 mb-5 text-sm">
      <p className="font-semibold">Análisis en curso</p>
      <p className="muted mt-1">TacticLens está procesando los eventos de esta sesión. El resultado y su informe estarán disponibles al finalizar. Puede esperar aquí o volver al historial para consultar el estado.</p>
    </div>}
    {!analysisInProgress&&session&&session.id_sesion===id&&analysis?.id_sesion===id&&analysis?.estado==='completado'&&analysis.id_analisis===reportAnalysisId&&
      <SessionReport key={analysis.id_analisis+':'+session.eventos} id={session.id_sesion} analysisId={analysis.id_analisis}/>}
    <div className="grid gap-5 min-w-0">
      <section className="panel p-5"><h2 className="font-semibold mb-4">Datos de la sesión</h2><dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2 xl:grid-cols-4">{[['ID',session?.id_sesion],['IP de origen',session?.ip_origen],['Inicio',date(session?.fecha_inicio)],['Cierre',date(session?.fecha_fin)]].map(([k,v])=><div className="min-w-0" key={k}><dt className="muted">{k}</dt><dd className="mt-1 break-words">{v||'—'}</dd></div>)}</dl></section>
      <section className="panel p-5">
        <div className="flex justify-between flex-wrap gap-3 mb-5"><div><h2 className="font-semibold">Línea de tiempo</h2><p className="muted text-xs mt-1">{session?.eventos??0} eventos · {session?.ip_origen||'IP desconocida'} · {session?.protocolo||'ssh'}</p></div>
          {requestedAnalysis?<Link className="btn-secondary text-xs" to={sessionEvidencePath(id??'')}>Ver sesión completa</Link>:
            <button className="btn flex gap-2 items-center" onClick={()=>submission.run(!!analysis&&!hasCurrentReport(analysis))} disabled={submission.busy||!session?.eventos||session?.estado_analisis==='en_proceso'}><Workflow size={16}/>{submission.busy?'Analizando...':session?.estado_analisis==='analizada'?'Actualizar análisis':session?analysisActionLabel(session):'Analizar'}</button>}</div>
        {loading?<p className="muted text-sm py-8">Cargando eventos…</p>:<div className="timeline-events border-l border-[#2d5470] ml-2 space-y-5" tabIndex={0} role="region" aria-label="Eventos de la sesión">{events.map(x=><div key={x.id_evento_texto??x.id_evento} className="relative pl-6"><div className="absolute -left-[5px] top-2 w-[9px] h-[9px] rounded-full bg-[#43d7d4]"/><div className="flex flex-wrap gap-3 items-baseline"><span className="text-xs accent font-mono">{date(x.fecha_hora)}</span><span className="font-semibold text-sm">{x.tipo_evento}</span><span className="muted text-[11px]">#{x.id_evento_texto??x.id_evento}</span></div>{typeof x.datos_originales.input==='string'&&<div className="bg-[#0c1728] rounded-md px-3 py-2 text-sm font-mono mt-2 text-[#c4e5e2]">$ {x.datos_originales.input}</div>}<details className="mt-2 text-xs muted"><summary className="cursor-pointer hover:text-white">Ver JSON relevante</summary><pre className="overflow-auto whitespace-pre-wrap bg-[#0c1728] p-3 rounded mt-2">{JSON.stringify(x.datos_originales,null,2)}</pre></details></div>)}{!events.length&&<p className="pl-6 muted text-sm">No hay eventos registrados</p>}</div>}
        <Pager page={page} pageSize={10} count={events.length} hasNext={hasNext} onChange={setPage} label="eventos" total={session?.eventos}/>
      </section>
      <section className="panel p-5 min-w-0"><div className="flex justify-between items-center mb-4"><h2 className="font-semibold">Análisis LLM</h2></div><AnalysisStatus attempt={session?.estado_ultimo_intento} validity={analysis?.vigencia_analisis}/>{!submission.error&&session?.ultimo_intento?.mensaje_error&&<p className="text-sm text-red-200 mb-3">{session.ultimo_intento.mensaje_error}</p>}{analysis?<>{originBadge(analysis)}<MitreResults analysis={analysis} mappings={actions.flatMap(action=>action.mitre)}/><AnalysisNarrative analysis={analysis}/><div className="session-actions">{actions.map(action=>
        <ActionEvidence key={action.id_accion} action={action} sessionId={analysis.id_sesion}/>)}
        {requestedAction&&!analysis.acciones.some(action=>action.id_accion===requestedAction)&&<p className="muted text-sm">La acción solicitada no está en este análisis.</p>}</div></>:<p className="muted text-sm">Esta sesión aún no se ha analizado.</p>}</section>
    </div>
    {id&&<RagCandidates key={id} sessionId={id}/>}
  </div>
}
export function AnalysisPage(){
  const [page,setPage]=useState(0)
  const {rows:sessions,setRows:setSessions,hasNext,loading,error:listError}=usePagedData<Session>('/sesiones',page,10,1000)
  const [selection,setSelection]=useState<string|null>(null)
  const choice=sessions.find(session=>session.id_sesion===selection)??sessions[0]
  const id=choice?.id_sesion
  const [session,setSession]=useState<Session|null>(null)
  const [snapshot,setSnapshot]=useState<Analysis|null>(null)
  const [recentEvents,setRecentEvents]=useState<{id:string;rows:Event[]}|null>(null)
  const [error,setError]=useState('')
  const selected=session?.id_sesion===id?session:choice
  const analysis=snapshot?.id_sesion===id?snapshot:null
  const commands=recentEvents?.id===id?recentEvents?.rows??[]:[]
  const loaded=useRef<{id:string;events:number}|null>(null)
  const epoch=useRef(0)
  const submission=useSessionAnalysisRun<Analysis,Session>(id,(detail,current)=>{
    epoch.current++
    setSnapshot(detail);setSession(current)
    setSessions(rows=>rows.map(row=>row.id_sesion===current.id_sesion?current:row))
  })
  useEffect(()=>{setError('')},[id])

  usePolling(async signal=>{
    if(!id)return
    const revision=epoch.current
    try{
      const current=await api<Session>('/sesiones/'+id,{signal})
      if(signal.aborted||revision!==epoch.current)return
      setSession(previous=>sameSnapshot(previous,current))
      const key=current.analisis?.id_analisis??null
      const last=loaded.current?.id===id?loaded.current:null
      const [detail,recent]=await Promise.all([
        key?api<Analysis>('/analisis/'+encodeURIComponent(key),{signal}):null,
        !last||last.events!==current.eventos?api<Event[]>('/sesiones/'+id+'/eventos?comandos_recientes=true&limit=6',{signal}):null,
      ])
      if(signal.aborted||revision!==epoch.current)return
      if(detail&&detail.id_sesion!==id)throw new Error('El análisis recibido pertenece a otra sesión.')
      setSnapshot(previous=>sameSnapshot(previous,detail))
      if(recent)setRecentEvents(previous=>sameSnapshot(previous,{id,rows:recent}))
      loaded.current={id,events:current.eventos??0}
      setError('')
    }catch(failure){if(!signal.aborted&&revision===epoch.current)setError((failure as Error).message);throw failure}
  },5000,[id],['sesiones','analisis','iocs','mitre','salvaguardas'])

  const completed=sessions.filter(row=>row.analisis).length
  const visibleError=submission.error||error||listError
  return <>
    <Header title="Análisis LLM" description="Actividad e interpretación por sesión" action={<LiveStatus/>}/>
    {visibleError&&<ErrorBox error={visibleError}/>}
    <div className="grid sm:grid-cols-3 gap-4 mb-5">
      <Metric label="Con resultado en página" value={completed} sub="Resultados disponibles"/>
      <Metric label="Pendientes en página" value={sessions.filter(row=>row.estado_analisis==='pendiente').length} sub="Sesiones por revisar" color="blue"/>
      <Metric label="Eventos en sesión" value={selected?.eventos??0} sub="Eventos registrados en Cowrie" color="green"/>
    </div>
    <div className="workspace-columns grid lg:grid-cols-2 gap-5">
      <section className="panel p-5">
        <h2 className="font-semibold mb-4">Sesiones y estado</h2>
        {loading?<p role="status" className="muted text-sm py-8">Cargando sesiones…</p>:
          <ul className="space-y-2">
            {sessions.map(row=><li key={row.id_sesion}>
              <button type="button" aria-pressed={row.id_sesion===id} onClick={()=>setSelection(row.id_sesion)}
                className="w-full rounded-lg border border-[#27415c] px-3 py-2 text-left hover:bg-[#1b3049] aria-pressed:border-teal-400 aria-pressed:bg-[#193247] focus-visible:outline-teal-400">
                <span className="flex items-center justify-between flex-wrap gap-2">
                  <span className="font-mono accent">{row.cowrie_session_id}</span>
                  <AnalysisStatus attempt={row.estado_ultimo_intento} validity={row.vigencia_analisis}/>
                </span>
                <span className="block muted text-xs mt-1">{date(row.fecha_inicio)} · {row.eventos??0} eventos</span>
              </button>
            </li>)}
            {!sessions.length&&<li className="muted text-sm py-4">Sin sesiones para analizar</li>}
          </ul>}
        <Pager page={page} pageSize={10} count={sessions.length} hasNext={hasNext} onChange={next=>{setSelection(null);setPage(next)}} label="sesiones para análisis"/>
      </section>
      <section className="space-y-5 min-w-0">
        <div className="panel p-5">
          <div className="flex flex-wrap justify-between gap-3">
            <h2 className="font-semibold">Resultado del análisis</h2>
            <button className="btn text-xs" disabled={!selected?.eventos||submission.busy||selected.estado_analisis==='en_proceso'}
              onClick={()=>submission.run(!!analysis&&!hasCurrentReport(analysis))}>
              {submission.busy?'Analizando…':selected?.estado_analisis==='analizada'?'Actualizar análisis':selected?.estado_analisis==='en_proceso'?'En proceso':selected?analysisActionLabel(selected):'Analizar sesión'}
            </button>
          </div>
          {submission.notice&&<p role="status" className="muted text-sm mt-3">{submission.notice}</p>}
          <AnalysisStatus attempt={selected?.estado_ultimo_intento} validity={analysis?.vigencia_analisis}/>{selected?.ultimo_intento?.mensaje_error&&!submission.error&&<p className="text-sm text-red-200 mt-3">{selected.ultimo_intento.mensaje_error}</p>}
          {analysis?<div className="mt-4">
            {originBadge(analysis)}
            <MitreResults analysis={analysis} mappings={analysis.acciones.flatMap(action=>action.mitre)}/>
            <AnalysisNarrative analysis={analysis}/>
            {analysis.acciones.length>0&&<h3 className="text-sm font-semibold mt-6 mb-3">Acciones identificadas</h3>}
            <div className="space-y-3">{analysis.acciones.map(action=><ActionEvidence key={action.id_accion} action={action} sessionId={analysis.id_sesion}/>)}</div>
          </div>:<p className="muted text-sm mt-5">{submission.busy?'El resultado se mostrará cuando finalice el análisis.':'Esta sesión todavía no tiene un análisis guardado.'}</p>}
        </div>
        <div className="panel p-5">
          <div className="flex flex-wrap gap-3 justify-between items-baseline">
            <h2 className="font-semibold">Comandos recientes</h2>
            {id&&<Link className="accent text-xs hover:underline" to={sessionEvidencePath(id)}>Ver cronología</Link>}
          </div>
          <ul className="space-y-2 mt-3">{id&&commands.map(event=><li key={event.id_evento_texto??event.id_evento} className="bg-[#0d192a] rounded p-3 text-xs font-mono">
            <span className="break-words">$ {String(event.datos_originales.input??'')}</span>
            <div className="muted mt-1">{date(event.fecha_hora)} · <Link className="accent underline" to={eventEvidencePath(id,event.id_evento_texto??String(event.id_evento))}>Evento #{event.id_evento_texto??event.id_evento}</Link></div>
          </li>)}</ul>
          {!commands.length&&<p className="muted text-sm mt-3">Todavía no hay comandos en esta sesión.</p>}
        </div>
        {id&&<RagCandidates key={id} sessionId={id}/>}
      </section>
    </div>
  </>
}
