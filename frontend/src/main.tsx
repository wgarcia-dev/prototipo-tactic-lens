import React, {useEffect, useRef, useState} from 'react'
import {createRoot} from 'react-dom/client'
import {BrowserRouter, Link, NavLink, Route, Routes, useNavigate, useParams, useSearchParams} from 'react-router-dom'
import {Activity, ArrowLeft, CheckCircle2, Database, FileUp, Fingerprint, LayoutDashboard, Search, Shield, Workflow, X} from 'lucide-react'
import {Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis} from 'recharts'
import './index.css'
import {api, mutate} from './auth/client'
import {AuthProvider, useAuth} from './auth/context'
import {AuthBoundary} from './auth/AuthBoundary'
import {SecurityPage, SessionControls} from './auth/SecurityPage'
import {AdminUsers} from './auth/AdminUsers'
import {AdminOnly} from './auth/AdminOnly'
import {AnalysisNarrative, hasCurrentReport, type AnalysisPayload} from './analysis/AnalysisNarrative'
import {useMonitorQuery as usePolling, RealtimeProvider, useRealtime} from './monitoring/Realtime'
import {sameSnapshot} from './monitoring/polling'
import {RagCandidates} from './analysis/RagCandidates'
import {MitreResults} from './analysis/MitreResults'
import {IOC_FILTERS,IocFilters,IocOverview,IocProfile,IocReviewStateBadge,IocSessions,withFilters,type ObservableRow} from './analysis/IocDashboard'
import {CountLabels, MitreMatrix, MitreOverview, MitreTechniqueProfile, modalities} from './analysis/MitreDashboard'
import {useSessionAnalysisRun} from './analysis/sessionAnalysis'
import {
  actionEvidencePath, behaviorLabels, eventEvidencePath, evidenceLabels, isAutomaticMapping,
  mappingReviewLabels, mitreBrowseStates, mitreGradeLabels, reviewLabels, scopeLabels, sessionEvidencePath, type RelationState,
} from './analysis/iocEvidence'
import {
  EvidenceEvents, MappingObservables, MappingStatus, ObservableLinks, ObservedRelation, RelationBadge, RelationLimits,
  TechniqueRelation, type ActionLink, type MappingEvidence, type ObservableLink, type ObservedCorrelation,
} from './analysis/IocCorrelations'

import {SessionReport} from './analysis/SessionReport'

type Session = {modalidad?:string,id_sesion:string,cowrie_session_id:string,ip_origen:string|null,fecha_inicio:string,fecha_fin:string|null,protocolo?:string,eventos?:number,estado_analisis?:'pendiente'|'en_proceso'|'analizada'|'error',analisis_desactualizado?:boolean,analisis?:{id_analisis:string,estado:string}|null,ultimo_intento?:{id_analisis:string,estado:string,mensaje_error:string|null}|null}
type Event = {id_evento:number,id_evento_texto?:string,tipo_evento:string,fecha_hora:string,datos_originales:Record<string,unknown>}
type RecentCommand = {id_evento:number,id_evento_texto:string,id_sesion:string,fecha_hora:string,comando:string}
type Dashboard = {por_modalidad?:Record<string,{sesiones:number,eventos:number}>,ultimos_comandos:RecentCommand[],sesiones:number,eventos:number,sesiones_analizadas:number,iocs:number,tecnicas_mitre:number,actividad:{dia:string,total:number}[],tipos_evento:{tipo_evento:string,total:number}[],ultimo_evento:string|null,collector_last_seen:string|null}
type AnalysisAction = {id_accion:string,tipo_accion:string,descripcion:string,confianza:number|null,eventos_texto:string[],observables:ObservableLink[],mitre:MappingEvidence[]}
type Analysis = {id_analisis:string,id_sesion:string,estado:string,resumen:string|null,mensaje_error:string|null,resultado_estructurado?:AnalysisPayload,acciones:AnalysisAction[]}

const isRag=(analysis:Analysis)=>analysis.resultado_estructurado?.rag?.metodo==='deepseek_rag_mitre_v1'
function originBadge(analysis:Analysis) {
  const rag=analysis.resultado_estructurado?.rag
  const version=rag?.catalogo?.version
  return <span className="badge mb-3">{isRag(analysis)?[rag?.modelo_llm?.modelo,'RAG',version&&'ATT&CK '+version].filter(Boolean).join(' · '):'Análisis histórico guardado'}</span>
}
const date=(v?:string|null)=>v?new Date(v).toLocaleString('es-EC',{dateStyle:'short',timeStyle:'short',timeZone:'America/Guayaquil'}):'—'
const badge=(status?:string|null)=><span className={'badge '+(['fallido','error'].includes(status||'')?'error':['pendiente','en_proceso'].includes(status||'')?'warn':'')}>{status==='analizada'||status==='completado'?'Analizada':status==='en_proceso'?'En proceso':status==='error'||status==='fallido'?'Análisis fallido':'Pendiente'}</span>
const analysisActionLabel=(session:Session)=>session.estado_analisis==='error'?'Reintentar':session.analisis_desactualizado?'Actualizar análisis':'Analizar'

const nav=[['/','Panel principal',LayoutDashboard],['/sesiones','Sesiones y eventos',Database],['/analisis','Análisis LLM',Workflow],['/iocs','Observables e IoCs',Fingerprint],['/mitre','MITRE ATT&CK',Shield],['/importar','Importar Cowrie',FileUp]] as const
function Shell({children}:{children:React.ReactNode}){const {session}=useAuth();return <div className="min-h-screen md:flex"><aside className="w-full md:w-60 md:sticky md:top-0 md:self-start md:max-h-dvh md:overflow-y-auto bg-[#0f1b2e] border-r line flex flex-col shrink-0"><div className="h-20 flex items-center gap-3 px-6 border-b line"><div className="w-9 h-9 rounded-lg bg-[#164b56] flex items-center justify-center text-[#5ce5de]"><Activity size={21}/></div><div><div className="font-bold tracking-wide text-lg">TacticLens</div><div className="text-[10px] tracking-[.2em] accent">OBSERVATORIO COWRIE</div></div></div><div className="px-5 pt-4 pb-2 text-[10px] tracking-[.13em] muted">NAVEGACIÓN</div><nav className="px-3 space-y-1">{nav.filter(([href])=>href!=='/importar'||session?.usuario.rol==='administrador').map(([href,label,Icon])=><NavLink key={href} to={href} end={href==='/'} className={({isActive})=>`flex items-center gap-3 px-4 py-3 rounded-lg text-sm ${isActive?'bg-[#1b3851] text-white border-l-[3px] border-[#43d7d4]':'text-[#8ea3bb] hover:bg-[#172b42]'}`}><Icon size={16}/>{label}</NavLink>)}</nav><div className="mt-3 px-5 py-4 border-t line text-xs muted"><SessionControls/><span className="inline-block w-2 h-2 rounded-full bg-emerald-400 mr-2"/>Cowrie · entorno controlado<br/><span className="text-[10px]">Prototipo de tesis · UNEMI</span></div></aside><main className="flex-1 min-w-0 bg-[#0b1423]"><div className="max-w-[1500px] mx-auto px-5 md:px-9 py-8">{children}</div></main></div>}
function Header({title,description,action}:{title:string,description:string,action?:React.ReactNode}){return <div className="flex flex-wrap items-start justify-between gap-4 pb-6 border-b line mb-7"><div><h1 className="text-2xl md:text-3xl font-bold tracking-tight">{title}</h1><p className="muted text-sm mt-1">{description}</p></div>{action}</div>}
function Metric({label,value,sub,color='cyan'}:{label:string,value:number|string,sub:string,color?:string}){return <div className={`panel p-5 border-l-[3px] ${color==='blue'?'border-l-blue-500':color==='purple'?'border-l-violet-400':color==='green'?'border-l-emerald-400':'border-l-cyan-400'}`}><div className="muted text-[11px] tracking-wide uppercase">{label}</div><div className="text-3xl font-bold mt-3">{value}</div><div className="muted text-xs mt-2">{sub}</div></div>}
function ErrorBox({error}:{error:string}){return <div className="panel p-4 border-red-700 text-red-200">{error}</div>}
function LiveStatus(){const [seen,setSeen]=useState<string|null>(null);usePolling(async signal=>{try{const x=await api<{collector_last_seen:string|null}>('/health',{signal});if(!signal.aborted)setSeen(x.collector_last_seen)}catch(e){if(!signal.aborted)setSeen(null);throw e}},5000);const active=!!seen&&Date.now()-new Date(seen).getTime()<15000;return <span className={'badge '+(active?'':'warn')}>{active?'RECOLECTOR CONECTADO':'SIN SEÑAL DEL RECOLECTOR'}</span>}
function DashboardPage(){
  const realtime=useRealtime()
  const [data,setData]=useState<Dashboard|null>(null),[sessions,setSessions]=useState<Session[]>([]),[error,setError]=useState('')
  usePolling(async signal=>{
    try {
      const results=await Promise.allSettled([api<Dashboard>('/dashboard/resumen',{signal}),api<Session[]>('/sesiones?limit=5',{signal})])
      if(signal.aborted)return
      const [summary,recent]=results
      if(summary.status==='rejected')throw summary.reason
      if(recent.status==='rejected')throw recent.reason
      setData(previous=>sameSnapshot(previous,{...summary.value,
        actividad:sameSnapshot(previous?.actividad??[],summary.value.actividad),
        tipos_evento:sameSnapshot(previous?.tipos_evento??[],summary.value.tipos_evento),
        ultimos_comandos:sameSnapshot(previous?.ultimos_comandos??[],summary.value.ultimos_comandos)}))
      setSessions(previous=>sameSnapshot(previous,recent.value));setError('')
    }catch(e){if(!signal.aborted)setError((e as Error).message);throw e}
  })
  return <><Header title="Panel principal" description="Actividad del honeypot"/>{error&&<ErrorBox error={error}/>}<div className="grid sm:grid-cols-2 xl:grid-cols-5 gap-4 mb-5"><Metric label="Sesiones registradas" value={data?.sesiones??'—'} sub="Sesiones almacenadas"/><Metric label="Eventos recibidos" value={data?.eventos??'—'} sub="Vinculados a sesiones" color="blue"/><Metric label="Sesiones analizadas" value={data?.sesiones_analizadas??'—'} sub="Análisis completados" color="green"/><Metric label="Observables registrados" value={data?.iocs??'—'} sub="Con evidencia de Cowrie" color="purple"/><Metric label="Técnicas MITRE" value={data?.tecnicas_mitre??'—'} sub="Asociaciones registradas" color="green"/></div><div className="grid lg:grid-cols-[1.7fr_1fr] gap-5 mb-5"><section className="panel p-5"><h2 className="font-semibold">Actividad de eventos</h2><ul className="muted text-xs">{Object.entries(data?.por_modalidad??{}).map(([nombre,total])=><li key={nombre}>{nombre} · {total.sesiones} sesiones · {total.eventos} eventos</li>)}</ul><p className="muted text-xs mt-1">Cantidad de eventos registrados por día</p><div className="h-60 mt-5">{data?.actividad.length?<ResponsiveContainer width="100%" height="100%"><BarChart data={data.actividad}><CartesianGrid stroke="#20344d" vertical={false}/><XAxis dataKey="dia" tick={{fill:'#8ea3bb',fontSize:11}}/><YAxis tick={{fill:'#8ea3bb',fontSize:11}}/><Tooltip contentStyle={{background:'#16273f',border:'1px solid #27415c',color:'#fff'}}/><Bar isAnimationActive={false} dataKey="total" fill="#4180aa" radius={[4,4,0,0]}/></BarChart></ResponsiveContainer>:<div className="muted text-sm pt-20 text-center">Sin eventos todavía</div>}</div></section><section className="panel p-5"><h2 className="font-semibold">Eventos por tipo</h2><p className="muted text-xs mt-1">Distribución observada en PostgreSQL</p><div className="mt-6 space-y-4">{data?.tipos_evento.map(x=><div key={x.tipo_evento}><div className="flex justify-between text-xs mb-2 gap-3"><span className="truncate">{x.tipo_evento}</span><span className="accent">{x.total}</span></div><div className="h-2 rounded-full bg-[#24384f]"><div className="h-2 rounded-full bg-[#42caca]" style={{width:`${Math.max(4,(x.total/(data.tipos_evento[0]?.total||1))*100)}%`}}/></div></div>)}</div></section></div><section className="panel p-5"><div className="flex justify-between items-start mb-4"><div><h2 className="font-semibold">Sesiones recientes</h2><p className="muted text-xs mt-1">Accesos capturados por Cowrie</p></div><Link className="btn text-xs" to="/sesiones">Ver todas</Link></div><SessionTable sessions={sessions}/></section><section className="panel p-5 mt-5" aria-label="Comandos recientes"><h2 className="font-semibold">Últimos comandos observados</h2><p className="muted text-xs mt-1">Actualizaciones por WebSocket · el análisis LLM se ejecuta manualmente</p><ul className="mt-4 space-y-3" aria-live="polite">{data?.ultimos_comandos?.map(command=><li key={command.id_evento_texto} data-evento={command.id_evento_texto} ref={node=>{if(node&&!node.dataset.renderizadoEn){node.dataset.renderizadoEn=new Date().toISOString();if(realtime.notice?.eventos?.includes(command.id_evento)){node.dataset.recibidoApi=realtime.notice.recibido_api;node.dataset.confirmadoApi=realtime.notice.confirmado_api}}}} className="bg-[#0c1728] rounded p-3"><code className="block text-sm break-all whitespace-pre-wrap">{command.comando}</code><div className="flex flex-wrap gap-3 mt-2 text-xs muted"><span>{date(command.fecha_hora)}</span><Link className="accent" to={'/sesiones/'+command.id_sesion}>Ver sesión</Link><Link className="accent underline" to={eventEvidencePath(command.id_sesion,command.id_evento_texto)}>Evento #{command.id_evento_texto}</Link></div></li>)}</ul>{!data?.ultimos_comandos?.length&&<p className="muted text-sm mt-4">Sin comandos registrados todavía.</p>}</section></>}
function SessionTable({sessions,onAnalyze,busyId}:{sessions:Session[],onAnalyze?:(session:Session)=>void,busyId?:string|null}){
  return <div className="overflow-x-auto"><table className="w-full text-sm">
    <thead className="bg-[#1b3049] text-[#a9bdd2] text-left text-xs"><tr><th className="p-3">Sesión</th><th className="p-3">IP de origen</th><th className="p-3">Inicio</th><th className="p-3">Protocolo</th><th className="p-3">Eventos</th><th className="p-3">Análisis</th>{onAnalyze&&<th className="p-3">Acción</th>}</tr></thead>
    <tbody>{sessions.map(x=><tr key={x.id_sesion} className="table-row border-b line"><td className="p-3"><Link className="accent hover:underline font-mono" to={'/sesiones/'+x.id_sesion}>{x.cowrie_session_id}</Link><div className="muted text-xs">{x.modalidad ?? "desconocido"}</div></td><td className="p-3">{x.ip_origen||'?'}</td><td className="p-3 muted">{date(x.fecha_inicio)}</td><td className="p-3">{x.protocolo||'ssh'}</td><td className="p-3">{x.eventos??'?'}</td><td className="p-3">{x.analisis_desactualizado&&x.estado_analisis==='pendiente'?<span className="badge warn">Por actualizar</span>:badge(x.estado_analisis)}</td>{onAnalyze&&<td className="p-3">{x.estado_analisis==='analizada'?<Link className="btn-secondary text-xs" to={'/sesiones/'+x.id_sesion}>Ver resultado</Link>:<button className="btn-secondary text-xs" disabled={!x.eventos||x.estado_analisis==='en_proceso'||!!busyId} onClick={()=>onAnalyze(x)}>{busyId===x.id_sesion?'Analizando…':x.estado_analisis==='en_proceso'?'En proceso':analysisActionLabel(x)}</button>}</td>}</tr>)}</tbody>
  </table>{!sessions.length&&<p className="muted text-sm p-5 text-center">No hay sesiones para mostrar</p>}</div>
}
const PAGE_SIZE = 15

function usePagedData<T>(path:string,page:number,pageSize=PAGE_SIZE,interval=5000,revision?:number){
  const [rows,setRows]=useState<T[]>([]),[hasNext,setHasNext]=useState(false)
  const [loading,setLoading]=useState(true),[error,setError]=useState('')
  const loaded=useRef<{url:string,revision:number|undefined}|null>(null)
  useEffect(()=>{setLoading(true);setError('')},[path,page,pageSize])
  usePolling(async signal=>{
    const separator=path.includes('?')?'&':'?'
    const url=path+separator+'limit='+(pageSize+1)+'&offset='+(page*pageSize)
    if(revision===-1||(revision!==undefined&&loaded.current?.url===url&&loaded.current.revision===revision))return
    try{
      const result=await api<T[]>(url,{signal})
      if(signal.aborted)return
      setRows(previous=>sameSnapshot(previous,result.slice(0,pageSize)))
      loaded.current={url,revision}
      setHasNext(result.length>pageSize);setError('')
    }catch(e){if(!signal.aborted)setError((e as Error).message);throw e}
    finally{if(!signal.aborted)setLoading(false)}
  },interval,[path,page,pageSize,revision])
  return {rows,setRows,hasNext,loading,error}
}

function Pager({page,pageSize,count,hasNext,onChange,label,total}:{page:number,pageSize:number,count:number,hasNext:boolean,onChange:(page:number)=>void,label:string,total?:number}){
  const pages=total===undefined?undefined:Math.max(1,Math.ceil(total/pageSize))
  return <nav className="pager" aria-label={'Paginacion de '+label}>
    <span className="muted text-xs" aria-live="polite">{count ? 'Mostrando '+(page*pageSize+1)+'–'+(page*pageSize+count)+(total===undefined?'':' de '+total) : 'Sin resultados'} · Página {page+1}{pages===undefined?'':' de '+pages}{!hasNext&&page>0?' · Última página':''}</span>
    {(page>0||hasNext)&&<div className="flex gap-2">
      <button type="button" className="btn-secondary" disabled={page===0} onClick={()=>onChange(page-1)}>Anterior</button>
      <button type="button" className="btn-secondary" disabled={!hasNext} onClick={()=>onChange(page+1)}>Siguiente</button>
    </div>}
  </nav>
}

function SessionsPage(){
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

function SessionRoute(){
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
  const loadedAnalysis=useRef<{id:string|null;at:number}|null>(null)
  const epoch=useRef(0)
  const submission=useSessionAnalysisRun<Analysis,Session>(id,(detail,current)=>{
    epoch.current++
    loadedAnalysis.current={id:detail.id_analisis,at:Date.now()}
    setSession(current);setAnalysis(detail)
  })
  useEffect(()=>{loadedAnalysis.current=null;setSession(null);setAnalysis(null)},[id,requestedAnalysis])
  usePolling(async signal=>{
    if(!id)return
    const revision=epoch.current
    try{
      const current=await api<Session>('/sesiones/'+id,{signal})
      if(signal.aborted||revision!==epoch.current)return
      setSession(previous=>sameSnapshot(previous,current))
      const key=requestedAnalysis??current.analisis?.id_analisis??null
      if(key!==loadedAnalysis.current?.id||(key&&Date.now()-(loadedAnalysis.current?.at??0)>=5000)){
        const detail=key?await api<Analysis>('/analisis/'+encodeURIComponent(key),{signal}):null
        if(signal.aborted||revision!==epoch.current)return
        if(detail&&detail.id_sesion!==id)throw new Error('El análisis seleccionado pertenece a otra sesión.')
        setAnalysis(previous=>sameSnapshot(previous,detail));loadedAnalysis.current={id:key,at:Date.now()}
      }
      setError('')
    }catch(failure){if(!signal.aborted&&revision===epoch.current)setError((failure as Error).message);throw failure}
  },5000,[id,requestedAnalysis])
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
      <section className="panel p-5 min-w-0"><div className="flex justify-between items-center mb-4"><h2 className="font-semibold">Análisis LLM</h2>{analysis&&badge(analysis.estado)}</div>{session?.analisis_desactualizado&&<p className="badge warn mb-3">Resultado anterior: hay eventos nuevos</p>}{!submission.error&&session?.ultimo_intento?.estado==='fallido'&&<p className="text-sm text-red-200 mb-3">Análisis fallido. {session.ultimo_intento.mensaje_error}</p>}{analysis?<>{originBadge(analysis)}<MitreResults analysis={analysis} mappings={actions.flatMap(action=>action.mitre)}/><AnalysisNarrative analysis={analysis}/><div className="session-actions">{actions.map(action=>
        <ActionEvidence key={action.id_accion} action={action} sessionId={analysis.id_sesion}/>)}
        {requestedAction&&!analysis.acciones.some(action=>action.id_accion===requestedAction)&&<p className="muted text-sm">La acción solicitada no está en este análisis.</p>}</div></>:<p className="muted text-sm">Esta sesión aún no se ha analizado.</p>}</section>
    </div>
    {id&&<RagCandidates key={id} sessionId={id}/>}
  </div>
}
function AnalysisPage(){
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
  const loaded=useRef<{id:string;events:number;analysis:string|null;at:number}|null>(null)
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
      const refreshAnalysis=!last||last.analysis!==key||!!key&&Date.now()-last.at>=5000
      const [detail,recent]=await Promise.all([
        refreshAnalysis&&key?api<Analysis>('/analisis/'+encodeURIComponent(key),{signal}):null,
        !last||last.events!==current.eventos?api<Event[]>('/sesiones/'+id+'/eventos?comandos_recientes=true&limit=6',{signal}):null,
      ])
      if(signal.aborted||revision!==epoch.current)return
      if(detail&&detail.id_sesion!==id)throw new Error('El análisis recibido pertenece a otra sesión.')
      if(refreshAnalysis)setSnapshot(previous=>sameSnapshot(previous,detail))
      if(recent)setRecentEvents(previous=>sameSnapshot(previous,{id,rows:recent}))
      loaded.current={id,events:current.eventos??0,analysis:key,at:refreshAnalysis?Date.now():last?.at??0}
      setError('')
    }catch(failure){if(!signal.aborted&&revision===epoch.current)setError((failure as Error).message);throw failure}
  },5000,[id])

  const completed=sessions.filter(row=>row.estado_analisis==='analizada').length
  const newer=analysis?.resultado_estructurado?.eventos_analizados!==undefined&&(selected?.eventos??0)>analysis.resultado_estructurado.eventos_analizados
  const visibleError=submission.error||error||listError
  return <>
    <Header title="Análisis LLM" description="Actividad e interpretación por sesión" action={<LiveStatus/>}/>
    {visibleError&&<ErrorBox error={visibleError}/>}
    <div className="grid sm:grid-cols-3 gap-4 mb-5">
      <Metric label="Completados en página" value={completed} sub="Resultados disponibles"/>
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
                  {row.analisis_desactualizado&&row.estado_analisis==='pendiente'?<span className="badge warn">Por actualizar</span>:badge(row.estado_analisis)}
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
          {selected?.ultimo_intento?.estado==='fallido'&&!submission.error&&<p className="text-sm text-red-200 mt-3">Análisis fallido. {selected.ultimo_intento.mensaje_error}</p>}
          {newer&&<p className="badge warn mt-4">Hay eventos posteriores al último análisis</p>}
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

function ImportPage(){const [file,setFile]=useState<File|null>(null),[result,setResult]=useState<unknown>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);async function submit(){if(!file)return;setBusy(true);setError('');try{const body=new FormData();body.append('file',file);setResult(await api('/ingesta/cowrie',{method:'POST',body}))}catch(e){setError((e as Error).message)}finally{setBusy(false)}}return <><Header title="Importar registros Cowrie" description="Importación de registros JSONL"/><div className="panel p-6 max-w-2xl"><div className="flex items-start gap-4"><FileUp size={30} className="accent"/><div><h2 className="font-semibold">Archivo cowrie.json</h2><p className="muted text-sm mt-1">Máximo 10 MB. Cada línea se valida de forma independiente. La reimportación evita duplicados.</p></div></div><input type="file" accept=".json,.jsonl" className="block mt-7 text-sm" onChange={e=>setFile(e.target.files?.[0]||null)}/><button className="btn mt-6" disabled={!file||busy} onClick={submit}>{busy?'Importando…':'Importar eventos'}</button>{error&&<div className="mt-5"><ErrorBox error={error}/></div>}{result!==null&&<pre className="bg-[#0c1728] p-4 rounded mt-5 overflow-auto text-sm">{JSON.stringify(result,null,2)}</pre>}</div></>}
type ReviewState='pendiente'|'confirmado'|'descartado'|'mixto'
type IocObservation = {
  id_observacion: string, id_sesion: string, id_evento: string, tipo_evento: string, fecha_hora: string,
  ingresado_en: string, numero_secuencia: number, estado_relacion: RelationState,
  evidencia: string, estado_revision: ReviewState, motivo_revision: string|null, revisado_en: string|null,
  datos_originales: Record<string, unknown>,
  revisado_por?:string;modalidad?:string;sensor?:string;cowrie_session_id?:string,
  acciones: ActionLink[], correlaciones: ObservedCorrelation[],
  detalles: {
    valor_original: string, campo: string, metodo: string, comportamiento: string, grado_evidencia: string,
    limitacion: string, alcance_ip: string|null, algoritmo: string|null, posicion: number|null
  }[]
}
type MitreRow=Omit<MappingEvidence,'eventos'|'estado_revision'>&{
  id_analisis:string;id_sesion:string;cowrie_session_id:string;modalidad:string;
  fecha_analisis:string|null;fecha_mapeo:string;version_pipeline?:string|null;version_informe?:string|null;
  estado_revision:ReviewState;tipo_accion:string;descripcion_accion:string;revisado_en?:string|null;evidencia?:string|null;
  confianza?:number|null;
}
function ReviewControls({kind,id,state,canConfirm=true,automatic=false,onReviewed}:{kind:'observacion_ioc'|'mitre',id:string,state:ReviewState,canConfirm?:boolean,automatic?:boolean,onReviewed?:(state:ReviewState)=>void}){
  const {session}=useAuth(),[busy,setBusy]=useState(false),[error,setError]=useState('')
  const [decision,setDecision]=useState<'confirmado'|'descartado'|null>(null)
  const [reason,setReason]=useState('')
  const [current,setCurrent]=useState(state)
  useEffect(()=>setCurrent(state),[state])
  const observable=kind==='observacion_ioc'
  async function review(){
    const motivo=reason.trim()
    if(!decision||motivo.length<10){setError('Escriba un motivo de al menos 10 caracteres.');return}
    setBusy(true);setError('')
    try{await mutate(`/inteligencia/${kind}/${id}/revision`,{estado:decision,motivo},'PATCH');setCurrent(decision);onReviewed?.(decision);setDecision(null);setReason('')}
    catch(e){setError((e as Error).message)}finally{setBusy(false)}
  }
  return <div className="mt-2">
    <span className={'badge '+(current==='pendiente'?'warn':'')} aria-live="polite">
      {observable?reviewLabels[current]:automatic?(current==='pendiente'?'Sin revisión administrativa':current==='confirmado'?'Confirmada en revisión':'Descartada en revisión'):mappingReviewLabels[current]}
    </span>
    {session?.usuario.rol==='administrador'&&<div className="flex flex-wrap gap-2 mt-2">
      {canConfirm&&<button className="btn text-xs" disabled={busy} onClick={()=>setDecision('confirmado')}>{observable?'Confirmar relevancia':'Confirmar mapeo'}</button>}
      <button className="btn text-xs" disabled={busy} onClick={()=>setDecision('descartado')}>{observable?'Descartar relevancia':'Descartar mapeo'}</button>
    </div>}
    {decision&&<div className="mt-2">
      <label className="block text-xs muted" htmlFor={`review-${id}`}>Motivo de la revisión</label>
      <textarea id={`review-${id}`} className="w-full bg-[#0d192a] border line rounded p-2 mt-1 text-sm" maxLength={500} value={reason} onChange={e=>setReason(e.target.value)}/>
      <div className="flex gap-2 mt-2">
        <button className="btn text-xs" disabled={busy||reason.trim().length<10} onClick={review}>Guardar revisión</button>
        <button className="btn text-xs" disabled={busy} onClick={()=>{setDecision(null);setReason('');setError('')}}>Cancelar</button>
      </div>
    </div>}
    {error&&<p role="alert" className="text-red-300 text-xs mt-2">{error}</p>}
  </div>
}

function IocObservations({id,eventId,filter,relations=false,onReviewed}: {
  id:string;eventId:string|null;filter:string;relations?:boolean;onReviewed:()=>void
}) {
  const [page,setPage]=useState(0)
  const [category,setCategory]=useState(relations?'todas':'prioritarias')
  const [order,setOrder]=useState('relevancia')
  const query=new URLSearchParams(filter)
  query.set('vista_segura','true');query.set('categoria',category);query.set('orden_evidencia',order)
  if(eventId)query.set('id_evento',eventId)
  const path='/iocs/'+encodeURIComponent(id)+'/observaciones?'+query
  const {rows,hasNext,loading,error}=usePagedData<IocObservation>(path,eventId?0:page,10)
  return <section id="ioc-observations" aria-label="Observaciones del valor seleccionado" className="panel p-5 min-w-0">
    <h2 className="font-semibold">{relations?'Red de correlaciones':'Evidencia de Cowrie'}</h2>
    <p className="muted text-xs mt-1">{relations?'Sigue los enlaces de sesión, evento, acción, técnica y observable respaldados por cada registro.':'La prioridad ordena por el contexto y el tipo de evento. Los eventos de ciclo de vida siguen disponibles.'}</p>
    {!eventId&&<div className="flex flex-wrap gap-3 mt-3 text-xs">
      <label>Categoría <select className="bg-[#1a2e46] rounded border line px-2 py-1" value={category} onChange={event=>{setCategory(event.target.value);setPage(0)}}>
        {Object.entries({prioritarias:'Evidencias prioritarias',todas:'Todos los eventos',autenticacion:'Autenticación',
          comandos:'Comandos',transferencias:'Transferencias',dns:'Comandos DNS',conexiones:'Conexiones',desconexiones:'Desconexiones',ssh:'Huella del cliente SSH'})
          .map(([key,label])=><option key={key} value={key}>{label}</option>)}
      </select></label>
      <label>Orden <select className="bg-[#1a2e46] rounded border line px-2 py-1" value={order} onChange={event=>{setOrder(event.target.value);setPage(0)}}>
        <option value="relevancia">Prioridad contextual</option><option value="recientes">Más recientes</option><option value="antiguas">Más antiguas</option>
      </select></label>
    </div>}
    {error&&<ErrorBox error={error}/>}
    {loading?<p className="muted text-sm mt-4" role="status">Cargando observaciones…</p>:
      <ul className="mt-4">
        {rows.map(row=><li key={row.id_observacion} className="py-4 min-w-0 border-b line last:border-b-0">
          <div className="flex flex-wrap gap-x-3 gap-y-1 items-baseline">
            <strong className="text-sm break-all">{row.tipo_evento}</strong>
            <Link className="accent text-xs hover:underline" to={eventEvidencePath(row.id_sesion,row.id_evento)}>#{row.id_evento}</Link>
            <span className="muted text-xs">Hora de Cowrie {date(row.fecha_hora)}</span>
            <Link className="accent text-xs hover:underline break-all" to={sessionEvidencePath(row.id_sesion)} title={row.id_sesion}>Sesión {row.cowrie_session_id??row.id_sesion.slice(0,8)}</Link>
            <RelationBadge state={row.estado_relacion}/>
          </div>
          <p className="muted text-xs mt-1">{modalities[row.modalidad??'desconocido']} · {row.sensor??'Sensor sin registro'} · Ingesta {date(row.ingresado_en)} · Secuencia {row.numero_secuencia}</p>
          {!relations&&<>{row.detalles.length===0?<p className="text-sm muted mt-3">
            <span className="badge warn">Evidencia histórica</span> {row.evidencia}. El extractor actual no ha verificado este valor.
          </p>:<ul className="space-y-3 mt-3">
            {row.detalles.map((detail,index)=><li key={detail.campo+'-'+(detail.posicion??index)} className="border-l line pl-3">
              <div className="flex flex-wrap gap-2 items-baseline">
                <strong className="text-sm">{behaviorLabels[detail.comportamiento]??detail.comportamiento}</strong>
                <span className="badge">{evidenceLabels[detail.grado_evidencia]??detail.grado_evidencia}</span>
              </div>
              <dl className="text-xs mt-2 space-y-1">
                <div><dt className="inline muted">Valor original </dt><dd className="inline font-mono break-all">{detail.valor_original}</dd></div>
                <div><dt className="inline muted">Campo </dt><dd className="inline">
                  <code>{detail.campo}</code>
                  <span className="muted"> · {detail.metodo==='campo_cowrie'?'Campo de Cowrie':'Argumento del comando'}</span>
                  {detail.alcance_ip&&<span className="muted"> · {scopeLabels[detail.alcance_ip]??detail.alcance_ip}</span>}
                  {detail.algoritmo&&<span className="muted"> · {detail.algoritmo}</span>}
                </dd>
                </div>
              </dl>
              <p className="text-xs muted mt-2">{detail.limitacion}</p>
            </li>)}
          </ul>}
          {typeof row.datos_originales.input==='string'&&<p className="text-xs mt-3 break-all"><span className="muted">Entrada registrada </span><code>{row.datos_originales.input}</code></p>}
          <details className="text-xs muted mt-3">
            <summary className="cursor-pointer hover:text-white">Ver JSON del evento</summary>
            <pre className="overflow-auto max-h-64 whitespace-pre-wrap break-all border line rounded p-3 mt-2">{JSON.stringify(row.datos_originales,null,2)}</pre>
          </details></>}
          {row.correlaciones.length>0&&<section className="text-xs mt-4">
            <h3 className="font-semibold mb-2">Relaciones con otros comportamientos y valores</h3>
            <ul className="space-y-3">{row.correlaciones.map(relation=><ObservedRelation
              key={relation.tipo+(relation.observable?.id_ioc??'')} correlation={relation}/>)}</ul>
          </section>}
          {row.acciones.length>0&&<details open={relations||undefined} className="text-xs mt-4">
            <summary className="cursor-pointer hover:underline">Acciones y técnicas asociadas</summary>
            <ul className="space-y-3 mt-2">{row.acciones.map(action=><li key={action.id_accion} className="break-words border-l line pl-3">
              <div className="flex flex-wrap gap-2 items-baseline">
                <Link className="accent hover:underline" to={actionEvidencePath(row.id_sesion,action.id_analisis,action.id_accion)}>{action.tipo_accion}</Link>
                <RelationBadge state={action.estado}/>
              </div>
              <p className="mt-1">{action.interpretacion}</p><p className="muted mt-1">{action.justificacion}</p>
              <RelationLimits limits={action.limitaciones}/>
              <EvidenceEvents events={action.eventos}/>
              {action.tecnicas.length>0?<ul className="space-y-3 mt-3">{action.tecnicas.map(mapping=>
                <TechniqueRelation key={mapping.id_mapeo} mapping={mapping}/>)}</ul>:
                <p className="muted mt-2">Ninguna técnica de la acción comparte evidencia verificable para este observable.</p>}
            </li>)}</ul>
          </details>}
          {relations&&!row.acciones.length&&!row.correlaciones.length&&<p className="muted text-xs mt-2">Este evento vincula el registro con su sesión. Sin acciones, técnicas u otros artefactos correlacionados.</p>}
          {!relations&&<details className="mt-3 border-t line pt-2">
            <summary className="cursor-pointer text-sm">Procedencia y revisión</summary>
            <p className="muted text-xs mt-2">{row.detalles.length?'Fuente primaria Cowrie. La ficha muestra el valor normalizado.':'Registro histórico sin método de extracción acreditado.'}</p>
            <ReviewControls kind="observacion_ioc" id={row.id_observacion} state={row.estado_revision} canConfirm={row.detalles.length>0} onReviewed={onReviewed}/>
            {row.motivo_revision&&<p className="text-xs muted mt-2 break-words">{row.motivo_revision} · {date(row.revisado_en)}{row.revisado_por?' · Revisor '+row.revisado_por:''}</p>}
          </details>}
        </li>)}
      </ul>}
    {!loading&&!error&&!rows.length&&<p className="muted text-sm mt-4">{eventId?'No se encontró esta observación en el evento solicitado.':'Sin observaciones en esta categoría o página.'}</p>}
    {!eventId&&((!loading&&rows.length>0)||page>0)&&<Pager page={page} pageSize={10} count={rows.length} hasNext={hasNext} onChange={setPage} label="observaciones"/>}
  </section>
}

function IocsPage() {
  const [params,setParams]=useSearchParams()
  const [revision,refresh]=useState(0)
  const id=params.get('ioc')
  const event=params.get('evento')
  const filters=new URLSearchParams()
  for(const key of IOC_FILTERS){
    const value=params.get(key)
    if(value)filters.set(key,value)
  }
  const filter=filters.toString()
  const select=(selected:string)=>setParams({...Object.fromEntries(filters),ioc:selected},{preventScrollReset:true})
  return <>
    <Header title="Observables e IoCs" description="Explora artefactos registrados en Cowrie, comprueba su evidencia y consulta la relevancia evaluada."
      action={id?<Link className="btn-secondary" to={filter?'/iocs?'+filter:'/iocs'}>Ver todos los observables</Link>:undefined}/>
    <div className="space-y-4 min-w-0">
      <IocFilters key={filter} filter={filter} onApply={next=>setParams(next)}/>
      <IocOverview filter={filter} revision={revision} onSelect={selected=>{
        select(selected);document.getElementById('ioc-explorer')?.scrollIntoView({block:'start'})
      }}/>
      <div id="ioc-explorer" className="grid gap-4 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.4fr)] items-start">
        <IocList key={filter} filter={filter} selected={id} onSelect={select} revision={revision}/>
        {id?<IocDetail key={id+':'+event+':'+filter} id={id} eventId={event} filter={filter} revision={revision} onReviewed={()=>refresh(value=>value+1)}/>:
          <p className="panel p-4 muted text-sm">Selecciona un observable para consultar su perfil y sus evidencias.</p>}
      </div>
    </div>
  </>
}

function IocList({filter,selected,onSelect,revision}: {filter:string;selected:string|null;onSelect:(id:string)=>void;revision:number}) {
  const [page,setPage]=useState(0)
  const {rows,hasNext,loading,error}=usePagedData<ObservableRow>(withFilters('/iocs/explorar',filter),page,10,5000,revision)
  return <section className="panel p-4 min-w-0" aria-label="Explorador de observables">
    <h2 className="font-semibold mb-3">Explorador</h2>
    {error&&<ErrorBox error={error}/>}
    {loading?<p className="muted text-sm" role="status">Cargando observables…</p>:<>
      {!rows.length&&!error&&<p className="muted text-sm mb-3">Sin observables con los filtros activos.</p>}
      <ul className="divide-y divide-[#20344d]">
        {rows.map(row=><li key={row.id_ioc}><button type="button" aria-pressed={selected===row.id_ioc}
          className="mitre-finding w-full rounded text-left p-2 text-xs min-w-0" onClick={()=>onSelect(row.id_ioc)}>
          <span className="flex flex-wrap gap-2 items-center"><strong>{row.tipo}</strong><IocReviewStateBadge state={row.estado_revision}/></span>
          <span className="font-mono text-sm block mt-1 accent break-all">{row.valor}</span>
          {row.alcance&&<span className="muted block mt-1">{scopeLabels[row.alcance]??row.alcance}</span>}
          <span className="block mt-1">{row.observaciones} {row.observaciones===1?'observación':'observaciones'} · {row.sesiones} {row.sesiones===1?'sesión':'sesiones'} · {row.tecnicas} {row.tecnicas===1?'técnica':'técnicas'}</span>
          <span className="muted block mt-1">{row.observaciones_verificables} verificables · {date(row.primera_observacion)} a {date(row.ultima_observacion)}</span>
        </button></li>)}
      </ul>
      <Pager page={page} pageSize={10} count={rows.length} hasNext={hasNext} onChange={setPage} label="observables"/>
    </>}
  </section>
}

function IocDetail({id,eventId,filter,revision,onReviewed}: {
  id:string;eventId:string|null;filter:string;revision:number;onReviewed:()=>void
}) {
  const [tab,setTab]=useState(eventId?'evidencias':'perfil')
  return <div className="space-y-3 min-w-0">
    <nav className="panel p-2 flex gap-1 flex-wrap" aria-label="Vistas del observable">
      {Object.entries({perfil:'Perfil',sesiones:'Sesiones',evidencias:'Evidencias',relaciones:'Relaciones'}).map(([key,label])=>
        <button type="button" aria-pressed={tab===key} key={key} className={'text-xs '+(tab===key?'btn':'btn-secondary')} onClick={()=>setTab(key)}>{label}</button>)}
    </nav>
    {tab==='perfil'&&<IocProfile id={id} filter={filter} revision={revision}/>}
    {tab==='sesiones'&&<IocSessions id={id} filter={filter}/>}
    {tab==='evidencias'&&<IocObservations key="evidencias" id={id} eventId={eventId} filter={filter} onReviewed={onReviewed}/>}
    {tab==='relaciones'&&<IocObservations key="relaciones" id={id} eventId={null} filter={filter} relations onReviewed={onReviewed}/>}
  </div>
}

const MITRE_FILTERS=['q','tactica','sesion','modalidad','estado','plataforma','ip','citas','grado','desde','hasta','orden'] as const
type MitreCounts=Parameters<typeof CountLabels>[0]['counts']
type MitreTechnique=MitreCounts & {codigo_tecnica:string;tecnica:string;tacticas:string[];sesiones:number;
  primera_aparicion:string|null;ultima_aparicion:string|null}
type MitreSession=MitreCounts & {id_sesion:string;cowrie_session_id:string;modalidades:string[];eventos:number;
  ip_origen:string|null;sensor:string;fecha_inicio:string;fecha_fin:string|null;duracion_segundos:number|null;
  acciones:number;estados_analisis:string[]}

function mitrePath(path:string, filters:string, scope:Record<string,string>={}) {
  const query=new URLSearchParams(filters)
  Object.entries(scope).forEach(([key,value])=>query.set(key,value))
  return path+(query.size?'?'+query:'')
}

function MitreFilterForm({filters,onApply}: {filters:string;onApply:(params:URLSearchParams)=>void}) {
  const query=new URLSearchParams(filters)
  const fieldClass='block w-full bg-[#1a2e46] border line rounded-md px-3 py-2 text-sm mt-1'
  return <form aria-label="Filtros MITRE" className="panel p-4 mb-5" onSubmit={event=>{
    event.preventDefault()
    const data=new FormData(event.currentTarget)
    const next=new URLSearchParams()
    for(const key of MITRE_FILTERS){
      const value=String(data.get(key)??'').trim()
      if(value)next.set(key,value)
    }
    onApply(next)
  }}>
    <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3">
      <label className="text-xs">Código o técnica<input name="q" className={fieldClass} defaultValue={query.get('q')??''} maxLength={100}/></label>
      <label className="text-xs">Táctica<input name="tactica" className={fieldClass} defaultValue={query.get('tactica')??''} maxLength={100}/></label>
      <label className="text-xs">Sesión<input name="sesion" className={fieldClass} defaultValue={query.get('sesion')??''} maxLength={100}/></label>
      <label className="text-xs">Modalidad<select name="modalidad" className={fieldClass} defaultValue={query.get('modalidad')??''}>
        <option value="">Todas</option><option value="cowrie_shell">Shell</option><option value="cowrie_proxy">Proxy</option>
        <option value="cowrie_llm">LLM</option><option value="desconocido">Desconocida</option>
      </select></label>
      <label className="text-xs">Estado<select name="estado" className={fieldClass} defaultValue={query.get('estado')??''}>
        <option value="">Todos</option>
        {Object.entries(mitreBrowseStates).map(([key,value])=><option key={key} value={key}>{value}</option>)}
      </select></label>
    </div>
    <details className="mt-3">
      <summary className="cursor-pointer text-sm">Filtros de evidencia, plataforma y fechas</summary>
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-3">
        <label className="text-xs">Plataforma oficial<input name="plataforma" className={fieldClass} defaultValue={query.get('plataforma')??''} placeholder="Linux" maxLength={50}/></label>
        <label className="text-xs">IP de origen<input name="ip" className={fieldClass} defaultValue={query.get('ip')??''} maxLength={64}/></label>
        <label className="text-xs">Citas<select name="citas" className={fieldClass} defaultValue={query.get('citas')??''}>
          <option value="">Todas</option><option value="con">Con citas verificables</option><option value="sin">Sin citas verificables</option>
        </select></label>
        <label className="text-xs">Grado de evidencia<select name="grado" className={fieldClass} defaultValue={query.get('grado')??''}>
          <option value="">Todos</option><option value="intento">Intento</option><option value="resultado_en_honeypot">Resultado observado</option><option value="sin_registro">Sin registro</option>
        </select></label>
        <label className="text-xs">Desde (Ecuador)<input name="desde" type="date" className={fieldClass} defaultValue={query.get('desde')??''}/></label>
        <label className="text-xs">Hasta (Ecuador)<input name="hasta" type="date" className={fieldClass} defaultValue={query.get('hasta')??''}/></label>
        <label className="text-xs">Ordenar por<select name="orden" className={fieldClass} defaultValue={query.get('orden')??''}>
          <option value="">Última aparición</option><option value="primera">Primera aparición</option><option value="codigo">Código</option>
          <option value="nombre">Nombre</option><option value="sesiones">Sesiones</option><option value="mapeos">Mapeos</option>
        </select></label>
      </div>
    </details>
    {query.size>0&&<p className="muted text-xs mt-3">Filtros activos: {[...query.values()].join(' · ')}</p>}
    <div className="flex gap-2 mt-3">
      <button type="submit" className="btn text-xs">Aplicar filtros</button>
      {query.size>0&&<button type="button" className="btn-secondary text-xs" onClick={()=>onApply(new URLSearchParams())}>Limpiar filtros</button>}
    </div>
  </form>
}

function MitreSessionMappings({codigo,sessionId,filters,activeMapping,onSelect}: {codigo:string;sessionId:string;filters:string;activeMapping:string|null;onSelect:(id:string)=>void}) {
  const [page,setPage]=useState(0)
  const {rows,hasNext,loading,error}=usePagedData<MitreRow>(mitrePath('/mitre/mapeos',filters,{codigo,id_sesion:sessionId}),page,8)
  return <section className="border-t line pt-3 mt-3" aria-label="Hallazgos de la sesión seleccionada">
    {error&&<ErrorBox error={error}/>}
    {loading?<p role="status" className="muted text-sm">Cargando hallazgos…</p>:<>
      <ul className="space-y-2 mb-3">
        {rows.map(row=><li key={row.id_mapeo}>
          <button type="button" aria-pressed={activeMapping===row.id_mapeo} className="w-full text-left p-2 rounded border line hover:bg-[#1b3049] aria-pressed:border-teal-400" onClick={()=>onSelect(row.id_mapeo)}>
            <span className="flex flex-wrap justify-between items-baseline gap-2">
              <span className="font-semibold text-sm">{row.tactica}</span><MappingStatus mapping={row}/>
            </span>
            <span className="block muted text-xs mt-1">{date(row.fecha_analisis??row.fecha_mapeo)} · {row.tipo_accion}</span>
          </button>
        </li>)}
      </ul>
      <Pager page={page} pageSize={8} count={rows.length} hasNext={hasNext} onChange={setPage} label="hallazgos de la sesión"/>
    </>}
  </section>
}

function MitreTechniqueSessions({codigo,filters,activeMapping,linkedSession,onSelect}: {codigo:string;filters:string;activeMapping:string|null;linkedSession:string|null;onSelect:(id:string|null)=>void}) {
  const [page,setPage]=useState(0)
  const [active,setActive]=useState<string|null>(linkedSession)
  const [onlyLinked,setOnlyLinked]=useState(!!linkedSession)
  const [order,setOrder]=useState('ultima')
  const path=mitrePath('/mitre/tecnicas/'+encodeURIComponent(codigo)+'/sesiones',filters,
    onlyLinked&&linkedSession?{id_sesion:linkedSession,orden:order}:{orden:order})
  const {rows,hasNext,loading,error}=usePagedData<MitreSession>(path,page,8)
  return <section className="panel p-5 min-w-0">
    <h2 className="font-semibold mb-3">Sesiones asociadas a {codigo}</h2>
    <label className="text-xs flex flex-wrap items-center gap-2 mb-3">Orden de sesiones
      <select className="bg-[#1a2e46] border line rounded px-2 py-1" value={order} onChange={event=>{
        setOrder(event.target.value);setPage(0);setActive(null);onSelect(null)
      }}>
        <option value="ultima">Última aparición</option><option value="primera">Inicio de sesión</option>
        <option value="codigo">Identificador de Cowrie</option><option value="mapeos">Cantidad de mapeos</option>
      </select>
    </label>
    {onlyLinked&&<button className="btn-secondary text-xs mb-3" type="button" onClick={()=>{setOnlyLinked(false);setPage(0)}}>Ver todas las sesiones de la técnica</button>}
    {error&&<ErrorBox error={error}/>}
    {loading?<p role="status" className="muted text-sm">Cargando sesiones asociadas…</p>:<>
      <ul className="space-y-2 mb-3">
        {rows.map(row=><li key={row.id_sesion} className="border line rounded p-3">
          <div className="flex flex-wrap justify-between gap-2 items-baseline">
            <Link className="font-mono accent break-all text-sm hover:underline" to={sessionEvidencePath(row.id_sesion)}>{row.cowrie_session_id}</Link>
            <button type="button" className="btn-secondary text-xs" aria-expanded={active===row.id_sesion} onClick={()=>{
              setActive(active===row.id_sesion?null:row.id_sesion);onSelect(null)
            }}>{active===row.id_sesion?'Ocultar hallazgos':'Ver hallazgos'}</button>
          </div>
          <p className="muted text-xs mt-1">{row.id_sesion} · {row.ip_origen??'IP sin registro'} · {row.sensor}</p>
          <p className="muted text-xs mt-1">{row.modalidades.map(mode=>modalities[mode]??mode).join(' / ')} · {date(row.fecha_inicio)} a {date(row.fecha_fin)}
            {row.duracion_segundos!=null?' · '+Math.round(row.duracion_segundos)+' s':''}</p>
          <p className="muted text-xs mt-1">{row.eventos} eventos · {row.acciones} acciones · {row.mapeos} mapeos · {row.con_citas} con citas · Análisis {row.estados_analisis.join(' / ')}</p>
          <CountLabels counts={row}/>
          {active===row.id_sesion&&<MitreSessionMappings key={row.id_sesion} codigo={codigo} sessionId={row.id_sesion} filters={filters} activeMapping={activeMapping} onSelect={onSelect}/>}
        </li>)}
      </ul>
      <Pager page={page} pageSize={8} count={rows.length} hasNext={hasNext} onChange={next=>{setActive(null);onSelect(null);setPage(next)}} label="sesiones asociadas"/>
    </>}
  </section>
}

function MitreMappingDetail({id,onReviewed,expectedCode,expectedSession}: {
  id:string;onReviewed?:()=>void;expectedCode?:string|null;expectedSession?:string|null
}) {
  const {session}=useAuth()
  const {rows,setRows,loading,error}=usePagedData<MitreRow>(mitrePath('/mitre/mapeos','',{id_mapeo:id}),0,1)
  const mapping=rows.find(row=>(!expectedCode||row.codigo_tecnica===expectedCode)&&(!expectedSession||row.id_sesion===expectedSession))
  const provenance=mapping?.rag_procedencia
  return <aside className="panel p-5 min-w-0" aria-label="Detalle del hallazgo">
    {error&&<ErrorBox error={error}/>}
    {loading?<p role="status" className="muted text-sm">Cargando hallazgo…</p>:mapping?<>
      <h2 className="font-semibold text-lg">{mapping.codigo_tecnica} · {mapping.tecnica}</h2>
      <div className="flex flex-wrap gap-2 items-baseline mt-2">
        <MappingStatus mapping={mapping}/>
        <span className="badge contextual">{mapping.codigo_tactica} {mapping.tactica}</span>
        {mapping.grado_evidencia&&<span className="badge">{mitreGradeLabels[mapping.grado_evidencia]??mapping.grado_evidencia}</span>}
      </div>
      <p className="text-sm mt-3">{[date(mapping.fecha_analisis??mapping.fecha_mapeo),mapping.modalidad].filter(Boolean).join(' · ')}</p>
      <div className="flex flex-wrap gap-3 mt-3 text-xs">
        <Link to={sessionEvidencePath(mapping.id_sesion)} className="accent hover:underline">Sesión {mapping.cowrie_session_id}</Link>
        <Link to={actionEvidencePath(mapping.id_sesion,mapping.id_analisis,mapping.id_accion)} className="accent hover:underline">Abrir análisis y acción</Link>
        <Link to={sessionEvidencePath(mapping.id_sesion)+'?'+new URLSearchParams({analisis:mapping.id_analisis})} className="accent hover:underline">Abrir informe del análisis</Link>
      </div>
      <p className="text-sm mt-3"><strong>{mapping.tipo_accion}</strong> {mapping.descripcion_accion}</p>
      {provenance?.comportamiento_observado&&<p className="text-sm mt-2"><strong>Interpretación del análisis</strong> {provenance.comportamiento_observado}</p>}
      {!isAutomaticMapping(mapping)&&mapping.evidencia&&<details open className="mt-3 text-xs muted">
        <summary className="cursor-pointer">Texto histórico del mapeo</summary>
        <p className="mt-2 break-words">{mapping.evidencia}</p>
      </details>}
      <MappingObservables key={mapping.id_mapeo} id={mapping.id_mapeo} review={mapping.estado_revision} detailed/>
      <details className="border-t line pt-3 mt-4">
        <summary className="cursor-pointer text-sm font-semibold">Procedencia y validación</summary>
        <dl className="grid gap-2 mt-3 text-xs sm:grid-cols-2">
          {[
            ['Análisis',mapping.id_analisis],['Origen',provenance?.modalidad??mapping.modalidad],
            ['Modelo LLM',provenance?.modelo_llm?.modelo],['Catálogo utilizado',provenance?.catalogo?.version],
            ['STIX',provenance?.stix_id],['Método de análisis',provenance?.metodo],
            ['Validador',provenance?.version_validador],['Contrato de evidencia',provenance?.version_contrato],
            ['Versión del pipeline',mapping.version_pipeline],['Versión del informe',mapping.version_informe],
            ['Fecha del análisis',date(mapping.fecha_analisis)],['Revisión',date(mapping.revisado_en)],
          ].map(([label,value])=><div className="break-words" key={label}><dt className="muted">{label}</dt><dd>{value||'Sin registro'}</dd></div>)}
          {mapping.confianza!=null&&<div><dt className="muted">Confianza declarada por el LLM</dt><dd>{mapping.confianza} · Valor sin calibrar</dd></div>}
        </dl>
      </details>
      {mapping.revisado_en&&<p className="muted text-xs mt-3">Revisado {date(mapping.revisado_en)}{mapping.motivo_revision?' · '+mapping.motivo_revision:''}</p>}
      {session?.usuario.rol==='administrador'&&<details className="border-t line pt-3 mt-4">
        <summary className="cursor-pointer text-sm font-semibold">Revisión administrativa</summary>
        <ReviewControls key={mapping.id_mapeo} kind="mitre" id={mapping.id_mapeo} state={mapping.estado_revision}
          automatic={isAutomaticMapping(mapping)} onReviewed={state=>{
            setRows(rows=>rows.map(row=>row.id_mapeo===mapping.id_mapeo?{...row,estado_revision:state}:row));onReviewed?.()
          }}/>
      </details>}
    </>:!error&&<p className="muted text-sm">No se encontró el hallazgo.</p>}
  </aside>
}

function MitreExplorer({filters,code,onTechnique,linkedMapping,linkedSession,revision,onReviewed}: {
  filters:string;code:string|null;onTechnique:(code:string)=>void;linkedMapping:string|null;linkedSession:string|null;
  revision:number;onReviewed:()=>void
}) {
  const [page,setPage]=useState(0)
  const [selection,setSelection]=useState<{code:string|null;mapping:string|null}>({code,mapping:linkedMapping})
  const activeMapping=selection.code===code?selection.mapping:null
  const setActiveMapping=(mapping:string|null)=>setSelection({code,mapping})
  const {rows,hasNext,loading,error}=usePagedData<MitreTechnique>(mitrePath('/mitre/tecnicas',filters),page,12,5000,revision)
  return <div id="mitre-explorer" className="mitre-review-layout grid lg:grid-cols-[minmax(0,1fr)_minmax(22rem,1.3fr)] gap-5 items-start">
    <section className="panel p-5 min-w-0">
      <h2 className="font-semibold mb-3">Técnicas con mapeos guardados</h2>
      {error&&<ErrorBox error={error}/>}
      {loading?<p role="status" className="muted text-sm">Cargando técnicas…</p>:
        <ul className="divide-y line mb-3">
          {rows.map(row=><li key={row.codigo_tecnica}>
            <button type="button" aria-pressed={code===row.codigo_tecnica}
              className="mitre-finding w-full text-left px-3 py-3 rounded-md"
              onClick={()=>{onTechnique(row.codigo_tecnica);setSelection({code:row.codigo_tecnica,mapping:null})}}>
              <span className="flex flex-wrap justify-between gap-2 items-baseline">
                <span className="font-semibold"><span className="font-mono accent mr-2">{row.codigo_tecnica}</span>{row.tecnica}</span>
                <span className="badge">{row.sesiones} {row.sesiones===1?'sesión':'sesiones'}</span>
              </span>
              <span className="block muted text-xs mt-1">{row.tacticas.join(' · ')}</span>
              <span className="block muted text-xs mt-1">{row.mapeos} mapeos · {row.con_citas} con citas</span>
              <span className="block muted text-xs mt-1">{date(row.primera_aparicion)} a {date(row.ultima_aparicion)}</span>
              <CountLabels counts={row}/>
            </button>
          </li>)}
        </ul>}
      <Pager page={page} pageSize={12} count={rows.length} hasNext={hasNext} onChange={setPage} label="técnicas MITRE"/>
    </section>
    <div className="space-y-5 min-w-0">
      {code?<><MitreTechniqueProfile path={mitrePath('/mitre/tecnicas/'+encodeURIComponent(code),filters)} onTechnique={onTechnique} revision={revision}/>
        <MitreTechniqueSessions key={code+':'+linkedSession} codigo={code} filters={filters} activeMapping={activeMapping} linkedSession={linkedSession} onSelect={setActiveMapping}/></>:
        <p className="panel p-5 muted text-sm">Selecciona una técnica para ver sus sesiones y hallazgos.</p>}
      {activeMapping&&<MitreMappingDetail key={activeMapping} id={activeMapping} onReviewed={onReviewed}
        expectedCode={code} expectedSession={linkedMapping===activeMapping?linkedSession:null}/>}
    </div>
  </div>
}

function MitrePage(){
  const [params,setParams]=useSearchParams()
  const [revision,setRevision]=useState(0)
  const direct=params.get('mapeo')
  const filters=new URLSearchParams()
  for(const key of MITRE_FILTERS){
    const value=params.get(key)
    if(value)filters.set(key,value)
  }
  const filterKey=filters.toString()
  const code=params.get('tecnica')
  const selectTechnique=(selected:string)=>setParams({...Object.fromEntries(filters),tecnica:selected},{preventScrollReset:true})
  const inspectTechnique=(selected:string)=>{
    selectTechnique(selected)
    document.getElementById('mitre-explorer')?.scrollIntoView({block:'start'})
  }
  const selectTactic=(tactic:string)=>setParams({...Object.fromEntries(filters),tactica:tactic})
  return <>
    <Header title="MITRE ATT&CK" description="Investiga las sesiones y las evidencias de cada técnica."
      action={direct?<Link className="btn-secondary" to="/mitre">Ver todas las técnicas</Link>:undefined}/>
    {direct&&!code?<MitreMappingDetail key={direct} id={direct}/>:<div className="space-y-4 min-w-0">
      <MitreFilterForm key={filterKey} filters={filterKey} onApply={setParams}/>
      <MitreOverview path={mitrePath('/mitre/resumen',filterKey)} onTactic={selectTactic} onTechnique={inspectTechnique} revision={revision}/>
      <MitreMatrix path={mitrePath('/mitre/matriz',filterKey)} selected={code} onTactic={selectTactic} onTechnique={inspectTechnique} revision={revision}/>
      <MitreExplorer key={filterKey+':'+(direct??'')} filters={filterKey} code={code} onTechnique={selectTechnique}
        linkedMapping={direct} linkedSession={params.get('sesion_id')} revision={revision} onReviewed={()=>setRevision(value=>value+1)}/>
    </div>}
  </>
}

function App(){return <BrowserRouter><AuthProvider><AuthBoundary><RealtimeProvider><Shell><Routes><Route path="/" element={<DashboardPage/>}/><Route path="/sesiones" element={<SessionsPage/>}/><Route path="/sesiones/:id" element={<SessionRoute/>}/><Route path="/analisis" element={<AnalysisPage/>}/><Route path="/iocs" element={<IocsPage/>}/><Route path="/mitre" element={<MitrePage/>}/><Route path="/importar" element={<AdminOnly><ImportPage/></AdminOnly>}/><Route path="/seguridad" element={<SecurityPage/>}/><Route path="/usuarios" element={<AdminUsers/>}/><Route path="*" element={<section><ErrorBox error="La página solicitada no existe."/><Link className="btn-secondary mt-4 inline-flex" to="/">Volver al panel principal</Link></section>}/></Routes></Shell></RealtimeProvider></AuthBoundary></AuthProvider></BrowserRouter>}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>)
