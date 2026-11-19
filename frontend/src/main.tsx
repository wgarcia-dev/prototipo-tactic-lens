import React, {useEffect, useRef, useState} from 'react'
import {createRoot} from 'react-dom/client'
import {BrowserRouter, Link, NavLink, Route, Routes, useNavigate, useParams, useSearchParams} from 'react-router-dom'
import {Activity, ArrowLeft, Database, FileUp, Fingerprint, LayoutDashboard, Search, Shield, Workflow} from 'lucide-react'
import {Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis} from 'recharts'
import './index.css'
import {api, mutate} from './auth/client'
import {AuthProvider, useAuth} from './auth/context'
import {AuthBoundary} from './auth/AuthBoundary'
import {SecurityPage, SessionControls} from './auth/SecurityPage'
import {AdminUsers} from './auth/AdminUsers'
import {AdminOnly} from './auth/AdminOnly'
import {AnalysisNarrative, hasDetailedReport, type AnalysisPayload} from './analysis/AnalysisNarrative'
import {useMonitorQuery as usePolling, RealtimeProvider, useRealtime} from './monitoring/Realtime'
import {sameSnapshot} from './monitoring/polling'
import {RagCandidates} from './analysis/RagCandidates'
import {
  actionEvidencePath, behaviorLabels, eventEvidencePath, evidenceLabels, mappingEvidencePath,
  mappingReviewLabels, reviewLabels, scopeLabels, sessionEvidencePath, type IocReviewState, type RelationState,
} from './analysis/iocEvidence'
import {
  EvidenceEvents, MappingObservables, ObservableLinks, ObservedRelation, RelationBadge, RelationLimits,
  TechniqueRelation, type ActionLink, type MappingEvidence, type ObservableLink, type ObservedCorrelation,
} from './analysis/IocCorrelations'

import {SessionReport} from './analysis/SessionReport'

type Session = {id_sesion:string,cowrie_session_id:string,ip_origen:string|null,fecha_inicio:string,fecha_fin:string|null,protocolo?:string,eventos?:number,estado_analisis?:'pendiente'|'en_proceso'|'analizada'|'error',analisis_desactualizado?:boolean,analisis?:{id_analisis:string,estado:string}|null,ultimo_intento?:{id_analisis:string,estado:string,mensaje_error:string|null}|null}
type Event = {id_evento:number,id_evento_texto?:string,tipo_evento:string,fecha_hora:string,datos_originales:Record<string,unknown>}
type RecentCommand = {id_evento:number,id_sesion:string,fecha_hora:string,comando:string}
type Dashboard = {ultimos_comandos:RecentCommand[],sesiones:number,eventos:number,sesiones_analizadas:number,iocs:number,tecnicas_mitre:number,actividad:{dia:string,total:number}[],tipos_evento:{tipo_evento:string,total:number}[],ultimo_evento:string|null,collector_last_seen:string|null}
type AnalysisAction = {id_accion:string,tipo_accion:string,descripcion:string,confianza:number|null,eventos_texto:string[],observables:ObservableLink[],mitre:MappingEvidence[]}
type Analysis = {id_analisis:string,id_sesion:string,estado:string,resumen:string|null,mensaje_error:string|null,resultado_estructurado?:AnalysisPayload,acciones:AnalysisAction[]}

const isRag=(analysis:Analysis)=>analysis.resultado_estructurado?.rag?.metodo==='deepseek_rag_mitre_v1'
const originBadge=(analysis:Analysis)=><span className="badge mb-3">{isRag(analysis)?'DeepSeek + RAG · ATT&CK '+analysis.resultado_estructurado?.rag?.catalogo.version:'DeepSeek anterior · resultado conservado'}</span>
const date=(v?:string|null)=>v?new Date(v).toLocaleString('es-EC',{dateStyle:'short',timeStyle:'short'}):'—'
const badge=(status?:string|null)=><span className={'badge '+(['fallido','error'].includes(status||'')?'error':['pendiente','en_proceso'].includes(status||'')?'warn':'')}>{status==='analizada'||status==='completado'?'Analizada':status==='en_proceso'?'En proceso':status==='error'||status==='fallido'?'Error':'Pendiente'}</span>
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
  return <><Header title="Panel principal" description="Resumen de sesiones, eventos y resultados del análisis del honeypot"/>{error&&<ErrorBox error={error}/>}<div className="grid sm:grid-cols-2 xl:grid-cols-5 gap-4 mb-5"><Metric label="Sesiones registradas" value={data?.sesiones??'—'} sub="Sesiones almacenadas"/><Metric label="Eventos recibidos" value={data?.eventos??'—'} sub="Vinculados a sesiones" color="blue"/><Metric label="Sesiones analizadas" value={data?.sesiones_analizadas??'—'} sub="Análisis completados" color="green"/><Metric label="Observables registrados" value={data?.iocs??'—'} sub="Con evidencia de Cowrie" color="purple"/><Metric label="Técnicas MITRE" value={data?.tecnicas_mitre??'—'} sub="Asociaciones registradas" color="green"/></div><div className="grid lg:grid-cols-[1.7fr_1fr] gap-5 mb-5"><section className="panel p-5"><h2 className="font-semibold">Actividad de eventos</h2><p className="muted text-xs mt-1">Cantidad de eventos registrados por día</p><div className="h-60 mt-5">{data?.actividad.length?<ResponsiveContainer width="100%" height="100%"><BarChart data={data.actividad}><CartesianGrid stroke="#20344d" vertical={false}/><XAxis dataKey="dia" tick={{fill:'#8ea3bb',fontSize:11}}/><YAxis tick={{fill:'#8ea3bb',fontSize:11}}/><Tooltip contentStyle={{background:'#16273f',border:'1px solid #27415c',color:'#fff'}}/><Bar isAnimationActive={false} dataKey="total" fill="#4180aa" radius={[4,4,0,0]}/></BarChart></ResponsiveContainer>:<div className="muted text-sm pt-20 text-center">Sin eventos todavía</div>}</div></section><section className="panel p-5"><h2 className="font-semibold">Eventos por tipo</h2><p className="muted text-xs mt-1">Distribución observada en PostgreSQL</p><div className="mt-6 space-y-4">{data?.tipos_evento.map(x=><div key={x.tipo_evento}><div className="flex justify-between text-xs mb-2 gap-3"><span className="truncate">{x.tipo_evento}</span><span className="accent">{x.total}</span></div><div className="h-2 rounded-full bg-[#24384f]"><div className="h-2 rounded-full bg-[#42caca]" style={{width:`${Math.max(4,(x.total/(data.tipos_evento[0]?.total||1))*100)}%`}}/></div></div>)}</div></section></div><section className="panel p-5"><div className="flex justify-between items-start mb-4"><div><h2 className="font-semibold">Sesiones recientes</h2><p className="muted text-xs mt-1">Accesos capturados por Cowrie</p></div><Link className="btn text-xs" to="/sesiones">Ver todas</Link></div><SessionTable sessions={sessions}/></section><section className="panel p-5 mt-5" aria-label="Comandos recientes"><h2 className="font-semibold">Últimos comandos observados</h2><p className="muted text-xs mt-1">Actualizaciones por WebSocket · el análisis LLM se ejecuta manualmente</p><ul className="mt-4 space-y-3" aria-live="polite">{data?.ultimos_comandos?.map(command=><li key={command.id_evento} data-evento={command.id_evento} ref={node=>{if(node&&!node.dataset.renderizadoEn){node.dataset.renderizadoEn=new Date().toISOString();if(realtime.notice?.eventos?.includes(command.id_evento)){node.dataset.recibidoApi=realtime.notice.recibido_api;node.dataset.confirmadoApi=realtime.notice.confirmado_api}}}} className="bg-[#0c1728] rounded p-3"><code className="block text-sm break-all whitespace-pre-wrap">{command.comando}</code><div className="flex flex-wrap gap-3 mt-2 text-xs muted"><span>{date(command.fecha_hora)}</span><Link className="accent" to={'/sesiones/'+command.id_sesion}>Ver sesión</Link><span>#{command.id_evento}</span></div></li>)}</ul>{!data?.ultimos_comandos?.length&&<p className="muted text-sm mt-4">Sin comandos registrados todavía.</p>}</section></>}
function SessionTable({sessions,onAnalyze,busyId}:{sessions:Session[],onAnalyze?:(session:Session)=>void,busyId?:string|null}){
  return <div className="overflow-x-auto"><table className="w-full text-sm">
    <thead className="bg-[#1b3049] text-[#a9bdd2] text-left text-xs"><tr><th className="p-3">Sesión</th><th className="p-3">IP de origen</th><th className="p-3">Inicio</th><th className="p-3">Protocolo</th><th className="p-3">Eventos</th><th className="p-3">Análisis</th>{onAnalyze&&<th className="p-3">Acción</th>}</tr></thead>
    <tbody>{sessions.map(x=><tr key={x.id_sesion} className="table-row border-b line"><td className="p-3"><Link className="accent hover:underline font-mono" to={'/sesiones/'+x.id_sesion}>{x.cowrie_session_id}</Link></td><td className="p-3">{x.ip_origen||'?'}</td><td className="p-3 muted">{date(x.fecha_inicio)}</td><td className="p-3">{x.protocolo||'ssh'}</td><td className="p-3">{x.eventos??'?'}</td><td className="p-3">{badge(x.estado_analisis)}{x.analisis_desactualizado&&<span className="badge warn ml-2">Desactualizado</span>}</td>{onAnalyze&&<td className="p-3">{x.estado_analisis==='analizada'?<Link className="btn-secondary text-xs" to={'/sesiones/'+x.id_sesion}>Ver resultado</Link>:<button className="btn-secondary text-xs" disabled={!x.eventos||x.estado_analisis==='en_proceso'||!!busyId} onClick={()=>onAnalyze(x)}>{busyId===x.id_sesion?'Analizando…':x.estado_analisis==='en_proceso'?'En proceso':analysisActionLabel(x)}</button>}</td>}</tr>)}</tbody>
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
  return {rows,hasNext,loading,error}
}

function Pager({page,pageSize,count,hasNext,onChange,label}:{page:number,pageSize:number,count:number,hasNext:boolean,onChange:(page:number)=>void,label:string}){
  return <nav className="pager" aria-label={'Paginacion de '+label}>
    <span className="muted text-xs" aria-live="polite">{count ? 'Mostrando '+(page*pageSize+1)+'–'+(page*pageSize+count) : 'Sin resultados'} · Página {page+1}</span>
    <div className="flex gap-2">
      <button type="button" className="btn-secondary" disabled={page===0} onClick={()=>onChange(page-1)}>Anterior</button>
      <button type="button" className="btn-secondary" disabled={!hasNext} onClick={()=>onChange(page+1)}>Siguiente</button>
    </div>
  </nav>
}

function SessionsPage(){
  const navigate=useNavigate()
  const [page,setPage]=useState(0)
  const [query,setQuery]=useState('')
  const [filter,setFilter]=useState('')
  useEffect(()=>{const timeout=window.setTimeout(()=>setFilter(query.trim()),250);return()=>window.clearTimeout(timeout)},[query])
  const [busyId,setBusyId]=useState<string|null>(null)
  const [actionError,setActionError]=useState('')
  const {rows:sessions,hasNext,loading,error}=usePagedData<Session>('/sesiones?q='+encodeURIComponent(filter),page,PAGE_SIZE,1000)
  async function analyze(session:Session){
    setBusyId(session.id_sesion);setActionError('')
    try{
      await api('/sesiones/'+session.id_sesion+'/analizar',{method:'POST'})
      navigate('/sesiones/'+session.id_sesion)
    }catch(e){setActionError((e as Error).message)}
    finally{setBusyId(null)}
  }
  return <>
    <Header title="Sesiones y eventos" description="Explora las sesiones registradas y consulta la secuencia de eventos" action={<Link className="btn" to="/importar">Importar archivo</Link>}/>
    {(error||actionError)&&<ErrorBox error={error||actionError}/>}
    <section className="panel p-5">
      <div className="flex flex-wrap gap-3 justify-between items-center mb-5">
        <div><h2 className="font-semibold">Historial de sesiones</h2><p className="muted text-xs mt-1">Busca y analiza cualquier sesión guardada en PostgreSQL</p></div>
        <div className="relative"><Search size={15} className="absolute left-3 top-3 muted"/><input aria-label="Buscar sesión o IP" className="bg-[#1a2e46] rounded-md text-sm pl-9 pr-3 py-2 outline-none border border-[#29415a]" placeholder="Filtrar sesión o IP" value={query} onChange={e=>{setQuery(e.target.value);setPage(0)}}/></div>
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
      {action.eventos_texto.map(event=><Link className="accent hover:underline" key={event} to={eventEvidencePath(sessionId,event)}>#{event}</Link>)}
    </div>
    {action.mitre.map(mapping=><div key={mapping.id_mapeo} className="text-xs mt-3">
      <Link className="accent hover:underline" to={mappingEvidencePath(mapping.id_mapeo)}>{mapping.codigo_tecnica} · {mapping.tecnica}</Link>
      <span className={'badge ml-2 '+(mapping.estado_revision==='pendiente'?'warn':'')}>{mappingReviewLabels[mapping.estado_revision]}</span>
      <p className="muted mt-1">{mapping.justificacion}</p>
    </div>)}
    {action.observables.length>0&&<details className="text-xs mt-3">
      <summary className="cursor-pointer">Observables respaldados por la acción</summary>
      <ObservableLinks links={action.observables}/>
    </details>}
  </article>
}

function SessionDetail(){
  const {id}=useParams()
  const navigate=useNavigate()
  const [params]=useSearchParams()
  const eventId=params.get('evento')
  const requestedAnalysis=params.get('analisis')
  const requestedAction=params.get('accion')
  const [session,setSession]=useState<Session|null>(null)
  const [analysis,setAnalysis]=useState<Analysis|null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [page,setPage]=useState(0)
  const eventPath='/sesiones/'+id+'/eventos'+(eventId?'?id_evento='+encodeURIComponent(eventId):'')
  const {rows:events,hasNext,loading,error:eventError}=usePagedData<Event>(eventPath,eventId?0:page,20,1000,session?.eventos??-1)
  useEffect(()=>setPage(0),[id,eventId])
  const loadedAnalysis=useRef<string|null>(null)
  useEffect(()=>{loadedAnalysis.current=null;setSession(null);setAnalysis(null)},[id,requestedAnalysis])
  usePolling(async signal=>{
    if(!id)return
    try{
      const current=await api<Session>('/sesiones/'+id,{signal})
      if(signal.aborted)return
      setSession(previous=>sameSnapshot(previous,current))
      const key=requestedAnalysis??current.analisis?.id_analisis??null
      if(key!==loadedAnalysis.current){
        const detail=key?await api<Analysis>('/analisis/'+encodeURIComponent(key),{signal}):null
        if(signal.aborted)return
        if(detail&&detail.id_sesion!==id)throw new Error('El análisis seleccionado pertenece a otra sesión.')
        setAnalysis(previous=>sameSnapshot(previous,detail));loadedAnalysis.current=key
      }
      setError('')
    }catch(e){if(!signal.aborted)setError((e as Error).message);throw e}
  },1000,[id,requestedAnalysis])
  async function analyze(){
    setBusy(true);setError('')
    try{
      const result=await api<{id_analisis:string}>('/sesiones/'+id+'/analizar?actualizar_rag=true'+(analysis&&!hasDetailedReport(analysis)?'&actualizar_informe=true':''),{method:'POST'})
      setAnalysis(await api<Analysis>('/analisis/'+result.id_analisis))
      setSession(await api<Session>('/sesiones/'+id))
    }catch(e){setError((e as Error).message)}
    finally{setBusy(false)}
  }
  return <>
    <Header title={'Sesión '+(session?.cowrie_session_id||'')} description="Reconstrucción cronológica y evidencia de origen" action={<button className="btn-secondary flex gap-2 items-center" onClick={()=>navigate('/sesiones')}><ArrowLeft size={16}/> Volver</button>}/>
    {error&&<ErrorBox error={error}/>}
    {eventError&&<ErrorBox error={eventError}/>}
    {session&&<SessionReport key={session.id_sesion} id={session.id_sesion}/>}
    <div className="grid gap-5 min-w-0">
      <section className="panel p-5"><h2 className="font-semibold mb-4">Datos de la sesión</h2><dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2 xl:grid-cols-4">{[['ID',session?.id_sesion],['IP de origen',session?.ip_origen],['Inicio',date(session?.fecha_inicio)],['Cierre',date(session?.fecha_fin)]].map(([k,v])=><div className="min-w-0" key={k}><dt className="muted">{k}</dt><dd className="mt-1 break-words">{v||'—'}</dd></div>)}</dl></section>
      <section className="panel p-5">
        <div className="flex justify-between flex-wrap gap-3 mb-5"><div><h2 className="font-semibold">{eventId?'Evento de evidencia':'Línea de tiempo'}</h2><p className="muted text-xs mt-1">{session?.eventos??0} eventos · {session?.ip_origen||'IP desconocida'} · {session?.protocolo||'ssh'}</p></div>
          {eventId||requestedAnalysis?<Link className="btn-secondary text-xs" to={sessionEvidencePath(id??'')}>Ver sesión completa</Link>:
            session?.estado_analisis==='analizada'&&(!analysis||(hasDetailedReport(analysis)&&isRag(analysis)))?<span className="badge">Resultado guardado</span>:<button className="btn flex gap-2 items-center" onClick={analyze} disabled={busy||!session?.eventos||session?.estado_analisis==='en_proceso'}><Workflow size={16}/>{busy?'Analizando...':session?.estado_analisis==='analizada'?'Analizar con RAG':session?analysisActionLabel(session):'Analizar'}</button>}</div>
        {loading?<p className="muted text-sm py-8">Cargando eventos…</p>:<div className="timeline-events border-l border-[#2d5470] ml-2 space-y-5" tabIndex={0} role="region" aria-label="Eventos de la sesión">{events.map(x=><div key={x.id_evento} className="relative pl-6"><div className="absolute -left-[5px] top-2 w-[9px] h-[9px] rounded-full bg-[#43d7d4]"/><div className="flex flex-wrap gap-3 items-baseline"><span className="text-xs accent font-mono">{date(x.fecha_hora)}</span><span className="font-semibold text-sm">{x.tipo_evento}</span><span className="muted text-[11px]">#{x.id_evento_texto??x.id_evento}</span></div>{typeof x.datos_originales.input==='string'&&<div className="bg-[#0c1728] rounded-md px-3 py-2 text-sm font-mono mt-2 text-[#c4e5e2]">$ {x.datos_originales.input}</div>}<details className="mt-2 text-xs muted"><summary className="cursor-pointer hover:text-white">Ver JSON relevante</summary><pre className="overflow-auto whitespace-pre-wrap bg-[#0c1728] p-3 rounded mt-2">{JSON.stringify(x.datos_originales,null,2)}</pre></details></div>)}{!events.length&&<p className="pl-6 muted text-sm">No hay eventos registrados</p>}</div>}
        {!eventId&&<Pager page={page} pageSize={20} count={events.length} hasNext={hasNext} onChange={setPage} label="eventos"/>}
      </section>
      <section className="panel p-5 min-w-0"><div className="flex justify-between items-center mb-4"><h2 className="font-semibold">Análisis LLM</h2>{analysis&&badge(analysis.estado)}</div>{session?.analisis_desactualizado&&<p className="badge warn mb-3">Resultado anterior: hay eventos nuevos</p>}{session?.estado_analisis==='error'&&<p className="text-sm text-red-200 mb-3">{session.ultimo_intento?.mensaje_error||'El último intento falló. Puede reintentarlo.'}</p>}{analysis?<>{originBadge(analysis)}<AnalysisNarrative analysis={analysis}/><div className="mt-5 space-y-4">{analysis.acciones.filter(action=>!requestedAction||action.id_accion===requestedAction).map(action=>
        <ActionEvidence key={action.id_accion} action={action} sessionId={analysis.id_sesion}/>)}
        {requestedAction&&!analysis.acciones.some(action=>action.id_accion===requestedAction)&&<p className="muted text-sm">La acción solicitada no está en este análisis.</p>}</div></>:<p className="muted text-sm">Esta sesión aún no se ha analizado.</p>}</section>
    </div>
    <RagCandidates sessionId={id}/>
  </>
}
function AnalysisPage(){
  const [page,setPage]=useState(0)
  const {rows:sessions,hasNext,loading,error:listError}=usePagedData<Session>('/sesiones',page,10,1000)
  const [selected,setSelected]=useState<Session|null>(null)
  const [analysis,setAnalysis]=useState<Analysis|null>(null)
  const [events,setEvents]=useState<Event[]>([])
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  useEffect(()=>{setSelected(previous=>sessions.find(s=>s.id_sesion===previous?.id_sesion)||sessions[0]||null)},[sessions])
  const loaded=useRef<{id:string,events:number,analysis:string|null}|null>(null)
  useEffect(()=>{loaded.current=null;setEvents([]);setAnalysis(null)},[selected?.id_sesion])
  usePolling(async signal=>{
    if(!selected)return
    try{
      const current=await api<Session>('/sesiones/'+selected.id_sesion,{signal})
      if(signal.aborted)return
      const key=current.analisis?.id_analisis??null
      if(!loaded.current||loaded.current.analysis!==key){
        const detail=key?await api<Analysis>('/analisis/'+key,{signal}):null
        if(signal.aborted)return
        setAnalysis(previous=>sameSnapshot(previous,detail))
      }
      if(!loaded.current||loaded.current.events!==current.eventos){
        const recent=await api<Event[]>('/sesiones/'+selected.id_sesion+'/eventos?limit=500&offset='+Math.max(0,(current.eventos??0)-500),{signal})
        if(signal.aborted)return
        setEvents(previous=>sameSnapshot(previous,recent))
      }
      loaded.current={id:current.id_sesion,events:current.eventos??0,analysis:key};setError('')
    }catch(e){if(!signal.aborted)setError((e as Error).message);throw e}
  },1000,[selected?.id_sesion])
  async function analyze(){
    if(!selected)return
    setBusy(true);setError('')
    try{
      const result=await api<{id_analisis:string}>('/sesiones/'+selected.id_sesion+'/analizar?actualizar_rag=true'+(analysis&&!hasDetailedReport(analysis)?'&actualizar_informe=true':''),{method:'POST'})
      setAnalysis(await api<Analysis>('/analisis/'+result.id_analisis))
      setSelected(await api<Session>('/sesiones/'+selected.id_sesion))
    }catch(e){setError((e as Error).message)}
    finally{setBusy(false)}
  }
  const completed=sessions.filter(x=>x.estado_analisis==='analizada').length
  const commands=events.filter(e=>e.tipo_evento==='cowrie.command.input').slice(-6).reverse()
  const newer=analysis?.resultado_estructurado?.eventos_analizados!==undefined&&(selected?.eventos??0)>analysis.resultado_estructurado.eventos_analizados
  return <>
    <Header title="Análisis LLM" description="Eventos reales de Cowrie y análisis de la sesión seleccionada" action={<LiveStatus/>}/>
    {(error||listError)&&<ErrorBox error={error||listError}/>}
    <div className="grid sm:grid-cols-3 gap-4 mb-5"><Metric label="Completados en página" value={completed} sub="Resultados disponibles"/><Metric label="Pendientes en página" value={sessions.length-completed} sub="Sesiones por revisar" color="blue"/><Metric label="Eventos en sesión" value={selected?.eventos??0} sub="Actualización cada 5 segundos" color="green"/></div>
    <div className="workspace-columns grid lg:grid-cols-2 gap-5">
      <section className="panel p-5"><h2 className="font-semibold">Sesiones y estado</h2><p className="muted text-xs mt-1 mb-5">Seleccione una sesión para consultar los eventos recientes</p>
        {loading ? <p role="status" className="muted text-sm py-8">Cargando sesiones…</p> :
          <ul className="space-y-2">
            {sessions.map(s => <li key={s.id_sesion}>
              <button type="button" aria-pressed={s.id_sesion === selected?.id_sesion}
                onClick={() => setSelected(s)}
                className="w-full rounded-lg border border-[#27415c] px-3 py-2 text-left hover:bg-[#1b3049] aria-pressed:border-teal-400 aria-pressed:bg-[#193247] focus-visible:outline-teal-400">
                <span className="flex items-center justify-between flex-wrap gap-2">
                  <span className="font-mono accent">{s.cowrie_session_id}</span>
                  {s.analisis_desactualizado && s.estado_analisis === 'pendiente' ? <span className="badge warn">Por actualizar</span> : badge(s.estado_analisis)}
                </span>
                <span className="block muted text-xs mt-1">{date(s.fecha_inicio)} · {s.eventos ?? 0} eventos</span>
              </button>
            </li>)}
            {!sessions.length && <li className="muted text-sm py-4">Sin sesiones para analizar</li>}
          </ul>}
        <Pager page={page} pageSize={10} count={sessions.length} hasNext={hasNext} onChange={setPage} label="sesiones para análisis"/>
      </section>
      <section className="space-y-5">
        <div className="panel p-5"><div className="flex flex-wrap justify-between items-center gap-3"><div><h2 className="font-semibold">Comandos recientes</h2><p className="muted text-xs mt-1">Sesión {selected?.cowrie_session_id||'—'} · datos capturados</p></div><Link className="btn-secondary text-xs" to={selected?'/sesiones/'+selected.id_sesion:'/sesiones'}>Ver cronología</Link></div><div className="mt-4 space-y-2">{commands.map(e=><div key={e.id_evento} className="bg-[#0d192a] rounded p-3 text-sm font-mono"><span className="accent">$ </span>{String(e.datos_originales.input||'')}<div className="muted text-[11px] mt-1">{date(e.fecha_hora)} · evento #{e.id_evento}</div></div>)}{!commands.length&&<p className="muted text-sm">Todavía no hay comandos en esta sesión.</p>}</div></div>
        <div className="panel p-5"><div className="flex flex-wrap justify-between gap-3"><div><h2 className="font-semibold">Resultado del análisis</h2><p className="muted text-xs mt-1">Proveedor LLM configurado en el backend</p></div><button className="btn text-xs" disabled={!selected||!(selected.eventos??0)||busy||(selected.estado_analisis==='analizada'&&(!analysis||(hasDetailedReport(analysis)&&isRag(analysis))))||selected.estado_analisis==='en_proceso'} onClick={analyze}>{busy?'Analizando…':selected?.estado_analisis==='analizada'?(analysis&&(!hasDetailedReport(analysis)||!isRag(analysis))?'Analizar con RAG':'Resultado guardado'):selected?.estado_analisis==='en_proceso'?'En proceso':selected?analysisActionLabel(selected):'Analizar sesión'}</button></div>{selected?.estado_analisis==='error'&&<p className="text-sm text-red-200 mt-4">{selected.ultimo_intento?.mensaje_error||'El último intento falló. Puede reintentarlo.'}</p>}{newer&&<p className="badge warn mt-4">Hay eventos posteriores al último análisis</p>}{analysis?<div className="mt-5">{badge(analysis.estado)}<div className="mt-5">{originBadge(analysis)}<AnalysisNarrative analysis={analysis}/></div><h3 className="text-sm font-semibold mt-6 mb-3">Acciones identificadas</h3><div className="space-y-3">{analysis.acciones.map(action=>
          <ActionEvidence key={action.id_accion} action={action} sessionId={analysis.id_sesion}/>)}</div></div>:<p className="muted text-sm mt-5">Esta sesión aún no tiene un análisis real.</p>}</div>
      </section>
    </div>
  </>
}
function ImportPage(){const [file,setFile]=useState<File|null>(null),[result,setResult]=useState<unknown>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);async function submit(){if(!file)return;setBusy(true);setError('');try{const body=new FormData();body.append('file',file);setResult(await api('/ingesta/cowrie',{method:'POST',body}))}catch(e){setError((e as Error).message)}finally{setBusy(false)}}return <><Header title="Importar registros Cowrie" description="Carga un archivo JSONL para incorporar sesiones y eventos reales"/><div className="panel p-6 max-w-2xl"><div className="flex items-start gap-4"><FileUp size={30} className="accent"/><div><h2 className="font-semibold">Archivo cowrie.json</h2><p className="muted text-sm mt-1">Máximo 10 MB. Cada línea se valida de forma independiente. La reimportación evita duplicados.</p></div></div><input type="file" accept=".json,.jsonl" className="block mt-7 text-sm" onChange={e=>setFile(e.target.files?.[0]||null)}/><button className="btn mt-6" disabled={!file||busy} onClick={submit}>{busy?'Importando…':'Importar eventos'}</button>{error&&<div className="mt-5"><ErrorBox error={error}/></div>}{result!==null&&<pre className="bg-[#0c1728] p-4 rounded mt-5 overflow-auto text-sm">{JSON.stringify(result,null,2)}</pre>}</div></>}
type ReviewState='pendiente'|'confirmado'|'descartado'|'mixto'
type IocRow = {
  id_ioc: string, tipo: string, valor: string, primera_observacion: string, ultima_observacion: string,
  evidencias: number, sesiones: number, observaciones_verificables: number,
  observaciones_historicas: number, estado_revision: IocReviewState
}
type IocObservation = {
  id_observacion: string, id_sesion: string, id_evento: string, tipo_evento: string, fecha_hora: string,
  ingresado_en: string, numero_secuencia: number, estado_relacion: RelationState,
  evidencia: string, estado_revision: ReviewState, motivo_revision: string|null, revisado_en: string|null,
  datos_originales: Record<string, unknown>,
  acciones: ActionLink[], correlaciones: ObservedCorrelation[],
  detalles: {
    valor_original: string, campo: string, metodo: string, comportamiento: string, grado_evidencia: string,
    limitacion: string, alcance_ip: string|null, algoritmo: string|null, posicion: number|null
  }[]
}
type MitreRow={id_mapeo:string,id_accion:string,id_analisis:string,codigo_tecnica:string,tecnica:string,tactica:string,evidencia:string,justificacion:string,confianza:number|null,id_sesion:string,tipo_accion:string,descripcion_accion:string,fecha_mapeo:string,estado_revision:ReviewState,motivo_revision:string|null,grado_evidencia?:string,rag_procedencia?:{metodo?:string,catalogo?:{version:string}},revisado_por?:string,revisado_en?:string}
function ReviewControls({kind,id,state,canConfirm=true,onReviewed}:{kind:'observacion_ioc'|'mitre',id:string,state:ReviewState,canConfirm?:boolean,onReviewed?:(state:ReviewState)=>void}){
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
      {observable?reviewLabels[current]:mappingReviewLabels[current]}
    </span>
    {session?.usuario.rol==='administrador'&&<div className="flex flex-wrap gap-2 mt-2">
      {canConfirm&&<button className="btn text-xs" disabled={busy} onClick={()=>setDecision('confirmado')}>{observable?'Confirmar relevancia':'Confirmar'}</button>}
      <button className="btn text-xs" disabled={busy} onClick={()=>setDecision('descartado')}>Descartar</button>
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

function IocObservations({ioc,eventId}: {ioc: IocRow,eventId:string|null}) {
  const [page,setPage]=useState(0)
  const path='/iocs/'+ioc.id_ioc+'/observaciones'+(eventId?'?id_evento='+encodeURIComponent(eventId):'')
  const {rows,hasNext,loading,error}=usePagedData<IocObservation>(path,eventId?0:page,10)
  return <section id="ioc-observations" aria-label="Observaciones del valor seleccionado" className="panel p-5 min-w-0">
    <h2 className="font-semibold">Evidencia de Cowrie</h2>
    <p className="font-mono text-sm break-all accent mt-2">{ioc.valor}</p>
    {error&&<ErrorBox error={error}/>}
    {loading?<p className="muted text-sm mt-4" role="status">Cargando observaciones…</p>:
      <ul className="mt-4">
        {rows.map(row=><li key={row.id_observacion} className="py-4 min-w-0 border-b line last:border-b-0">
          <div className="flex flex-wrap gap-x-3 gap-y-1 items-baseline">
            <strong className="text-sm break-all">{row.tipo_evento}</strong>
            <Link className="accent text-xs hover:underline" to={eventEvidencePath(row.id_sesion,row.id_evento)}>#{row.id_evento}</Link>
            <span className="muted text-xs">Hora de Cowrie {date(row.fecha_hora)}</span>
            <Link className="accent text-xs hover:underline" to={sessionEvidencePath(row.id_sesion)} title={row.id_sesion}>Sesión {row.id_sesion.slice(0,8)}</Link>
            <RelationBadge state={row.estado_relacion}/>
          </div>
          <p className="muted text-xs mt-1">Ingesta {date(row.ingresado_en)} · Secuencia {row.numero_secuencia}</p>
          {row.detalles.length===0?<p className="text-sm muted mt-3">
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
          <details className="text-xs muted mt-3">
            <summary className="cursor-pointer hover:text-white">Ver JSON del evento</summary>
            <pre className="overflow-auto max-h-64 whitespace-pre-wrap break-all border line rounded p-3 mt-2">{JSON.stringify(row.datos_originales,null,2)}</pre>
          </details>
          {row.correlaciones.length>0&&<section className="text-xs mt-4">
            <h3 className="font-semibold mb-2">Relaciones con otros comportamientos y valores</h3>
            <ul className="space-y-3">{row.correlaciones.map(relation=><ObservedRelation
              key={relation.tipo+(relation.observable?.id_ioc??'')} correlation={relation}/>)}</ul>
          </section>}
          {row.acciones.length>0&&<details className="text-xs mt-4">
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
          <ReviewControls kind="observacion_ioc" id={row.id_observacion} state={row.estado_revision} canConfirm={row.detalles.length>0}/>
          {row.motivo_revision&&<p className="text-xs muted mt-2 break-words">{row.motivo_revision} · {date(row.revisado_en)}</p>}
        </li>)}
      </ul>}
    {!loading&&!error&&!rows.length&&<p className="muted text-sm mt-4">{eventId?'No se encontró esta observación en el evento solicitado.':page===0?'El registro histórico carece de un evento vinculado.':'Sin observaciones en esta página.'}</p>}
    {!eventId&&((!loading&&rows.length>0)||page>0)&&<Pager page={page} pageSize={10} count={rows.length} hasNext={hasNext} onChange={setPage} label="observaciones"/>}
  </section>
}

function IocsPage() {
  const [params]=useSearchParams()
  const linkedIoc=params.get('ioc')
  const eventId=params.get('evento')
  const [page,setPage]=useState(0)
  const [selectedId,setSelectedId]=useState<string|null>(linkedIoc)
  useEffect(()=>{setSelectedId(linkedIoc);setPage(0)},[linkedIoc,eventId])
  const path='/iocs'+(linkedIoc?'?id_ioc='+encodeURIComponent(linkedIoc):'')
  const {rows,hasNext,loading,error}=usePagedData<IocRow>(path,linkedIoc?0:page)
  const selected=rows.find(row=>row.id_ioc===selectedId)
  return <>
    <Header title="Observables de Cowrie" description="Consulta el contexto de cada valor y su revisión de relevancia."
      action={linkedIoc?<Link className="btn-secondary" to="/iocs">Ver todos los observables</Link>:undefined}/>
    {error&&<ErrorBox error={error}/>}
    <div className="space-y-5">
      <section className="panel p-5">
        {loading?<p className="muted text-sm py-8" role="status">Cargando observables…</p>:
          <ul>
            {rows.map(row=><li key={row.id_ioc} className="grid sm:grid-cols-[2fr_1.2fr_1fr] gap-3 py-4 items-start border-b line last:border-b-0">
              <div className="min-w-0">
                <span className="text-xs muted block">{row.tipo}</span>
                <button type="button" className="accent font-mono text-sm text-left hover:underline break-all min-h-10"
                  aria-expanded={row.id_ioc===selectedId} aria-controls={row.id_ioc===selectedId?'ioc-observations':undefined}
                  onClick={()=>setSelectedId(row.id_ioc===selectedId?null:row.id_ioc)}>{row.valor}</button>
              </div>
              <dl className="text-xs space-y-1">
                <div><dt className="inline muted">Primera </dt><dd className="inline">{date(row.primera_observacion)}</dd></div>
                <div><dt className="inline muted">Última </dt><dd className="inline">{date(row.ultima_observacion)}</dd></div>
                <div><dt className="sr-only">Cobertura</dt><dd className="muted">
                  {row.evidencias} {row.evidencias===1?'observación':'observaciones'} · {row.sesiones} {row.sesiones===1?'sesión':'sesiones'}
                </dd></div>
              </dl>
              <div><span className="badge">{reviewLabels[row.estado_revision]}</span>
                {row.observaciones_historicas>0&&<p className="muted text-xs mt-2">
                  {row.observaciones_historicas===1?'1 observación histórica':row.observaciones_historicas+' observaciones históricas'}
                </p>}
              </div>
              {selected?.id_ioc===row.id_ioc&&<div className="sm:col-span-3 min-w-0"><IocObservations key={row.id_ioc+'-'+eventId} ioc={row} eventId={eventId}/></div>}
            </li>)}
          </ul>}
        {!loading&&!error&&!rows.length&&<p className="muted text-sm p-5 text-center">Sin observables registrados</p>}
        {!linkedIoc&&<Pager page={page} pageSize={PAGE_SIZE} count={rows.length} hasNext={hasNext} onChange={next=>{setPage(next);setSelectedId(null)}} label="observables"/>}
      </section>
    </div>
  </>
}

function MitrePage(){
  const [params]=useSearchParams()
  const linkedMapping=params.get('mapeo')
  const [page,setPage]=useState(0)
  const [selectedId,setSelectedId]=useState<string|null>(linkedMapping)
  const [reviewed,setReviewed]=useState<Record<string,ReviewState>>({})
  const path='/mitre/mapeos'+(linkedMapping?'?id_mapeo='+encodeURIComponent(linkedMapping):'')
  const {rows:maps,hasNext,loading,error}=usePagedData<MitreRow>(path,linkedMapping?0:page)
  const selected=maps.find(row=>row.id_mapeo===selectedId)||null
  useEffect(()=>{setPage(0);setSelectedId(linkedMapping)},[linkedMapping])
  function changePage(next:number){setSelectedId(null);setPage(next)}
  const reviewState=(mapping:MitreRow)=>reviewed[mapping.id_mapeo]??mapping.estado_revision
  return <>
    <Header title="MITRE ATT&CK" description="Consulta técnicas, tácticas y evidencias vinculadas a eventos analizados"
      action={linkedMapping?<Link className="btn-secondary" to="/mitre">Ver todos los mapeos</Link>:undefined}/>
    {error&&<ErrorBox error={error}/>}
    <div className="mitre-review-layout grid lg:grid-cols-[minmax(0,1.15fr)_minmax(22rem,.85fr)] gap-5 items-start">
      <section className="panel p-5"><div className="flex flex-wrap justify-between gap-3 mb-4"><div><h2 className="font-semibold">Hallazgos MITRE</h2><p className="muted text-xs mt-1">Cada registro corresponde a una técnica propuesta para una acción y sesión concretas</p></div><span className="badge">{maps.length} en esta página</span></div>
        {loading?<p className="muted text-sm py-8" role="status">Cargando hallazgos…</p>:<ul className="divide-y line" aria-label="Mapeos MITRE pendientes de revisión">{maps.map(x=>{const state=reviewState(x);return <li key={x.id_mapeo}>
          <button type="button" aria-pressed={selectedId===x.id_mapeo} onClick={()=>setSelectedId(x.id_mapeo)} className="mitre-finding w-full text-left px-3 py-4 rounded-md">
            <span className="flex flex-wrap items-center justify-between gap-2"><span className="font-semibold"><span className="font-mono accent mr-2">{x.codigo_tecnica}</span>{x.tecnica}</span><span className={'badge '+(state==='pendiente'?'warn':'')}>{mappingReviewLabels[state]}</span></span>
            <span className="block text-xs muted mt-2">{x.tactica} · {x.tipo_accion} · sesión {x.id_sesion.slice(0,8)}</span>
            <span className="block text-xs mt-2 line-clamp-2">{x.justificacion}</span>
          </button>
        </li>})}{!maps.length&&<li className="muted text-sm p-5 text-center">Aún no hay hallazgos registrados</li>}</ul>}
        {!linkedMapping&&<Pager page={page} pageSize={PAGE_SIZE} count={maps.length} hasNext={hasNext} onChange={changePage} label="hallazgos MITRE"/>}
      </section>
      <aside className="panel p-5 min-w-0" aria-live="polite">
        <h2 className="font-semibold">Revisión del hallazgo</h2>
        {selected?<><p className="muted text-xs mt-1">Mapeo {selected.id_mapeo.slice(0,8)} · sesión {selected.id_sesion.slice(0,8)}</p><h3 className="text-2xl font-bold mt-5">{selected.tecnica}</h3>
          <div className="flex flex-wrap gap-2 items-baseline mt-3"><span className="badge">{selected.codigo_tecnica}</span><span className="badge contextual">{selected.tactica}</span>{selected.confianza!=null&&<span className="muted text-xs">{Math.round(Number(selected.confianza)*100)} % de confianza declarada</span>}</div>
          <div className="mt-5 rounded-lg bg-[#0d192a] p-4"><p className="muted text-xs">Acción analizada</p><p className="font-semibold mt-1">{selected.tipo_accion}</p><p className="text-sm mt-2">{selected.descripcion_accion}</p></div>
          <ReviewControls key={selected.id_mapeo} kind="mitre" id={selected.id_mapeo} state={reviewState(selected)} onReviewed={state=>setReviewed(previous=>({...previous,[selected.id_mapeo]:state}))}/>
          <div className="flex flex-wrap gap-3 mt-5 text-xs">
            <Link to={sessionEvidencePath(selected.id_sesion)} className="accent hover:underline">Ver sesión</Link>
            <Link to={actionEvidencePath(selected.id_sesion,selected.id_analisis,selected.id_accion)} className="accent hover:underline">Ver acción</Link>
          </div>
          <div className="border-t line mt-5 pt-4 text-sm"><h4 className="muted text-xs mb-2">Justificación del mapeo</h4><p>{selected.justificacion}</p></div>
          <details className="mt-3 text-xs muted"><summary className="cursor-pointer">Evidencia original del mapeo</summary>
            <p className="mt-2 break-words">{selected.evidencia}</p>
          </details>
          <MappingObservables key={selected.id_mapeo} id={selected.id_mapeo} review={selected.estado_revision}/>
          <p className="muted text-xs mt-3">{selected.rag_procedencia?.metodo?'DeepSeek + RAG · ATT&CK '+selected.rag_procedencia.catalogo?.version:'Método anterior'}{selected.grado_evidencia?' · '+selected.grado_evidencia.replaceAll('_',' '):''}</p>
          {selected.revisado_en&&<p className="muted text-xs">Revisado {date(selected.revisado_en)}</p>}
          {selected.motivo_revision&&<p className="muted text-xs mt-2">{selected.motivo_revision}</p>}
        </>:<div className="mt-8 rounded-lg border line p-5"><p className="font-semibold">Seleccione un hallazgo</p><p className="muted text-sm mt-2">La paginación no cambia la revisión automáticamente. Abra un registro para consultar su acción, evidencia y procedencia antes de tomar una decisión.</p></div>}
      </aside>
    </div>
  </>
}
function App(){return <BrowserRouter><AuthProvider><AuthBoundary><RealtimeProvider><Shell><Routes><Route path="/" element={<DashboardPage/>}/><Route path="/sesiones" element={<SessionsPage/>}/><Route path="/sesiones/:id" element={<SessionDetail/>}/><Route path="/analisis" element={<AnalysisPage/>}/><Route path="/iocs" element={<IocsPage/>}/><Route path="/mitre" element={<MitrePage/>}/><Route path="/importar" element={<AdminOnly><ImportPage/></AdminOnly>}/><Route path="/seguridad" element={<SecurityPage/>}/><Route path="/usuarios" element={<AdminUsers/>}/><Route path="*" element={<ErrorBox error="La página solicitada no existe."/>}/></Routes></Shell></RealtimeProvider></AuthBoundary></AuthProvider></BrowserRouter>}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>)
