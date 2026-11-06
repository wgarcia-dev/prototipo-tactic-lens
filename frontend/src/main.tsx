import React, {useEffect, useRef, useState} from 'react'
import {createRoot} from 'react-dom/client'
import {BrowserRouter, Link, NavLink, Route, Routes, useNavigate, useParams} from 'react-router-dom'
import {Activity, ArrowLeft, Database, FileUp, Fingerprint, LayoutDashboard, Search, Shield, Workflow} from 'lucide-react'
import {Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis} from 'recharts'
import './index.css'
import {api} from './auth/client'
import {AuthProvider, useAuth} from './auth/context'
import {AuthBoundary} from './auth/AuthBoundary'
import {SecurityPage, SessionControls} from './auth/SecurityPage'
import {AdminUsers} from './auth/AdminUsers'
import {AdminOnly} from './auth/AdminOnly'
import {AnalysisNarrative, hasDetailedReport, type AnalysisPayload} from './analysis/AnalysisNarrative'

type Session = {id_sesion:string,cowrie_session_id:string,ip_origen:string|null,fecha_inicio:string,fecha_fin:string|null,protocolo?:string,eventos?:number,estado_analisis?:'pendiente'|'en_proceso'|'analizada'|'error',analisis_desactualizado?:boolean,analisis?:{id_analisis:string,estado:string}|null,ultimo_intento?:{id_analisis:string,estado:string,mensaje_error:string|null}|null}
type Event = {id_evento:number,tipo_evento:string,fecha_hora:string,datos_originales:Record<string,unknown>}
type Dashboard = {sesiones:number,eventos:number,sesiones_analizadas:number,iocs:number,tecnicas_mitre:number,actividad:{dia:string,total:number}[],tipos_evento:{tipo_evento:string,total:number}[],ultimo_evento:string|null,collector_last_seen:string|null}
type Analysis = {id_analisis:string,estado:string,resumen:string|null,mensaje_error:string|null,resultado_estructurado?:AnalysisPayload,acciones:{id_accion:string,tipo_accion:string,descripcion:string,confianza:number,eventos:number[],mitre:{codigo_tecnica:string,tecnica:string,tactica:string,justificacion:string,confianza:number}[]}[]}

function usePolling(refresh:()=>void,delay=5000){const callback=useRef(refresh);callback.current=refresh;useEffect(()=>{callback.current();const timer=window.setInterval(()=>callback.current(),delay);return()=>window.clearInterval(timer)},[delay])}
const date=(v?:string|null)=>v?new Date(v).toLocaleString('es-EC',{dateStyle:'short',timeStyle:'short'}):'—'
const badge=(status?:string|null)=><span className={'badge '+(['fallido','error'].includes(status||'')?'error':['pendiente','en_proceso'].includes(status||'')?'warn':'')}>{status==='analizada'||status==='completado'?'Analizada':status==='en_proceso'?'En proceso':status==='error'||status==='fallido'?'Error':'Pendiente'}</span>
const analysisActionLabel=(session:Session)=>session.estado_analisis==='error'?'Reintentar':session.analisis_desactualizado?'Actualizar análisis':'Analizar'

const nav=[['/','Panel principal',LayoutDashboard],['/sesiones','Sesiones y eventos',Database],['/analisis','Análisis LLM',Workflow],['/iocs','Indicadores de compromiso',Fingerprint],['/mitre','MITRE ATT&CK',Shield],['/importar','Importar Cowrie',FileUp]] as const
function Shell({children}:{children:React.ReactNode}){const {session}=useAuth();return <div className="min-h-screen md:flex"><aside className="w-full md:w-64 md:min-h-screen bg-[#0f1b2e] border-r line flex flex-col shrink-0"><div className="h-20 flex items-center gap-3 px-6 border-b line"><div className="w-9 h-9 rounded-lg bg-[#164b56] flex items-center justify-center text-[#5ce5de]"><Activity size={21}/></div><div><div className="font-bold tracking-wide text-lg">TacticLens</div><div className="text-[10px] tracking-[.2em] accent">OBSERVATORIO COWRIE</div></div></div><div className="px-6 pt-7 pb-3 text-[10px] tracking-[.13em] muted">NAVEGACIÓN</div><nav className="px-3 space-y-1">{nav.filter(([href])=>href!=='/importar'||session?.usuario.rol==='administrador').map(([href,label,Icon])=><NavLink key={href} to={href} end={href==='/'} className={({isActive})=>`flex items-center gap-3 px-4 py-3 rounded-lg text-sm ${isActive?'bg-[#1b3851] text-white border-l-[3px] border-[#43d7d4]':'text-[#8ea3bb] hover:bg-[#172b42]'}`}><Icon size={16}/>{label}</NavLink>)}</nav><div className="mt-auto p-6 border-t line text-xs muted"><SessionControls/><span className="inline-block w-2 h-2 rounded-full bg-emerald-400 mr-2"/>Cowrie · entorno controlado<br/><span className="text-[10px]">Prototipo de tesis · UNEMI</span></div></aside><main className="flex-1 min-w-0 bg-[#0b1423]"><div className="max-w-[1500px] mx-auto px-5 md:px-9 py-8">{children}</div></main></div>}
function Header({title,description,action}:{title:string,description:string,action?:React.ReactNode}){return <div className="flex flex-wrap items-start justify-between gap-4 pb-6 border-b line mb-7"><div><h1 className="text-2xl md:text-3xl font-bold tracking-tight">{title}</h1><p className="muted text-sm mt-1">{description}</p></div>{action}</div>}
function Metric({label,value,sub,color='cyan'}:{label:string,value:number|string,sub:string,color?:string}){return <div className={`panel p-5 border-l-[3px] ${color==='blue'?'border-l-blue-500':color==='purple'?'border-l-violet-400':color==='green'?'border-l-emerald-400':'border-l-cyan-400'}`}><div className="muted text-[11px] tracking-wide uppercase">{label}</div><div className="text-3xl font-bold mt-3">{value}</div><div className="muted text-xs mt-2">{sub}</div></div>}
function ErrorBox({error}:{error:string}){return <div className="panel p-4 border-red-700 text-red-200">{error}</div>}
function LiveStatus(){const [seen,setSeen]=useState<string|null>(null);usePolling(()=>{api<{collector_last_seen:string|null}>('/health').then(x=>setSeen(x.collector_last_seen)).catch(()=>setSeen(null))});const active=!!seen&&Date.now()-new Date(seen).getTime()<45000;return <span className={'badge '+(active?'':'warn')}>{active?'RECOLECTOR CONECTADO':'SIN SEÑAL DEL RECOLECTOR'}</span>}
function DashboardPage(){const [data,setData]=useState<Dashboard|null>(null),[sessions,setSessions]=useState<Session[]>([]),[error,setError]=useState('');usePolling(()=>{api<Dashboard>('/dashboard/resumen').then(setData).catch(e=>setError(e.message));api<Session[]>('/sesiones?limit=5').then(setSessions).catch(e=>setError(e.message))});return <><Header title="Panel principal" description="Resumen de sesiones, eventos y resultados del análisis del honeypot" action={<span className="badge">PROTOTIPO · DATOS REALES</span>}/>{error&&<ErrorBox error={error}/>}<div className="grid sm:grid-cols-2 xl:grid-cols-5 gap-4 mb-5"><Metric label="Sesiones registradas" value={data?.sesiones??'—'} sub="Sesiones almacenadas"/><Metric label="Eventos recibidos" value={data?.eventos??'—'} sub="Vinculados a sesiones" color="blue"/><Metric label="Sesiones analizadas" value={data?.sesiones_analizadas??'—'} sub="Análisis completados" color="green"/><Metric label="IoCs identificados" value={data?.iocs??'—'} sub="Con evidencia" color="purple"/><Metric label="Técnicas MITRE" value={data?.tecnicas_mitre??'—'} sub="Asociaciones registradas" color="green"/></div><div className="grid lg:grid-cols-[1.7fr_1fr] gap-5 mb-5"><section className="panel p-5"><h2 className="font-semibold">Actividad de eventos</h2><p className="muted text-xs mt-1">Cantidad de eventos registrados por día</p><div className="h-60 mt-5">{data?.actividad.length?<ResponsiveContainer width="100%" height="100%"><BarChart data={data.actividad}><CartesianGrid stroke="#20344d" vertical={false}/><XAxis dataKey="dia" tick={{fill:'#8ea3bb',fontSize:11}}/><YAxis tick={{fill:'#8ea3bb',fontSize:11}}/><Tooltip contentStyle={{background:'#16273f',border:'1px solid #27415c',color:'#fff'}}/><Bar dataKey="total" fill="#4180aa" radius={[4,4,0,0]}/></BarChart></ResponsiveContainer>:<div className="muted text-sm pt-20 text-center">Sin eventos todavía</div>}</div></section><section className="panel p-5"><h2 className="font-semibold">Eventos por tipo</h2><p className="muted text-xs mt-1">Distribución observada en PostgreSQL</p><div className="mt-6 space-y-4">{data?.tipos_evento.map(x=><div key={x.tipo_evento}><div className="flex justify-between text-xs mb-2 gap-3"><span className="truncate">{x.tipo_evento}</span><span className="accent">{x.total}</span></div><div className="h-2 rounded-full bg-[#24384f]"><div className="h-2 rounded-full bg-[#42caca]" style={{width:`${Math.max(4,(x.total/(data.tipos_evento[0]?.total||1))*100)}%`}}/></div></div>)}</div></section></div><section className="panel p-5"><div className="flex justify-between items-start mb-4"><div><h2 className="font-semibold">Sesiones recientes</h2><p className="muted text-xs mt-1">Accesos capturados por Cowrie</p></div><Link className="btn text-xs" to="/sesiones">Ver todas</Link></div><SessionTable sessions={sessions}/></section></>}
function SessionTable({sessions,onAnalyze,busyId}:{sessions:Session[],onAnalyze?:(session:Session)=>void,busyId?:string|null}){
  return <div className="overflow-x-auto"><table className="w-full text-sm">
    <thead className="bg-[#1b3049] text-[#a9bdd2] text-left text-xs"><tr><th className="p-3">Sesión</th><th className="p-3">IP de origen</th><th className="p-3">Inicio</th><th className="p-3">Protocolo</th><th className="p-3">Eventos</th><th className="p-3">Análisis</th>{onAnalyze&&<th className="p-3">Acción</th>}</tr></thead>
    <tbody>{sessions.map(x=><tr key={x.id_sesion} className="table-row border-b line"><td className="p-3"><Link className="accent hover:underline font-mono" to={'/sesiones/'+x.id_sesion}>{x.cowrie_session_id}</Link></td><td className="p-3">{x.ip_origen||'?'}</td><td className="p-3 muted">{date(x.fecha_inicio)}</td><td className="p-3">{x.protocolo||'ssh'}</td><td className="p-3">{x.eventos??'?'}</td><td className="p-3">{badge(x.estado_analisis)}{x.analisis_desactualizado&&<span className="badge warn ml-2">Desactualizado</span>}</td>{onAnalyze&&<td className="p-3">{x.estado_analisis==='analizada'?<Link className="btn-secondary text-xs" to={'/sesiones/'+x.id_sesion}>Ver resultado</Link>:<button className="btn-secondary text-xs" disabled={!x.eventos||x.estado_analisis==='en_proceso'||!!busyId} onClick={()=>onAnalyze(x)}>{busyId===x.id_sesion?'Analizando…':x.estado_analisis==='en_proceso'?'En proceso':analysisActionLabel(x)}</button>}</td>}</tr>)}</tbody>
  </table>{!sessions.length&&<p className="muted text-sm p-5 text-center">No hay sesiones para mostrar.</p>}</div>
}
const PAGE_SIZE = 15

function usePagedData<T>(path:string,page:number,pageSize=PAGE_SIZE){
  const [rows,setRows]=useState<T[]>([])
  const [hasNext,setHasNext]=useState(false)
  const [loading,setLoading]=useState(true)
  const [error,setError]=useState('')
  useEffect(()=>{
    let active=true
    const separator=path.includes('?')?'&':'?'
    const url=path+separator+'limit='+(pageSize+1)+'&offset='+(page*pageSize)
    async function load(){
      try{
        const result=await api<T[]>(url)
        if(!active)return
        setRows(result.slice(0,pageSize))
        setHasNext(result.length>pageSize)
        setError('')
      }catch(e){if(active)setError((e as Error).message)}
      finally{if(active)setLoading(false)}
    }
    setLoading(true)
    load()
    const timer=window.setInterval(load,5000)
    return()=>{active=false;window.clearInterval(timer)}
  },[path,page,pageSize])
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
  const [busyId,setBusyId]=useState<string|null>(null)
  const [actionError,setActionError]=useState('')
  const {rows:sessions,hasNext,loading,error}=usePagedData<Session>('/sesiones?q='+encodeURIComponent(query.trim()),page)
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
function SessionDetail(){
  const {id}=useParams()
  const navigate=useNavigate()
  const [session,setSession]=useState<Session|null>(null)
  const [analysis,setAnalysis]=useState<Analysis|null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [page,setPage]=useState(0)
  const {rows:events,hasNext,loading,error:eventError}=usePagedData<Event>('/sesiones/'+id+'/eventos',page,20)
  useEffect(()=>setPage(0),[id])
  useEffect(()=>{
    if(!id)return
    let active=true
    async function load(){
      try{
        const current=await api<Session>('/sesiones/'+id)
        if(!active)return
        setSession(current)
        setAnalysis(current.analisis?await api<Analysis>('/analisis/'+current.analisis.id_analisis):null)
        setError('')
      }catch(e){if(active)setError((e as Error).message)}
    }
    load()
    const timer=window.setInterval(load,5000)
    return()=>{active=false;window.clearInterval(timer)}
  },[id])
  async function analyze(){
    setBusy(true);setError('')
    try{
      const result=await api<{id_analisis:string}>('/sesiones/'+id+'/analizar'+(analysis&&!hasDetailedReport(analysis)?'?actualizar_informe=true':''),{method:'POST'})
      setAnalysis(await api<Analysis>('/analisis/'+result.id_analisis))
      setSession(await api<Session>('/sesiones/'+id))
    }catch(e){setError((e as Error).message)}
    finally{setBusy(false)}
  }
  return <>
    <Header title={'Sesión '+(session?.cowrie_session_id||'')} description="Reconstrucción cronológica y evidencia de origen" action={<button className="btn-secondary flex gap-2 items-center" onClick={()=>navigate('/sesiones')}><ArrowLeft size={16}/> Volver</button>}/>
    {error&&<ErrorBox error={error}/>}
    {eventError&&<ErrorBox error={eventError}/>}
    <div className="grid lg:grid-cols-[1.5fr_1fr] gap-5">
      <section className="panel p-5">
        <div className="flex justify-between flex-wrap gap-3 mb-5"><div><h2 className="font-semibold">Línea de tiempo</h2><p className="muted text-xs mt-1">{session?.eventos??0} eventos · {session?.ip_origen||'IP desconocida'} · {session?.protocolo||'ssh'}</p></div>{session?.estado_analisis==='analizada'&&(!analysis||hasDetailedReport(analysis))?<span className="badge">Resultado guardado</span>:<button className="btn flex gap-2 items-center" onClick={analyze} disabled={busy||!session?.eventos||session?.estado_analisis==='en_proceso'}><Workflow size={16}/>{busy?'Analizando...':session?.estado_analisis==='analizada'?'Ampliar análisis':session?analysisActionLabel(session):'Analizar'}</button>}</div>
        {loading?<p className="muted text-sm py-8">Cargando eventos…</p>:<div className="border-l border-[#2d5470] ml-2 space-y-5">{events.map(x=><div key={x.id_evento} className="relative pl-6"><div className="absolute -left-[5px] top-2 w-[9px] h-[9px] rounded-full bg-[#43d7d4]"/><div className="flex flex-wrap gap-3 items-baseline"><span className="text-xs accent font-mono">{date(x.fecha_hora)}</span><span className="font-semibold text-sm">{x.tipo_evento}</span><span className="muted text-[11px]">#{x.id_evento}</span></div>{typeof x.datos_originales.input==='string'&&<div className="bg-[#0c1728] rounded-md px-3 py-2 text-sm font-mono mt-2 text-[#c4e5e2]">$ {x.datos_originales.input}</div>}<details className="mt-2 text-xs muted"><summary className="cursor-pointer hover:text-white">Ver JSON relevante</summary><pre className="overflow-auto whitespace-pre-wrap bg-[#0c1728] p-3 rounded mt-2">{JSON.stringify(x.datos_originales,null,2)}</pre></details></div>)}{!events.length&&<p className="pl-6 muted text-sm">No hay eventos registrados.</p>}</div>}
        <Pager page={page} pageSize={20} count={events.length} hasNext={hasNext} onChange={setPage} label="eventos"/>
      </section>
      <section className="space-y-5"><div className="panel p-5"><h2 className="font-semibold mb-4">Datos de la sesión</h2><dl className="text-sm space-y-3">{[['ID',session?.id_sesion],['IP de origen',session?.ip_origen],['Inicio',date(session?.fecha_inicio)],['Cierre',date(session?.fecha_fin)]].map(([k,v])=><div className="flex gap-3 justify-between border-b line pb-2" key={k}><dt className="muted">{k}</dt><dd className="text-right break-all">{v||'—'}</dd></div>)}</dl></div><div className="panel p-5"><div className="flex justify-between items-center mb-4"><h2 className="font-semibold">Análisis LLM</h2>{analysis&&badge(analysis.estado)}</div>{session?.analisis_desactualizado&&<p className="badge warn mb-3">Resultado anterior: hay eventos nuevos</p>}{session?.estado_analisis==='error'&&<p className="text-sm text-red-200 mb-3">{session.ultimo_intento?.mensaje_error||'El último intento falló. Puede reintentarlo.'}</p>}{analysis?<><AnalysisNarrative analysis={analysis}/><div className="mt-5 space-y-4">{analysis.acciones.map(x=><div className="border-t line pt-4" key={x.id_accion}><div className="flex justify-between gap-2"><strong className="text-sm">{x.tipo_accion}</strong><span className="accent text-xs">{Math.round(x.confianza*100)}%</span></div><p className="text-sm muted mt-1">{x.descripcion}</p><p className="text-xs muted mt-2">Evidencia: {x.eventos.map(n=>'#'+n).join(', ')}</p>{x.mitre.map(m=><div className="text-xs bg-[#19364a] rounded p-2 mt-2" key={m.codigo_tecnica}><span className="accent font-bold">{m.codigo_tecnica}</span> · {m.tecnica}<p className="muted mt-1">{m.justificacion}</p></div>)}</div>)}</div></>:<p className="muted text-sm">Esta sesión aún no se ha analizado.</p>}</div></section>
    </div>
  </>
}
function AnalysisPage(){
  const [page,setPage]=useState(0)
  const {rows:sessions,hasNext,loading,error:listError}=usePagedData<Session>('/sesiones',page,10)
  const [selected,setSelected]=useState<Session|null>(null)
  const [analysis,setAnalysis]=useState<Analysis|null>(null)
  const [events,setEvents]=useState<Event[]>([])
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  useEffect(()=>{setSelected(previous=>sessions.find(s=>s.id_sesion===previous?.id_sesion)||sessions[0]||null)},[sessions])
  useEffect(()=>{
    if(!selected)return
    let active=true
    setEvents([]);setAnalysis(null)
    async function load(){
      try{
        const current=await api<Session>('/sesiones/'+selected!.id_sesion)
        const latest=current.analisis?await api<Analysis>('/analisis/'+current.analisis.id_analisis):null
        const recent=await api<Event[]>('/sesiones/'+selected!.id_sesion+'/eventos?limit=500&offset='+Math.max(0,(current.eventos??0)-500))
        if(active){setAnalysis(latest);setEvents(recent);setError('')}
      }catch(e){if(active)setError((e as Error).message)}
    }
    load()
    const timer=window.setInterval(load,5000)
    return()=>{active=false;window.clearInterval(timer)}
  },[selected?.id_sesion])
  async function analyze(){
    if(!selected)return
    setBusy(true);setError('')
    try{
      const result=await api<{id_analisis:string}>('/sesiones/'+selected.id_sesion+'/analizar'+(analysis&&!hasDetailedReport(analysis)?'?actualizar_informe=true':''),{method:'POST'})
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
    <div className="grid lg:grid-cols-2 gap-5">
      <section className="panel p-5"><h2 className="font-semibold">Sesiones y estado</h2><p className="muted text-xs mt-1 mb-5">Seleccione una sesión para consultar los eventos recientes</p>
        {loading?<p className="muted text-sm py-8">Cargando sesiones…</p>:<div className="overflow-auto"><table className="w-full text-sm"><thead className="bg-[#1b3049] text-left text-xs muted"><tr><th className="p-3">Sesión</th><th className="p-3">Eventos</th><th className="p-3">Estado</th><th className="p-3">Fecha</th></tr></thead><tbody>{sessions.map(s=><tr key={s.id_sesion} className={'table-row border-b line '+(s.id_sesion===selected?.id_sesion?'bg-[#1b3049]':'')}><td className="p-3"><button className="accent font-mono text-left hover:underline" onClick={()=>setSelected(s)} aria-label={'Seleccionar sesión '+s.cowrie_session_id}>{s.cowrie_session_id}</button></td><td className="p-3">{s.eventos??0}</td><td className="p-3">{badge(s.estado_analisis)}{s.analisis_desactualizado&&<span className="badge warn ml-2">Desactualizado</span>}</td><td className="p-3 muted">{date(s.fecha_inicio)}</td></tr>)}</tbody></table>{!sessions.length&&<p className="muted text-sm p-5 text-center">Sin sesiones para analizar.</p>}</div>}
        <Pager page={page} pageSize={10} count={sessions.length} hasNext={hasNext} onChange={setPage} label="sesiones para análisis"/>
      </section>
      <section className="space-y-5">
        <div className="panel p-5"><div className="flex flex-wrap justify-between items-center gap-3"><div><h2 className="font-semibold">Comandos recientes</h2><p className="muted text-xs mt-1">Sesión {selected?.cowrie_session_id||'—'} · datos capturados</p></div><Link className="btn-secondary text-xs" to={selected?'/sesiones/'+selected.id_sesion:'/sesiones'}>Ver cronología</Link></div><div className="mt-4 space-y-2">{commands.map(e=><div key={e.id_evento} className="bg-[#0d192a] rounded p-3 text-sm font-mono"><span className="accent">$ </span>{String(e.datos_originales.input||'')}<div className="muted text-[11px] mt-1">{date(e.fecha_hora)} · evento #{e.id_evento}</div></div>)}{!commands.length&&<p className="muted text-sm">Todavía no hay comandos en esta sesión.</p>}</div></div>
        <div className="panel p-5"><div className="flex flex-wrap justify-between gap-3"><div><h2 className="font-semibold">Resultado del análisis</h2><p className="muted text-xs mt-1">Proveedor LLM configurado en el backend</p></div><button className="btn text-xs" disabled={!selected||!(selected.eventos??0)||busy||(selected.estado_analisis==='analizada'&&(!analysis||hasDetailedReport(analysis)))||selected.estado_analisis==='en_proceso'} onClick={analyze}>{busy?'Analizando…':selected?.estado_analisis==='analizada'?(analysis&&!hasDetailedReport(analysis)?'Ampliar análisis':'Resultado guardado'):selected?.estado_analisis==='en_proceso'?'En proceso':selected?analysisActionLabel(selected):'Analizar sesión'}</button></div>{selected?.estado_analisis==='error'&&<p className="text-sm text-red-200 mt-4">{selected.ultimo_intento?.mensaje_error||'El último intento falló. Puede reintentarlo.'}</p>}{newer&&<p className="badge warn mt-4">Hay eventos posteriores al último análisis</p>}{analysis?<div className="mt-5">{badge(analysis.estado)}<div className="mt-5"><AnalysisNarrative analysis={analysis}/></div><h3 className="text-sm font-semibold mt-6 mb-3">Acciones identificadas</h3><div className="space-y-3">{analysis.acciones.map(a=><div key={a.id_accion} className="border-t line pt-3"><div className="text-sm">{a.descripcion}</div><div className="muted text-xs mt-1">Eventos {a.eventos.map(x=>'#'+x).join(', ')} · {Math.round(a.confianza*100)}% confianza</div><div className="flex gap-2 mt-2 flex-wrap">{a.mitre.map(m=><span className="badge" key={m.codigo_tecnica}>{m.codigo_tecnica} · {m.tecnica}</span>)}</div></div>)}</div></div>:<p className="muted text-sm mt-5">Esta sesión aún no tiene un análisis real.</p>}</div>
      </section>
    </div>
  </>
}
function ImportPage(){const [file,setFile]=useState<File|null>(null),[result,setResult]=useState<unknown>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);async function submit(){if(!file)return;setBusy(true);setError('');try{const body=new FormData();body.append('file',file);setResult(await api('/ingesta/cowrie',{method:'POST',body}))}catch(e){setError((e as Error).message)}finally{setBusy(false)}}return <><Header title="Importar registros Cowrie" description="Carga un archivo JSONL para incorporar sesiones y eventos reales"/><div className="panel p-6 max-w-2xl"><div className="flex items-start gap-4"><FileUp size={30} className="accent"/><div><h2 className="font-semibold">Archivo cowrie.json</h2><p className="muted text-sm mt-1">Máximo 10 MB. Cada línea se valida de forma independiente. La reimportación evita duplicados.</p></div></div><input type="file" accept=".json,.jsonl" className="block mt-7 text-sm" onChange={e=>setFile(e.target.files?.[0]||null)}/><button className="btn mt-6" disabled={!file||busy} onClick={submit}>{busy?'Importando…':'Importar eventos'}</button>{error&&<div className="mt-5"><ErrorBox error={error}/></div>}{result!==null&&<pre className="bg-[#0c1728] p-4 rounded mt-5 overflow-auto text-sm">{JSON.stringify(result,null,2)}</pre>}</div></>}
type IocRow={id_ioc:string,tipo:string,valor:string,primera_observacion:string,id_evento:number,id_sesion:string,evidencias:number}
type MitreRow={id_mapeo:string,codigo_tecnica:string,tecnica:string,tactica:string,evidencia:string,justificacion:string,confianza:number,id_sesion:string}
function ListingPage({kind}:{kind:'iocs'|'mitre'}){
  const [page,setPage]=useState(0)
  const [selected,setSelected]=useState<MitreRow|null>(null)
  const path=kind==='iocs'?'/iocs':'/mitre/mapeos'
  const {rows,hasNext,loading,error}=usePagedData<IocRow|MitreRow>(path,page)
  useEffect(()=>setPage(0),[kind])
  const iocs=rows as IocRow[]
  const maps=rows as MitreRow[]
  useEffect(()=>{if(kind==='mitre')setSelected(previous=>maps.find(row=>row.id_mapeo===previous?.id_mapeo)||maps[0]||null)},[rows,kind])
  if(kind==='iocs')return <>
    <Header title="Indicadores de compromiso" description="Consulta los IoCs identificados y su relación con sesiones y eventos"/>
    {error&&<ErrorBox error={error}/>}
    <section className="panel p-5"><div className="flex flex-wrap justify-between gap-3 mb-5"><div><h2 className="font-semibold">Indicadores identificados</h2><p className="muted text-xs mt-1">Cada indicador conserva referencias a su evidencia de origen</p></div><span className="badge">{iocs.length} en esta página</span></div>
      {loading?<p className="muted text-sm py-8">Cargando indicadores…</p>:<div className="overflow-x-auto"><table className="w-full text-sm"><thead className="bg-[#1b3049] text-left text-xs muted"><tr><th className="p-3">Tipo</th><th className="p-3">Valor identificado</th><th className="p-3">Evento de origen</th><th className="p-3">Sesión</th><th className="p-3">Evidencias</th></tr></thead><tbody>{iocs.map(x=><tr key={x.id_ioc} className="table-row border-b line"><td className="p-3 accent">{x.tipo}</td><td className="p-3 break-all">{x.valor}</td><td className="p-3">#{x.id_evento}</td><td className="p-3"><Link className="accent hover:underline" to={'/sesiones/'+x.id_sesion}>{x.id_sesion?.slice(0,8)}…</Link></td><td className="p-3">{x.evidencias}</td></tr>)}</tbody></table>{!iocs.length&&<p className="muted text-sm p-5 text-center">Sin IoCs registrados. Analice una sesión con indicadores observables.</p>}</div>}
      <Pager page={page} pageSize={PAGE_SIZE} count={iocs.length} hasNext={hasNext} onChange={setPage} label="indicadores"/>
      <div className="bg-[#0d192a] rounded p-4 mt-6 text-xs muted"><span className="accent font-semibold">TRAZABILIDAD</span><p className="mt-2">IoC → detección → evento → sesión. Un valor aislado no demuestra compromiso.</p></div>
    </section>
  </>
  return <>
    <Header title="MITRE ATT&CK" description="Consulta técnicas, tácticas y evidencias vinculadas a eventos analizados"/>
    {error&&<ErrorBox error={error}/>}
    <div className="grid lg:grid-cols-[1.4fr_1fr] gap-5">
      <section className="panel p-5"><div className="flex flex-wrap justify-between gap-3 mb-5"><div><h2 className="font-semibold">Técnicas identificadas</h2><p className="muted text-xs mt-1">Mapeos guardados con evidencia verificable</p></div><span className="badge">{maps.length} en esta página</span></div>
        {loading?<p className="muted text-sm py-8">Cargando mapeos…</p>:<div className="overflow-auto"><table className="w-full text-sm"><thead className="bg-[#1b3049] text-left text-xs muted"><tr><th className="p-3">Código</th><th className="p-3">Técnica</th><th className="p-3">Táctica</th></tr></thead><tbody>{maps.map(x=><tr key={x.id_mapeo} className={'table-row border-b line '+(selected?.id_mapeo===x.id_mapeo?'bg-[#1b3049]':'')}><td className="p-3"><button className="accent font-mono text-left hover:underline" onClick={()=>setSelected(x)} aria-label={'Ver mapeo '+x.codigo_tecnica}>{x.codigo_tecnica}</button></td><td className="p-3">{x.tecnica}</td><td className="p-3 muted">{x.tactica}</td></tr>)}</tbody></table>{!maps.length&&<p className="muted text-sm p-5 text-center">Aún no hay mapeos registrados.</p>}</div>}
        <Pager page={page} pageSize={PAGE_SIZE} count={maps.length} hasNext={hasNext} onChange={setPage} label="mapeos MITRE"/>
      </section>
      <section className="panel p-5"><h2 className="font-semibold">Detalle de técnica</h2><p className="muted text-xs mt-1">Mapeo seleccionado · evidencia verificable</p>{selected?<><h3 className="text-2xl font-bold mt-9">{selected.tecnica}</h3><span className="badge mt-4">{selected.codigo_tecnica} · {selected.tactica}</span><div className="border-t line mt-8 pt-5 text-sm"><p className="muted text-xs mb-2">Sesión vinculada</p><Link to={'/sesiones/'+selected.id_sesion} className="accent">{selected.id_sesion}</Link></div><div className="border-t line mt-6 pt-5 text-sm"><p className="muted text-xs mb-2">Evidencia registrada</p>{selected.evidencia}</div><div className="border-t line mt-6 pt-5 text-sm"><p className="muted text-xs mb-2">Justificación del mapeo</p>{selected.justificacion}</div><p className="muted text-xs mt-8">Propuesta para revisión · {Math.round(selected.confianza*100)}% confianza</p></>:<p className="muted text-sm mt-8">Seleccione un mapeo para ver su evidencia.</p>}</section>
    </div>
  </>
}
function App(){return <BrowserRouter><AuthProvider><AuthBoundary><Shell><Routes><Route path="/" element={<DashboardPage/>}/><Route path="/sesiones" element={<SessionsPage/>}/><Route path="/sesiones/:id" element={<SessionDetail/>}/><Route path="/analisis" element={<AnalysisPage/>}/><Route path="/iocs" element={<ListingPage kind="iocs"/>}/><Route path="/mitre" element={<ListingPage kind="mitre"/>}/><Route path="/importar" element={<AdminOnly><ImportPage/></AdminOnly>}/><Route path="/seguridad" element={<SecurityPage/>}/><Route path="/usuarios" element={<AdminUsers/>}/><Route path="*" element={<ErrorBox error="La página solicitada no existe."/>}/></Routes></Shell></AuthBoundary></AuthProvider></BrowserRouter>}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>)
