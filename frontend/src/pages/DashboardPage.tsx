import {useState} from 'react'
import {Link} from 'react-router-dom'
import {Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis} from 'recharts'
import {api} from '../auth/client'
import {useMonitorQuery as usePolling, useRealtime} from '../monitoring/Realtime'
import {sameSnapshot} from '../monitoring/polling'
import {eventEvidencePath} from '../analysis/iocEvidence'
import {Header,Metric,ErrorBox,SessionTable,date,type Session} from './shared'

type RecentCommand = {id_evento:number,id_evento_texto:string,id_sesion:string,fecha_hora:string,comando:string}
type Dashboard = {por_modalidad?:Record<string,{sesiones:number,eventos:number}>,ultimos_comandos:RecentCommand[],sesiones:number,eventos:number,sesiones_analizadas:number,iocs:number,tecnicas_mitre:number,actividad:{dia:string,total:number}[],tipos_evento:{tipo_evento:string,total:number}[],ultimo_evento:string|null,collector_last_seen:string|null}
export function DashboardPage(){
  const realtime=useRealtime()
  const [data,setData]=useState<Dashboard|null>(null),[sessions,setSessions]=useState<Session[]>([]),[error,setError]=useState('')
  const [sessionError,setSessionError]=useState('')
  usePolling(async signal=>{
    try {
      const summary=await api<Dashboard>('/dashboard/resumen',{signal})
      if(signal.aborted)return
      setData(previous=>sameSnapshot(previous,{...summary,
        actividad:sameSnapshot(previous?.actividad??[],summary.actividad),
        tipos_evento:sameSnapshot(previous?.tipos_evento??[],summary.tipos_evento),
        ultimos_comandos:sameSnapshot(previous?.ultimos_comandos??[],summary.ultimos_comandos)}))
      setError('')
    }catch(e){if(!signal.aborted)setError((e as Error).message);throw e}
  }, 5000, [], ['panel'])
  usePolling(async signal=>{
    try {
      const recent=await api<Session[]>('/sesiones?limit=5',{signal})
      if(signal.aborted)return
      setSessions(previous=>sameSnapshot(previous,recent));setSessionError('')
    }catch(e){if(!signal.aborted)setSessionError((e as Error).message);throw e}
  }, 5000, [], ['sesiones','analisis'])
  return <><Header title="Panel principal" description="Actividad del honeypot"/>{error&&<ErrorBox error={error}/>}<div className="grid sm:grid-cols-2 xl:grid-cols-5 gap-4 mb-5"><Metric label="Sesiones registradas" value={data?.sesiones??'—'} sub="Sesiones almacenadas"/><Metric label="Eventos recibidos" value={data?.eventos??'—'} sub="Vinculados a sesiones" color="blue"/><Metric label="Sesiones con resultado" value={data?.sesiones_analizadas??'—'} sub="Al menos un análisis completado" color="green"/><Metric label="Observables registrados" value={data?.iocs??'—'} sub="IoCs únicos en sensores configurados" color="purple"/><Metric label="Técnicas MITRE" value={data?.tecnicas_mitre??'—'} sub="Técnicas distintas con mapeos registrados" color="green"/></div><div className="grid lg:grid-cols-[1.7fr_1fr] gap-5 mb-5"><section className="panel p-5"><h2 className="font-semibold">Actividad de eventos</h2><ul className="muted text-xs">{Object.entries(data?.por_modalidad??{}).map(([nombre,total])=><li key={nombre}>{nombre} · {total.sesiones} sesiones · {total.eventos} eventos</li>)}</ul><p className="muted text-xs mt-1">Cantidad de eventos registrados por día</p><div className="h-60 mt-5">{data?.actividad.length?<ResponsiveContainer width="100%" height="100%"><BarChart data={data.actividad}><CartesianGrid stroke="#20344d" vertical={false}/><XAxis dataKey="dia" tick={{fill:'#8ea3bb',fontSize:11}}/><YAxis tick={{fill:'#8ea3bb',fontSize:11}}/><Tooltip contentStyle={{background:'#16273f',border:'1px solid #27415c',color:'#fff'}}/><Bar isAnimationActive={false} dataKey="total" fill="#4180aa" radius={[4,4,0,0]}/></BarChart></ResponsiveContainer>:<div className="muted text-sm pt-20 text-center">Sin eventos todavía</div>}</div></section><section className="panel p-5"><h2 className="font-semibold">Eventos por tipo</h2><p className="muted text-xs mt-1">Distribución observada en PostgreSQL</p><div className="mt-6 space-y-4">{data?.tipos_evento.map(x=><div key={x.tipo_evento}><div className="flex justify-between text-xs mb-2 gap-3"><span className="truncate">{x.tipo_evento}</span><span className="accent">{x.total}</span></div><div className="h-2 rounded-full bg-[#24384f]"><div className="h-2 rounded-full bg-[#42caca]" style={{width:`${Math.max(4,(x.total/(data.tipos_evento[0]?.total||1))*100)}%`}}/></div></div>)}</div></section></div><section className="panel p-5"><div className="flex justify-between items-start mb-4"><div><h2 className="font-semibold">Sesiones recientes</h2><p className="muted text-xs mt-1">Accesos capturados por Cowrie</p></div><Link className="btn text-xs" to="/sesiones">Ver todas</Link></div>{sessionError&&<ErrorBox error={sessionError}/>}<SessionTable sessions={sessions}/></section><section className="panel p-5 mt-5" aria-label="Comandos recientes"><h2 className="font-semibold">Últimos comandos observados</h2><p className="muted text-xs mt-1">Actualizaciones por WebSocket · el análisis LLM se ejecuta manualmente</p><ul className="mt-4 space-y-3" aria-live="polite">{data?.ultimos_comandos?.map(command=><li key={command.id_evento_texto} data-evento={command.id_evento_texto} ref={node=>{if(node&&!node.dataset.renderizadoEn){node.dataset.renderizadoEn=new Date().toISOString();if(realtime.notice?.eventos?.includes(command.id_evento)){node.dataset.recibidoApi=realtime.notice.recibido_api;node.dataset.confirmadoApi=realtime.notice.confirmado_api}}}} className="bg-[#0c1728] rounded p-3"><code className="block text-sm break-all whitespace-pre-wrap">{command.comando}</code><div className="flex flex-wrap gap-3 mt-2 text-xs muted"><span>{date(command.fecha_hora)}</span><Link className="accent" to={'/sesiones/'+command.id_sesion}>Ver sesión</Link><Link className="accent underline" to={eventEvidencePath(command.id_sesion,command.id_evento_texto)}>Evento #{command.id_evento_texto}</Link></div></li>)}</ul>{!data?.ultimos_comandos?.length&&<p className="muted text-sm mt-4">Sin comandos registrados todavía.</p>}</section></>}
