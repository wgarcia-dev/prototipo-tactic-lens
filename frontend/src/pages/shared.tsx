import React, {useEffect, useRef, useState} from 'react'
import {Link} from 'react-router-dom'
import {api} from '../auth/client'
import {useMonitorQuery as usePolling} from '../monitoring/Realtime'
import type {MonitorDomain} from '../monitoring/socket'
import {sameSnapshot} from '../monitoring/polling'
import {AnalysisStatus, type AnalysisValidity, type AttemptStatus} from '../analysis/AnalysisStatus'

export type Session = {modalidad?:string,id_sesion:string,cowrie_session_id:string,ip_origen:string|null,fecha_inicio:string,fecha_fin:string|null,protocolo?:string,eventos?:number,estado_analisis?:'pendiente'|'en_proceso'|'analizada'|'error',analisis_desactualizado?:boolean,vigencia_analisis?:AnalysisValidity|null,estado_ultimo_intento?:AttemptStatus,analisis?:{id_analisis:string,estado:string}|null,ultimo_intento?:{id_analisis:string,estado:string,mensaje_error:string|null}|null}
export type Event = {id_evento:number,id_evento_texto?:string,tipo_evento:string,fecha_hora:string,datos_originales:Record<string,unknown>}
export const date=(v?:string|null)=>v?new Date(v).toLocaleString('es-EC',{dateStyle:'short',timeStyle:'short',timeZone:'America/Guayaquil'}):'—'
export const analysisActionLabel=(session:Session)=>session.estado_analisis==='error'?'Reintentar':session.analisis_desactualizado?'Actualizar análisis':'Analizar'

export function Header({title,description,action}:{title:string,description:string,action?:React.ReactNode}){return <div className="flex flex-wrap items-start justify-between gap-4 pb-6 border-b line mb-7"><div><h1 className="text-2xl md:text-3xl font-bold tracking-tight">{title}</h1><p className="muted text-sm mt-1">{description}</p></div>{action}</div>}
export function Metric({label,value,sub,color='cyan'}:{label:string,value:number|string,sub:string,color?:string}){return <div className={`panel p-5 border-l-[3px] ${color==='blue'?'border-l-blue-500':color==='purple'?'border-l-violet-400':color==='green'?'border-l-emerald-400':'border-l-cyan-400'}`}><div className="muted text-[11px] tracking-wide uppercase">{label}</div><div className="text-3xl font-bold mt-3">{value}</div><div className="muted text-xs mt-2">{sub}</div></div>}
export function ErrorBox({error}:{error:string}){return <div className="panel p-4 border-red-700 text-red-200">{error}</div>}
export function LiveStatus(){const [seen,setSeen]=useState<string|null>(null);usePolling(async signal=>{try{const x=await api<{collector_last_seen:string|null}>('/operacion?solo_recolector=true',{signal});if(!signal.aborted)setSeen(x.collector_last_seen)}catch(e){if(!signal.aborted)setSeen(null);throw e}},5000);const active=!!seen&&Date.now()-new Date(seen).getTime()<15000;return <span className={'badge '+(active?'':'warn')}>{active?'RECOLECTOR CONECTADO':'SIN SEÑAL DEL RECOLECTOR'}</span>}
export function SessionTable({sessions,onAnalyze,busyId}:{sessions:Session[],onAnalyze?:(session:Session)=>void,busyId?:string|null}){
  return <div className="overflow-x-auto"><table className="w-full text-sm">
    <thead className="bg-[#1b3049] text-[#a9bdd2] text-left text-xs"><tr><th className="p-3">Sesión</th><th className="p-3">IP de origen</th><th className="p-3">Inicio</th><th className="p-3">Protocolo</th><th className="p-3">Eventos</th><th className="p-3">Análisis</th>{onAnalyze&&<th className="p-3">Acción</th>}</tr></thead>
    <tbody>{sessions.map(x=><tr key={x.id_sesion} className="table-row border-b line"><td className="p-3"><Link className="accent hover:underline font-mono" to={'/sesiones/'+x.id_sesion}>{x.cowrie_session_id}</Link><div className="muted text-xs">{x.modalidad ?? "desconocido"}</div></td><td className="p-3">{x.ip_origen||'?'}</td><td className="p-3 muted">{date(x.fecha_inicio)}</td><td className="p-3">{x.protocolo||'ssh'}</td><td className="p-3">{x.eventos??'?'}</td><td className="p-3"><AnalysisStatus attempt={x.estado_ultimo_intento} validity={x.vigencia_analisis}/></td>{onAnalyze&&<td className="p-3">{x.estado_analisis==='analizada'?<Link className="btn-secondary text-xs" to={'/sesiones/'+x.id_sesion}>Ver resultado</Link>:<button className="btn-secondary text-xs" disabled={!x.eventos||x.estado_analisis==='en_proceso'||!!busyId} onClick={()=>onAnalyze(x)}>{busyId===x.id_sesion?'Analizando…':x.estado_analisis==='en_proceso'?'En proceso':analysisActionLabel(x)}</button>}</td>}</tr>)}</tbody>
  </table>{!sessions.length&&<p className="muted text-sm p-5 text-center">No hay sesiones para mostrar</p>}</div>
}
export const PAGE_SIZE = 15

export function usePagedData<T>(path:string,page:number,pageSize=PAGE_SIZE,interval=5000,revision?:number){
  const [rows,setRows]=useState<T[]>([]),[hasNext,setHasNext]=useState(false)
  const [loading,setLoading]=useState(true),[error,setError]=useState('')
  const domains: MonitorDomain[] = path.startsWith('/mitre') ? ['mitre'] : path.startsWith('/iocs') ? ['iocs'] :
    path.includes('/eventos') ? ['sesiones'] : ['sesiones','analisis']
  const anchors=useRef<{scope:string;pages:Map<number,Session>}>({scope:'',pages:new Map()})
  const scope=path+'|'+pageSize
  if(anchors.current.scope!==scope)anchors.current={scope,pages:new Map()}
  const supportsCursor=path==='/sesiones'||path.startsWith('/sesiones?')
  useEffect(()=>{setLoading(true);setError('')},[path,page,pageSize])
  usePolling(async signal=>{
    const separator=path.includes('?')?'&':'?'
    const anchor=supportsCursor?anchors.current.pages.get(page):undefined
    const position=anchor?'&antes_fecha='+encodeURIComponent(anchor.fecha_inicio)+'&antes_id='+encodeURIComponent(anchor.id_sesion):
      '&offset='+(page*pageSize)
    const url=path+separator+'limit='+(pageSize+1)+position
    if(revision===-1)return
    try{
      const result=await api<T[]>(url,{signal})
      if(signal.aborted)return
      const visible=result.slice(0,pageSize)
      if(supportsCursor&&visible.length>0){
        const boundary=visible.at(-1) as Session
        anchors.current.pages.set(page+1,boundary)
      }
      setRows(previous=>sameSnapshot(previous,visible))
      setHasNext(result.length>pageSize);setError('')
    }catch(e){if(!signal.aborted)setError((e as Error).message);throw e}
    finally{if(!signal.aborted)setLoading(false)}
  },interval,[path,page,pageSize,revision],domains)
  return {rows,setRows,hasNext,loading,error}
}

export function Pager({page,pageSize,count,hasNext,onChange,label,total}:{page:number,pageSize:number,count:number,hasNext:boolean,onChange:(page:number)=>void,label:string,total?:number}){
  const pages=total===undefined?undefined:Math.max(1,Math.ceil(total/pageSize))
  return <nav className="pager" aria-label={'Paginacion de '+label}>
    <span className="muted text-xs" aria-live="polite">{count ? 'Mostrando '+(page*pageSize+1)+'–'+(page*pageSize+count)+(total===undefined?'':' de '+total) : 'Sin resultados'} · Página {page+1}{pages===undefined?'':' de '+pages}{!hasNext&&page>0?' · Última página':''}</span>
    {(page>0||hasNext)&&<div className="flex gap-2">
      <button type="button" className="btn-secondary" disabled={page===0} onClick={()=>onChange(page-1)}>Anterior</button>
      <button type="button" className="btn-secondary" disabled={!hasNext} onClick={()=>onChange(page+1)}>Siguiente</button>
    </div>}
  </nav>
}
