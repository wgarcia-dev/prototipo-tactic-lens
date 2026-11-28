import {useState} from 'react'
import {Bell} from 'lucide-react'
import {Link} from 'react-router-dom'
import {api,ApiError,mutate} from '../auth/client'
import {useMonitorQuery} from '../monitoring/Realtime'

const DOMAINS=['avisos_incidentes'] as const
const PATH='/respuestas-incidentes/avisos'
type Notice={id_aviso:string;id_incidente:string;id_accion:string|null;titulo:string;creado_en:string;leido_en:string|null}
type Inbox={items:Notice[];no_leidos:number;hay_mas:boolean}

export function IncidentInbox(){
  const [open,setOpen]=useState(false),[unavailable,setUnavailable]=useState(false),[refresh,reload]=useState(0)
  const [inbox,setInbox]=useState<Inbox>({items:[],no_leidos:0,hay_mas:false}),[page,setPage]=useState(1),[error,setError]=useState('')
  useMonitorQuery(async signal=>{
    if(unavailable)return
    try {
      const result=await api<Inbox>(PATH+'?pagina='+page,{signal})
      if(!signal.aborted){setInbox(result);setError('')}
    }catch(failure){
      if(signal.aborted)return
      if(failure instanceof ApiError&&[403,404,503].includes(failure.status)){setUnavailable(true);return}
      setError((failure as Error).message)
      throw failure
    }
  },5000,[page,refresh,unavailable],DOMAINS)
  async function read(id?:string){
    try{await mutate(PATH+(id?'/'+id+'/leer':'/leer-todos'));reload(value=>value+1)}
    catch(failure){setError((failure as Error).message)}
  }
  if(unavailable)return null
  return <div className="relative">
    <button type="button" className="btn-secondary inline-flex items-center gap-2" aria-label={`Notificaciones. ${inbox.no_leidos} sin leer`}
      aria-expanded={open} onClick={()=>setOpen(!open)}><Bell size={17}/>{inbox.no_leidos||null}</button>
    {open&&<section className="panel p-3 border line mt-2 md:absolute md:right-0 md:z-20 md:w-96" aria-label="Historial de notificaciones">
      <div className="flex flex-wrap justify-between gap-2"><h2 className="font-semibold">Notificaciones</h2>
        {!!inbox.no_leidos&&<button className="btn-secondary" onClick={()=>void read()}>Marcar todas como leídas</button>}</div>
      {error&&<p role="alert">{error}</p>}
      <ul className="max-h-80 overflow-auto">{inbox.items.map(item=><li key={item.id_aviso} className="border-b line py-2">
        <Link className="accent underline" to={'/incidentes/'+item.id_incidente+'/respuesta'+(item.id_accion?'?accion='+item.id_accion:'')}
          onClick={()=>{if(!item.leido_en)void read(item.id_aviso);setOpen(false)}}>{item.titulo}</Link>
        <div className="flex justify-between gap-2"><span className="muted text-xs">{new Date(item.creado_en).toLocaleString('es-EC',{timeZone:'America/Guayaquil'})}</span>
          {!item.leido_en&&<button className="text-xs accent" onClick={()=>void read(item.id_aviso)}>Marcar como leída</button>}</div>
      </li>)}</ul>
      {!inbox.items.length&&<p className="muted">Sin notificaciones.</p>}
      {(page>1||inbox.hay_mas)&&<div className="flex gap-2 mt-2"><button className="btn-secondary" disabled={page===1}
        onClick={()=>setPage(page-1)}>Anterior</button><button className="btn-secondary" disabled={!inbox.hay_mas}
        onClick={()=>setPage(page+1)}>Siguiente</button></div>}
    </section>}
  </div>
}
