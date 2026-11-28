import {useState} from 'react'
import {useMonitorQuery} from '../monitoring/Realtime'
import {Link} from 'react-router-dom'
import {api} from '../auth/client'
import {Chart,Stats,mitreDate,modalities} from './MitreDashboard'
import {enrichmentStatusLabel,eventEvidencePath,reviewLabels,scopeLabels,sessionEvidencePath,type IocReviewState} from './iocEvidence'

export const IOC_FILTERS=['q','tipo','estado','alcance','modalidad','sesion','sensor','evento','tecnica','tactica',
  'evidencia','relacion','desde','hasta','orden'] as const
type Option=[value:string,label:string]
const order:Option[]=[['ultima','Última observación'],['primera','Primera observación'],['observaciones','Cantidad de observaciones'],
  ['sesiones','Cantidad de sesiones'],['tipo','Tipo'],['valor','Valor'],['estado','Estado de revisión']]
const selectOptions:Partial<Record<typeof IOC_FILTERS[number],Option[]>>={
  tipo:[['IP','Dirección IP'],['Dominio','Dominio'],['URL','URL'],['Hash','Hash']],
  estado:Object.entries(reviewLabels), alcance:Object.entries(scopeLabels), modalidad:Object.entries(modalities),
  evidencia:[['verificable','Verificable'],['historica','Histórica sin verificación']],
  relacion:[['directa','Evidencia directa del evento'],['contextual','Técnica con relación contextual'],
    ['candidata','Técnica con relación candidata'],['insuficiente','Evidencia insuficiente']], orden:order,
}
const descriptions:Record<typeof IOC_FILTERS[number],string>={
  q:'Valor o sesión',tipo:'Tipo',estado:'Revisión',alcance:'Alcance IP',modalidad:'Modalidad',sesion:'Sesión',
  sensor:'Sensor',evento:'Tipo de evento',tecnica:'Código MITRE',tactica:'Táctica MITRE',
  evidencia:'Evidencia',relacion:'Relación',desde:'Desde (Ecuador)',hasta:'Hasta (Ecuador)',orden:'Ordenar por',
}
const lengths:Partial<Record<typeof IOC_FILTERS[number],number>>={q:150,sesion:100,sensor:80,evento:90,tecnica:20,tactica:80}

export type ObservableRow={id_ioc:string;tipo:string;valor:string;estado_revision:IocReviewState;alcance:string|null;
  sesiones:number;observaciones:number;observaciones_verificables:number;eventos:number;tecnicas:number;
  primera_observacion:string;ultima_observacion:string}
type Bucket={categoria:string;observables:number;observaciones:number}
type Overview={totales:{observables:number;observaciones:number;eventos:number;sesiones:number;verificables:number;con_mitre:number};
  tipos:Bucket[];estados:Bucket[];modalidades:Bucket[];alcances:Bucket[];evolucion:Bucket[];
  recurrentes:{id_ioc:string;valor:string;sesiones:number}[]}
type Reputation={estado:string;resultados:{proveedor:string;estado?:string;resultado?:string;motivo?:string;nombre?:string;
  consultado_en?:string;id_sesion:string;id_analisis:string}[]}
type Profile=ObservableRow & {clasificacion:{version_ip?:number;alcance?:string;algoritmo?:string;esquema?:string;
  host?:string;puerto?:number;ruta_segura?:string;alcance_destino?:string};
  comportamiento:Record<string,number> & {modalidades:string[];sensores:string[];ultima_revision:string|null};
  artefactos:{id_evento:string;id_sesion:string;hassh?:string;archivo?:string;tamano?:number}[];enriquecimiento:Reputation}
type Session={id_sesion:string;cowrie_session_id:string;modalidad:string;sensor:string;ip_origen:string|null;
  fecha_inicio:string;fecha_fin:string|null;duracion_segundos:number|null;observaciones:number;eventos:number;
  acciones:number;tecnicas:string[];estado_analisis:string;observaciones_verificables:number;analisis:{id_analisis:string}|null}

export function withFilters(path:string,filter:string) {
  return filter?path+'?'+filter:path
}

function useExplorer<T>(path:string,revision=0) {
  const [response,setResponse]=useState<{path:string;data?:T;error?:string}>()
  const [attempt,refresh]=useState(0)
  useMonitorQuery(async signal=>{
    try {
      const data=await api<T>(path,{signal})
      if(!signal.aborted)setResponse({path,data})
    } catch(error) {
      if(!signal.aborted)setResponse({path,error:(error as Error).message})
      throw error
    }
  },5000,[path,attempt,revision],['iocs'])
  return {...(response?.path===path?response:undefined),retry:()=>{setResponse(undefined);refresh(n=>n+1)}}
}

function Pending({error,retry}: {error?:string;retry:()=>void}) {
  return error?<div role="alert" className="text-sm text-red-200">
    <p>{error}</p><button type="button" className="btn-secondary mt-2" onClick={retry}>Reintentar</button>
  </div>:<p role="status" className="muted text-sm">Cargando observables…</p>
}

export function IocFilters({filter,onApply}: {filter:string;onApply:(params:URLSearchParams)=>void}) {
  const active=new URLSearchParams(filter)
  const field='block w-full min-w-0 bg-[#1a2e46] border line rounded-md px-3 py-2 text-sm mt-1'
  const control=(key:typeof IOC_FILTERS[number])=><label key={key} className="text-xs min-w-0">{descriptions[key]}
    {selectOptions[key]?<select name={key} className={field} defaultValue={active.get(key)??''}>
      {key!=='orden'&&<option value="">Todos</option>}
      {selectOptions[key].map(([value,label])=><option key={value} value={value}>{label}</option>)}
    </select>:<input type={key==='desde'||key==='hasta'?'date':'text'} name={key} className={field}
      maxLength={lengths[key]} defaultValue={active.get(key)??''}/>}
  </label>
  return <form className="panel p-4" aria-label="Filtros de observables" onSubmit={event=>{
    event.preventDefault()
    const next=new URLSearchParams()
    for(const [key,value] of new FormData(event.currentTarget)){
      const text=String(value).trim()
      if(text&&(key!=='orden'||text!=='ultima'))next.set(key,text)
    }
    onApply(next)
  }}>
    <div className="grid sm:grid-cols-2 xl:grid-cols-5 gap-3">{IOC_FILTERS.slice(0,5).map(control)}</div>
    <details className="mt-3"><summary className="cursor-pointer text-sm">Filtros de evidencia, contexto y fechas</summary>
      <div className="grid sm:grid-cols-2 xl:grid-cols-5 gap-3 mt-3">{IOC_FILTERS.slice(5).map(control)}</div>
    </details>
    {!!active.size&&<ul className="flex gap-2 flex-wrap text-xs mt-3" aria-label="Filtros activos">
      {[...active].map(([key,value])=><li key={key} className="badge break-all">{descriptions[key as keyof typeof descriptions]} · {selectOptions[key as keyof typeof selectOptions]?.find(option=>option[0]===value)?.[1]??value}</li>)}
    </ul>}
    <div className="flex gap-2 mt-3"><button className="btn text-xs" type="submit">Aplicar filtros</button>
      {!!active.size&&<button type="button" className="btn-secondary text-xs" onClick={()=>onApply(new URLSearchParams())}>Limpiar filtros</button>}
    </div>
  </form>
}

export function IocOverview({filter,onSelect,revision}: {filter:string;onSelect:(id:string)=>void;revision:number}) {
  const {data,error,retry}=useExplorer<Overview>(withFilters('/iocs/resumen',filter),revision)
  if(!data)return <section className="panel p-4"><Pending error={error} retry={retry}/></section>
  const t=data.totales
  const chart=(buckets:Bucket[],unit:'observables'|'observaciones',labels:Record<string,string>={})=>
    buckets.map(row=>({name:labels[row.categoria]??row.categoria,value:row[unit]}))
  return <>
    <section className="panel p-4" aria-label="Indicadores de observables">
      <h2 className="font-semibold mb-3">Actividad registrada</h2>
      <Stats items={[[ 'Observables únicos',t.observables],['Observaciones',t.observaciones],['Sesiones distintas',t.sesiones],['Con evidencia verificable',t.verificables]]}/>
      <p className="mt-3 muted text-xs">{t.eventos} eventos distintos · {t.con_mitre} {t.con_mitre===1?'observable':'observables'} con relación MITRE respaldada. Una observación vincula un artefacto a un evento.</p>
    </section>
    <details className="panel p-4" aria-label="Gráficos de observables"><summary className="font-semibold cursor-pointer">Distribución y evolución</summary>
      <div className="grid gap-3 mt-3 md:grid-cols-2 2xl:grid-cols-3">
        <Chart title="Tipos registrados" unit="Observables únicos" rows={chart(data.tipos,'observables')}/>
        <Chart title="Observaciones por tipo" unit="Observaciones" rows={chart(data.tipos,'observaciones')}/>
        <Chart title="Evolución en hora de Ecuador" unit="Observaciones por fecha del evento" rows={chart(data.evolucion,'observaciones')}/>
        <Chart title="Observables recurrentes" unit="Sesiones distintas" rows={data.recurrentes.map(row=>({name:row.valor,value:row.sesiones,code:row.id_ioc}))} onSelect={onSelect}/>
        <Chart title="Modalidad Cowrie" unit="Observaciones" rows={chart(data.modalidades,'observaciones',modalities)}/>
        <Chart title="Estado de revisión" unit="Observables únicos" rows={chart(data.estados,'observables',reviewLabels)}/>
        <Chart title="Alcance de direcciones IP" unit="Direcciones IP distintas" rows={chart(data.alcances,'observables',scopeLabels)}/>
      </div>
    </details>
  </>
}

export function IocReviewStateBadge({state}: {state:IocReviewState}) {
  const tone={confirmado:'contextual',pendiente:'warn',descartado:'error',mixto:'warn',historico:'warn'}[state]
  return <span className={'badge '+tone}>{reviewLabels[state]}</span>
}

const behaviorLabels:Record<string,string>={
  autenticaciones:'Intentos de autenticación',autenticaciones_fallidas:'Autenticaciones fallidas',
  autenticaciones_aceptadas:'Autenticaciones aceptadas por el señuelo',comandos:'Comandos ingresados',
  comandos_fallidos:'Fallos de comando registrados',descargas:'Descargas registradas por Cowrie',
  descargas_fallidas:'Descargas fallidas',archivos_subidos:'Archivos subidos al señuelo',conexiones:'Conexiones registradas',
  desconexiones:'Desconexiones',ordenes_dns:'Comandos DNS ingresados',intentos_descarga:'Intentos de descarga',
  sesiones_con_comandos:'Sesiones con comandos registrados',acciones:'Acciones vinculadas',tecnicas:'Técnicas relacionadas',
  usuarios_objetivo:'Usuarios objetivo distintos (sin identidades)',
}

export function IocProfile({id,filter,revision}: {id:string;filter:string;revision:number}) {
  const {data,error,retry}=useExplorer<Profile>(withFilters('/iocs/'+encodeURIComponent(id)+'/perfil',filter),revision)
  if(!data)return <section className="panel p-4"><Pending error={error} retry={retry}/></section>
  const {clasificacion:tech,comportamiento:behavior}=data
  const facts=[
    ['ID del observable',data.id_ioc],['IPv'+tech.version_ip,tech.version_ip?(scopeLabels[tech.alcance??'']??'Alcance sin registro'):null],
    ['Algoritmo',tech.algoritmo],['Esquema',tech.esquema],['Host',tech.host],['Puerto',tech.puerto],['Ruta segura',tech.ruta_segura],
    ['Alcance del destino',tech.alcance_destino==='dominio'?'Dominio · resolución sin verificar':tech.alcance_destino&&scopeLabels[tech.alcance_destino]],
    ['Primera observación',mitreDate(data.primera_observacion)],
    ['Última observación',mitreDate(data.ultima_observacion)],['Modalidades',behavior.modalidades.map(mode=>modalities[mode]??mode).join(' · ')],
    ['Sensores',behavior.sensores.join(' · ')],['Última revisión',behavior.ultima_revision?mitreDate(behavior.ultima_revision):null],
  ]
  const activities=Object.entries(behaviorLabels).filter(([key])=>behavior[key]>0)
  return <div className="space-y-4 min-w-0">
    <section className="panel p-4 space-y-3 min-w-0" aria-label="Perfil del observable">
      <div className="flex flex-wrap gap-2 items-center"><h2 className="font-semibold">Perfil del observable</h2><IocReviewStateBadge state={data.estado_revision}/></div>
      <p className="font-mono accent break-all">{data.tipo} · {data.valor}</p>
      <Stats items={[[ 'Observaciones',data.observaciones],['Sesiones',data.sesiones],['Eventos únicos',data.eventos],['Observaciones verificables',data.observaciones_verificables]]}/>
      <p className="muted text-xs">Severidad no determinada. El estado indica relevancia en el contexto revisado. El alcance de red es una propiedad técnica.</p>
      <dl className="grid grid-cols-2 gap-2 text-xs">{facts.filter(([,value])=>value!=null&&value!=='').map(([label,value])=><div className="break-all" key={label}><dt className="muted">{label}</dt><dd>{value}</dd></div>)}</dl>
      {!!data.artefactos.length&&<details><summary className="cursor-pointer text-sm">Artefactos registrados</summary>
        <ul className="mt-2 text-xs space-y-2">{data.artefactos.map(row=><li key={row.id_evento} className="break-all">{row.hassh?'HASSH del cliente SSH '+row.hassh:[row.archivo,row.tamano!=null?row.tamano+' bytes':null].filter(Boolean).join(' · ')}{' '}
          <Link className="accent underline" to={eventEvidencePath(row.id_sesion,row.id_evento)}>Evento #{row.id_evento}</Link></li>)}</ul>
      </details>}
    </section>
    <section className="panel p-4" aria-label="Comportamiento registrado">
      <h2 className="font-semibold">Comportamiento registrado</h2>
      <p className="muted text-xs mt-1">Eventos vinculados al observable. Una IP de origen puede figurar como contexto de sesión. Un comando DNS ingresado no acredita resolución y una aceptación de Cowrie no acredita compromiso.</p>
      {activities.length?<dl className="grid sm:grid-cols-2 gap-2 mt-3 text-sm">{activities.map(([key,label])=><div className="flex items-start gap-2 justify-between border-b line py-1" key={key}><dt>{label}</dt><dd className="font-semibold">{behavior[key]}</dd></div>)}</dl>:
        <p className="muted text-sm mt-3">Sin comportamiento adicional respaldado por las observaciones disponibles.</p>}
    </section>
    <details className="panel p-4" aria-label="Reputación y enriquecimiento">
      <summary className="font-semibold cursor-pointer">Reputación y enriquecimiento</summary>
      <p className="muted text-xs mt-2">Resultados guardados durante análisis anteriores. Un resultado externo aporta contexto de reputación y requiere corroboración. Este módulo solo lee datos persistidos.</p>
      {data.enriquecimiento.resultados.length?<ul className="mt-3 space-y-2 text-xs">
        {data.enriquecimiento.resultados.map((entry,index)=><li key={entry.proveedor+index} className="border-l line pl-3">
          <strong>{({threatfox:'ThreatFox',urlhaus:'URLhaus',misp_warning_lists:'MISP Warning Lists'} as Record<string,string>)[entry.proveedor]??entry.proveedor}</strong> · {enrichmentStatusLabel(entry.estado??entry.resultado)}
          <p className="muted">{[entry.nombre,entry.motivo,entry.consultado_en&&mitreDate(entry.consultado_en)].filter(Boolean).join(' · ')}</p>
          <Link className="accent underline" to={sessionEvidencePath(entry.id_sesion)+'?'+new URLSearchParams({analisis:entry.id_analisis})}>Análisis de procedencia</Link>
        </li>)}
      </ul>:<p className="muted text-sm mt-2">{data.enriquecimiento.estado==='sin_resultados_guardados'?'Sin resultados guardados para este observable.':'Enriquecimiento externo no configurado en los análisis guardados para este observable.'}</p>}
    </details>
  </div>
}

export function IocSessions({id,filter}: {id:string;filter:string}) {
  const [page,setPage]=useState(0)
  const query=new URLSearchParams(filter)
  query.set('limit','9');query.set('offset',String(page*8))
  const {data,error,retry}=useExplorer<Session[]>('/iocs/'+encodeURIComponent(id)+'/sesiones?'+query)
  return <section className="panel p-4 min-w-0" aria-label="Sesiones del observable">
    <h2 className="font-semibold mb-3">Sesiones asociadas</h2>
    {!data?<Pending error={error} retry={retry}/>:<>
      {!data.length&&<p className="muted text-sm">Sin sesiones en esta página.</p>}
      <ul className="space-y-2">{data.slice(0,8).map(row=><li className="border line rounded-lg p-3 text-xs break-words" key={row.id_sesion}>
        <Link className="accent underline font-mono break-all" to={sessionEvidencePath(row.id_sesion)}>{row.cowrie_session_id}</Link>
        <p className="muted mt-1 break-all">{row.id_sesion} · {row.ip_origen??'IP sin registro'} · {modalities[row.modalidad]??row.modalidad} · {row.sensor}</p>
        <p className="mt-1">{mitreDate(row.fecha_inicio)} · {mitreDate(row.fecha_fin)}{row.duracion_segundos!=null?' · '+Math.round(row.duracion_segundos)+' s':''}</p>
        <p className="mt-1">{row.eventos} eventos de sesión · {row.observaciones} observaciones del artefacto · {row.observaciones_verificables} verificables · {row.acciones} acciones vinculadas</p>
        <p className="muted mt-1">Análisis {row.estado_analisis}{row.tecnicas.length?' · MITRE '+row.tecnicas.join(', '):''}</p>
        {row.analisis&&<Link className="accent underline mt-1 inline-block" to={sessionEvidencePath(row.id_sesion)+'?'+new URLSearchParams({analisis:row.analisis.id_analisis})}>Abrir análisis e informe de sesión</Link>}
      </li>)}</ul>
      <nav className="flex justify-between gap-2 mt-3 items-center" aria-label="Paginación de sesiones del observable">
        <button type="button" className="btn-secondary text-xs" disabled={page===0} onClick={()=>setPage(page-1)}>Anterior</button>
        <span className="muted text-xs">Página {page+1}</span>
        <button type="button" className="btn-secondary text-xs" disabled={data.length<9} onClick={()=>setPage(page+1)}>Siguiente</button>
      </nav>
    </>}
  </section>
}
