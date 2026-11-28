import {useState} from 'react'
import {Link, useSearchParams} from 'react-router-dom'
import {IOC_FILTERS, IocFilters, IocOverview, IocProfile, IocReviewStateBadge, IocSessions, withFilters, type ObservableRow} from '../analysis/IocDashboard'
import {modalities} from '../analysis/MitreDashboard'
import {actionEvidencePath, behaviorLabels, eventEvidencePath, evidenceLabels, scopeLabels, sessionEvidencePath, type RelationState} from '../analysis/iocEvidence'
import {EvidenceEvents, ObservedRelation, RelationBadge, RelationLimits, TechniqueRelation, type ActionLink, type ObservedCorrelation} from '../analysis/IocCorrelations'
import {Header,ErrorBox,usePagedData,Pager,date} from './shared'
import {ReviewControls,type ReviewState} from './ReviewControls'

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
            <ReviewControls kind="observacion_ioc" id={row.id_observacion} state={row.estado_revision} reviewedAt={row.revisado_en} canConfirm={row.detalles.length>0} onReviewed={onReviewed}/>
            {row.motivo_revision&&<p className="text-xs muted mt-2 break-words">{row.motivo_revision} · {date(row.revisado_en)}{row.revisado_por?' · Revisor '+row.revisado_por:''}</p>}
          </details>}
        </li>)}
      </ul>}
    {!loading&&!error&&!rows.length&&<p className="muted text-sm mt-4">{eventId?'No se encontró esta observación en el evento solicitado.':'Sin observaciones en esta categoría o página.'}</p>}
    {!eventId&&((!loading&&rows.length>0)||page>0)&&<Pager page={page} pageSize={10} count={rows.length} hasNext={hasNext} onChange={setPage} label="observaciones"/>}
  </section>
}

export function IocsPage() {
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
