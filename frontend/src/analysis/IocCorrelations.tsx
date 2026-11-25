import {useEffect, useState} from 'react'
import {Link} from 'react-router-dom'
import {api} from '../auth/client'
import {
  behaviorLabels, eventEvidencePath, isAutomaticMapping, mappingClassificationLabel, mappingEvidencePath, mitreGradeLabels,
  observableEvidencePath, relationLabels, type RelationState,
} from './iocEvidence'

export type EventRef = {
  id_evento: string
  id_sesion: string
  tipo_evento: string
  fecha_hora: string
  ingresado_en: string
  numero_secuencia: number
  rol?: string
  comando?: string|null
}

type EvidenceRelation = {
  estado: RelationState
  metodo: string
  justificacion: string
  limitaciones: string[]
  eventos: EventRef[]
}

type Observable = {id_ioc: string; tipo: string; valor: string}

export type ObservableLink = Observable & EvidenceRelation & {
  id_evento: string
  revision_observable: string
  papeles?: string[]
}

export type ObservedCorrelation = EvidenceRelation & {
  tipo: 'comando_transferencia' | 'url_archivo'
  total_candidatos?: number
  ventana_segundos?: number | null
  observable?: Observable
}

export type MappingEvidence = {
  id_mapeo: string
  id_accion: string
  codigo_tecnica: string
  tecnica: string
  tactica: string
  codigo_tactica?: string
  estado_revision: string
  justificacion: string
  motivo_revision: string | null
  eventos: EventRef[]
  grado_evidencia?: string|null
  rag_procedencia?: {limitaciones?: string[];clasificacion?: string;modalidad?:string;metodo?:string;
    catalogo?:{version:string};version_validador?:string;modelo_llm?:{modelo:string;proveedor:string};
    stix_id?:string;version_contrato?:string;comportamiento_observado?:string}
}

export type TechniqueLink = MappingEvidence & EvidenceRelation & {
  fundamento: string
  evento_compartido: string
}

export type ActionLink = ObservableLink & {
  id_accion: string
  id_analisis: string
  tipo_accion: string
  interpretacion: string
  tecnicas: TechniqueLink[]
}

export function RelationBadge({state}: {state: RelationState}) {
  const styles = {directa:'',contextual:'contextual',candidata:'warn',insuficiente:'error'}
  return <span className={'badge '+styles[state]}>{relationLabels[state]}</span>
}

function eventDate(value: string) {
  return new Date(value).toLocaleString('es-EC', {dateStyle:'short', timeStyle:'medium',timeZone:'America/Guayaquil'})
}

export function EvidenceEvents({events}: {events: EventRef[]}) {
  return <ul className="space-y-2 mt-2">
    {events.map(event=><li key={event.id_evento} className="border-l line pl-3">
      <Link className="accent hover:underline break-words" to={eventEvidencePath(event.id_sesion,event.id_evento)}>
        #{event.id_evento} · {event.rol?behaviorLabels[event.rol]:event.tipo_evento}
      </Link>
      <div className="muted">Hora de Cowrie {eventDate(event.fecha_hora)} · Ingesta {eventDate(event.ingresado_en)} · Secuencia {event.numero_secuencia}</div>
      {event.comando&&<div className="mt-1"><span className="muted">Entrada registrada: </span><code className="break-all whitespace-pre-wrap">{event.comando}</code></div>}
    </li>)}
  </ul>
}

export function RelationLimits({limits}: {limits: string[]}) {
  return <ul className="list-disc pl-4 mt-2 muted">{limits.map((limit,index)=><li key={index}>{limit}</li>)}</ul>
}

export function ObservedRelation({correlation}: {correlation: ObservedCorrelation}) {
  const title = correlation.tipo === 'url_archivo' ? 'URL y archivo registrado' : 'Comando y resultado de descarga'
  const shownAlternatives = correlation.eventos.length - 1
  return <li className="border-l line pl-3">
    <div className="flex flex-wrap gap-2 items-baseline">
      <strong>{title}</strong><RelationBadge state={correlation.estado}/>
    </div>
    <p className="mt-1">{correlation.justificacion}</p>
    {correlation.ventana_segundos!=null&&<p className="muted mt-1">Ventana configurada de {correlation.ventana_segundos} segundos.</p>}
    {correlation.total_candidatos!=null&&correlation.total_candidatos>shownAlternatives&&
      <p className="muted mt-1">Se muestran {shownAlternatives} de {correlation.total_candidatos} eventos candidatos.</p>}
    {correlation.observable&&<Link className="accent break-all hover:underline" to={observableEvidencePath(correlation.observable.id_ioc,correlation.eventos[0].id_evento)}>
      {correlation.observable.tipo} · {correlation.observable.valor}
    </Link>}
    <EvidenceEvents events={correlation.eventos}/>
    <RelationLimits limits={correlation.limitaciones}/>
  </li>
}

export function MappingStatus({mapping}: {mapping:Pick<MappingEvidence,'estado_revision'|'rag_procedencia'>}) {
  const state=mapping.estado_revision
  const automatic=isAutomaticMapping(mapping)
  const tone=state==='descartado'?'error':state==='confirmado'||automatic?'contextual':'warn'
  return <span className="inline-flex flex-wrap gap-1">
    <span className={'badge '+tone}>{mappingClassificationLabel(mapping)}</span>
    {automatic&&state==='confirmado'&&<span className="badge contextual">Confirmada administrativamente</span>}
  </span>
}

export function MappingBasis({mapping}: {mapping:MappingEvidence}) {
  const provenance=mapping.rag_procedencia
  return <>
    <p className="muted mt-1">{[mapping.codigo_tactica,mapping.tactica,mitreGradeLabels[mapping.grado_evidencia??''],provenance?.modalidad].filter(Boolean).join(' · ')}</p>
    <p className="mt-1">{mapping.justificacion||'Sin justificación registrada'}</p>
    {mapping.eventos.length ? <EvidenceEvents events={mapping.eventos}/> : <p className="muted mt-1">Sin citas verificables</p>}
    <RelationLimits limits={Array.isArray(provenance?.limitaciones)?provenance.limitaciones:[]}/>
  </>
}

export function TechniqueRelation({mapping}: {mapping: TechniqueLink}) {
  return <li className="border-l line pl-3">
    <div className="flex flex-wrap gap-2 items-baseline">
      <Link className="accent hover:underline" to={mappingEvidencePath(mapping.id_mapeo,mapping.eventos[0]?
        {technique:mapping.codigo_tecnica,session:mapping.eventos[0].id_sesion}:undefined)}>{mapping.codigo_tecnica} · {mapping.tecnica}</Link>
      <MappingStatus mapping={mapping}/>
      <RelationBadge state={mapping.estado}/>
    </div>
    <p className="mt-1">{mapping.justificacion}</p>
    <p className="muted mt-1">{mapping.fundamento} Evento compartido #{mapping.evento_compartido}.</p>
    {mapping.motivo_revision&&<p className="muted mt-1">{mapping.motivo_revision}</p>}
    <EvidenceEvents events={mapping.eventos}/>
    <RelationLimits limits={mapping.limitaciones}/>
  </li>
}

export function ObservableLinks({links}: {links: ObservableLink[]}) {
  return <ul className="space-y-3 mt-2">
    {links.map(link=><li key={link.id_ioc+'-'+link.id_evento} className="border-l line pl-3">
      <div className="flex flex-wrap items-baseline gap-2">
        <Link className="accent break-all hover:underline" to={observableEvidencePath(link.id_ioc,link.id_evento)}>
          {link.tipo} · {link.valor}
        </Link>
        <RelationBadge state={link.estado}/>
      </div>
      <p className="mt-1">{link.justificacion}</p>
      {!!link.papeles?.length&&<p className="muted mt-1">{link.papeles.map(role=>behaviorLabels[role]??role).join(' · ')}</p>}
      <EvidenceEvents events={link.eventos}/>
      <RelationLimits limits={link.limitaciones}/>
    </li>)}
  </ul>
}

type MappingDetail = {mapeo: MappingEvidence; observables: ObservableLink[]; hay_mas: boolean}
const PAGE_SIZE = 10

export function MappingObservables({id, review, detailed=false}: {id: string; review: string; detailed?:boolean}) {
  const [page,setPage]=useState(0)
  const [data,setData]=useState<MappingDetail|null>(null)
  const [error,setError]=useState('')
  useEffect(()=>{
    const controller=new AbortController()
    setError('');setData(null)
    api<MappingDetail>(`/mitre/mapeos/${id}/observables?limit=${PAGE_SIZE}&offset=${page*PAGE_SIZE}`+(detailed?'&detallar_citas=true':''),{signal:controller.signal})
      .then(result=>{if(!controller.signal.aborted)setData(result)})
      .catch(e=>{if(!controller.signal.aborted)setError((e as Error).message)})
    return ()=>controller.abort()
  },[id,review,page,detailed])
  return <section className="border-t line mt-6 pt-5 text-xs">
    <h4 className="font-semibold text-sm">Evidencia y observables asociados</h4>
    {error&&<p role="alert" className="text-red-300 mt-2">{error}</p>}
    {!data&&!error&&<p role="status" className="muted mt-2">Cargando evidencia…</p>}
    {data&&<>
      <MappingBasis mapping={data.mapeo}/>
      {data.observables.length>0?<ObservableLinks links={data.observables}/>:
        data.mapeo.eventos.length>0&&<p className="muted mt-3">{
          data.mapeo.estado_revision==='descartado'?'El mapeo está descartado.':
            page>0?'No hay observables en esta página.':'No hay observables con evidencia verificable compartida.'}</p>}
      {(page>0||data.hay_mas)&&<div className="flex gap-2 mt-3">
        <button type="button" className="btn-secondary" disabled={page===0} onClick={()=>setPage(page-1)}>Anterior</button>
        <button type="button" className="btn-secondary" disabled={!data.hay_mas} onClick={()=>setPage(page+1)}>Siguiente</button>
      </div>}
    </>}
  </section>
}
