import {useState} from 'react'
import {mutate} from '../auth/client'
import {useAuth} from '../auth/context'
import {Link} from 'react-router-dom'
import {eventEvidencePath} from './iocEvidence'

export type Assessment = {
  metodologia:string; clasificacion:string; estado:string; severidad:string;
  prioridad_triaje:string; fundamento_prioridad:string; snapshot_sha256:string;
  eventos_evaluados:number; origen?:string; generado_en:string;
  criterios:{criterio:string; descripcion:string; cumplido:boolean; eventos:string[]}[];
  limitaciones:string[];
  revisiones:{decision:string; severidad:string; justificacion:string; criterio_incidente:string;
    impacto:string; alcance:string; responsable:string; medidas:string; estado:string;
    criterio_cierre:string; revisado_en:string; revisado_por:string; eventos:string[]}[];
}

const label=(text:string)=>text.replaceAll('_',' ')

export function IncidentAssessment({id,session,initial}:{id:string;session:string;initial?:Assessment}) {
  const {session:auth}=useAuth()
  const [assessment,setAssessment]=useState(initial)
  const [error,setError]=useState(''),[busy,setBusy]=useState(false)
  const admin=auth?.usuario.rol==='administrador'
  async function prepare(){
    setBusy(true);setError('')
    try{setAssessment(await mutate<Assessment>(`/analisis/${id}/preparar-evaluacion`))}
    catch(e){setError((e as Error).message)}finally{setBusy(false)}
  }
  async function save(event:React.FormEvent<HTMLFormElement>){
    event.preventDefault()
    const data=Object.fromEntries(new FormData(event.currentTarget))
    setBusy(true);setError('')
    try{
      setAssessment(await mutate<Assessment>(`/analisis/${id}/evaluacion-incidente`,{
        ...data,revision_esperada:assessment?.revisiones.length??0,
        eventos:String(data.eventos).split(',').map(value=>value.trim())
      }))
    }catch(e){setError((e as Error).message)}finally{setBusy(false)}
  }
  return <section className="border line rounded-lg p-4 space-y-3" aria-label="Evaluación de incidente">
    <h3 className="font-semibold text-lg">Evaluación de incidente</h3>
    {error&&<p role="alert" className="text-red-300">{error}</p>}
    {!assessment?<><p className="muted">Este análisis requiere una evaluación de los eventos almacenados.</p>
      {admin&&<button className="btn-secondary" disabled={busy} onClick={prepare}>Preparar evaluación local</button>}</>:<>
      <dl className="grid sm:grid-cols-2 gap-3 text-sm">
        <div><dt className="muted">Clasificación</dt><dd>{label(assessment.clasificacion)}</dd></div>
        <div><dt className="muted">Estado</dt><dd>{label(assessment.estado)}</dd></div>
        <div><dt className="muted">Severidad</dt><dd>{label(assessment.severidad)}</dd></div>
        <div><dt className="muted">Prioridad de triaje</dt><dd>{assessment.prioridad_triaje}</dd></div>
      </dl>
      <p className="muted text-xs">{assessment.fundamento_prioridad}</p>
      <ul className="space-y-2">{assessment.criterios.map(item=><li key={item.criterio}>
        <strong>{item.descripcion}</strong> · {item.cumplido?'Registrado':'Sin evidencia en la captura'}
        <div className="text-xs">{item.eventos.map(eid=><Link key={eid} className="accent underline mr-2" to={eventEvidencePath(session,eid)}>Evento #{eid}</Link>)}</div>
      </li>)}</ul>
      <details><summary className="cursor-pointer">Método y cobertura</summary>
        <p className="text-xs muted break-all">{assessment.metodologia} · {assessment.eventos_evaluados} eventos · {assessment.generado_en}<br/>SHA-256 {assessment.snapshot_sha256}</p>
        {assessment.origen&&<p>{assessment.origen}</p>}
        <ul className="text-xs muted">{assessment.limitaciones.map(item=><li key={item}>{item}</li>)}</ul>
      </details>
      {assessment.revisiones.map((review,index)=><details key={index} open={index===assessment.revisiones.length-1}>
        <summary className="cursor-pointer font-semibold">Revisión {index+1} · {label(review.decision)} · {new Date(review.revisado_en).toLocaleString('es-EC')}</summary>
        <dl className="text-sm space-y-2 mt-2">{(['justificacion','criterio_incidente','impacto','alcance','responsable','medidas','criterio_cierre'] as const).map(key=>review[key]&&<div key={key}><dt className="muted">{label(key)}</dt><dd className="whitespace-pre-wrap">{review[key]}</dd></div>)}</dl>
      </details>)}
      {admin&&<details><summary className="cursor-pointer font-semibold">Registrar decisión del analista</summary>
        <form onSubmit={save} className="grid sm:grid-cols-2 gap-3 mt-3">
          <label>Decisión<select className="input w-full" name="decision"><option value="evidencia_insuficiente">Evidencia insuficiente</option><option value="actividad_sospechosa">Actividad sospechosa</option><option value="actividad_autorizada">Actividad autorizada</option><option value="incidente_confirmado">Incidente confirmado</option></select></label>
          <label>Severidad<select className="input w-full" name="severidad">{['por_determinar','baja','media','alta','critica'].map(value=><option key={value} value={value}>{label(value)}</option>)}</select></label>
          {['justificacion','criterio_incidente','impacto','alcance','responsable','medidas','eventos'].map(name=><label key={name}>{label(name)}{name==='eventos'?' (IDs separados por coma)':''}<textarea className="input w-full" required name={name} minLength={name==='justificacion'?30:undefined}/></label>)}
          <label>Estado<select className="input w-full" name="estado">{['en_investigacion','en_respuesta','cerrado'].map(value=><option key={value} value={value}>{label(value)}</option>)}</select></label>
          <label>Criterio y verificación de cierre<textarea className="input w-full" name="criterio_cierre"/></label>
          <button className="btn" disabled={busy}>Guardar revisión</button>
        </form>
      </details>}
    </>}
  </section>
}
