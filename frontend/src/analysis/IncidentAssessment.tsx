import {useState} from 'react'
import {mutate} from '../auth/client'
import {useAuth} from '../auth/context'
import {Link} from 'react-router-dom'
import {eventEvidencePath} from './iocEvidence'

export type Assessment = {
  metodologia:string; clasificacion:string; estado:string; severidad:string;
  prioridad_triaje:string|null; fundamento_prioridad:string; snapshot_sha256:string;
  automatica?:{fundamento:string; decision_recomendada:string; eventos:string[]; recursos:string[];
    clasificacion?:string; severidad?:string; prioridad?:string|null};
  eventos?:string[]; eventos_evaluados:number; origen?:string; generado_en:string;
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
  const previous=assessment?.revisiones[assessment.revisiones.length-1]
  const cited=assessment?.criterios.flatMap(item=>item.eventos.slice(0,1)) ?? []
  const draft:Record<string,string>={
    alcance:previous?.alcance ?? 'Telemetría de la sesión Cowrie '+session,
    responsable:previous?.responsable ?? auth?.usuario.nombre_usuario ?? '',
    eventos:(previous?.eventos ?? (cited.length ? cited : assessment?.eventos?.slice(0,1)) ?? []).join(', '),
    impacto:previous?.impacto ?? 'Impacto sobre activos reales pendiente de corroboración.',
    criterio_incidente:previous?.criterio_incidente ?? '',
    medidas:previous?.medidas ?? '',
  }
  const fields:Record<string,string>={justificacion:'Fundamento de esta decisión',criterio_incidente:'Criterio de clasificación',impacto:'Impacto corroborado',alcance:'Alcance',responsable:'Responsable',medidas:'Medidas acordadas',eventos:'Eventos de respaldo'}
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
  if (!admin && !assessment?.revisiones.length) return null
  return <section className="border line rounded-lg p-4 space-y-3" aria-label="Revisión humana del incidente">
    <h3 className="font-semibold text-lg">Revisión humana del incidente</h3>
    {error&&<p role="alert" className="text-red-300">{error}</p>}
    {!assessment?<><p className="muted">Este análisis requiere una evaluación de los eventos almacenados.</p>
      {admin&&<button className="btn-secondary" disabled={busy} onClick={prepare}>Preparar evaluación local</button>}</>:<>
      {assessment.revisiones.map((review,index)=><details key={index} open={index===assessment.revisiones.length-1}>
        <summary className="cursor-pointer font-semibold">Revisión {index+1} · {label(review.decision)} · {new Date(review.revisado_en).toLocaleString('es-EC',{timeZone:'America/Guayaquil'})}</summary>
        <dl className="text-sm space-y-2 mt-2">{(['justificacion','criterio_incidente','impacto','alcance','responsable','medidas','criterio_cierre'] as const).map(key=>review[key]&&<div key={key}><dt className="muted">{label(key)}</dt><dd className="whitespace-pre-wrap">{review[key]}</dd></div>)}</dl>
        <div className="text-xs">{review.eventos.map(eid=><Link key={eid} className="accent underline mr-2"
          to={eventEvidencePath(session,eid)}>Evento #{eid}</Link>)}</div>
      </details>)}
      {admin&&<details><summary className="cursor-pointer font-semibold">Validar la evaluación y registrar una decisión</summary>
        <p className="muted text-xs mt-2">El triaje y las propuestas se generan con el análisis. Revise el borrador cuando disponga de contexto sobre autorización e impacto. Puede consultar y exportar el informe antes de registrar su decisión.</p>
        <form key={assessment.revisiones.length} onSubmit={save} className="grid sm:grid-cols-2 gap-3 mt-3">
          <label>Decisión<select className="input w-full" name="decision" defaultValue={previous?.decision ?? ""} required><option value="" disabled>Seleccione la decisión</option><option value="evidencia_insuficiente">Evidencia insuficiente</option><option value="actividad_sospechosa">Actividad sospechosa</option><option value="actividad_autorizada">Actividad autorizada</option><option value="incidente_confirmado">Incidente confirmado</option></select></label>
          <label>Severidad<select className="input w-full" name="severidad" defaultValue={previous?.severidad}>{['por_determinar','baja','media','alta','critica'].map(value=><option key={value} value={value}>{label(value)}</option>)}</select></label>
          {['justificacion','criterio_incidente','impacto','alcance','responsable','medidas','eventos'].map(name=><label key={name}>{fields[name]}{name==='eventos'?' (IDs separados por coma)':''}<textarea className="input w-full" required defaultValue={draft[name]} name={name} minLength={name==='justificacion'?30:undefined}/></label>)}
          <label>Estado<select className="input w-full" name="estado" defaultValue={previous?.estado}>{['en_investigacion','en_respuesta','cerrado'].map(value=><option key={value} value={value}>{label(value)}</option>)}</select></label>
          <label>Criterio y verificación de cierre<textarea className="input w-full" name="criterio_cierre" defaultValue={previous?.criterio_cierre}/></label>
          <button className="btn" disabled={busy}>Guardar revisión</button>
        </form>
      </details>}
    </>}
  </section>
}
