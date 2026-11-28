import {useEffect,useRef,useState,type FormEvent,type ReactNode} from 'react'
import {Link,useParams} from 'react-router-dom'
import {api,mutate} from '../../auth/client'
import {useAuth} from '../../auth/context'
import {useMonitorQuery} from '../../monitoring/Realtime'
import {EvidenceLink,eventsFrom,input,ResponseBoard,Timeline} from './ResponseBoard'
import {ResponseReport} from './ResponseReport'
import {actionStates,pathFor,phases,planStates,type Action,type Antecedent,type Lot,type Page,type Person,type Phase,type Plan} from './model'
import './response.css'

const DOMAIN=['respuesta_incidentes'] as const

function Field({name,label,value='',required=true,short=false}:{name:string;label:string;value?:string;required?:boolean;short?:boolean}) {
  return <label className="block">{label}
    {short?<input name={name} className={input} required={required} defaultValue={value} minLength={3} maxLength={200}/>:
      <textarea name={name} className={input} required={required} defaultValue={value} minLength={8} maxLength={2000}/>}
  </label>
}

function PhaseSelect({excluded}:{excluded?:Plan['fases_no_aplicables']}) {
  return <label className="block">Fase<select className={input} name="fase" required defaultValue="">
    <option value="">Seleccione una fase</option>
    {Object.entries(phases).map(([key,label])=>!excluded?.[key as Phase]&&<option key={key} value={key}>{label}</option>)}
  </select></label>
}

function SaveForm({children,label,run,onSaved}:{children:ReactNode;label:string;
  run:(form:FormData)=>Promise<unknown>;onSaved:()=>void}) {
  const [busy,setBusy]=useState(false), [error,setError]=useState('')
  async function save(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy)return
    const form=event.currentTarget
    setBusy(true);setError('')
    try {await run(new FormData(form));form.reset();onSaved()}
    catch(failure){setError((failure as Error).message)}
    finally{setBusy(false)}
  }
  return <form className="space-y-3" onSubmit={save}>{children}
    {error&&<p role="alert">{error}</p>}
    <button className="btn" disabled={busy}>{busy?'Guardando…':label}</button>
  </form>
}

function PlanEditor({plan,path,onSaved}:{plan:Plan;path:string;onSaved:()=>void}) {
  const review=!!plan.id_respuesta
  const [people,setPeople]=useState<Person[]>([]), [pending,setPending]=useState<Action[]>([])
  const [ready,setReady]=useState(false), [error,setError]=useState('')
  useEffect(()=>{
    const request=new AbortController()
    async function unresolved(){
      const pending:Action[]=[]
      const query=new URLSearchParams({limite:'100'})
      for(const state of ['propuesta','aprobada','en_curso','ejecutada'])query.append('estado',state)
      if(!review)return pending
      for(let page=0;page<6;page++){
        const result:Page<Action>=await api(path+'/acciones?'+query,{signal:request.signal})
        pending.push(...result.items)
        if(!result.cursor&&pending.length<=500)return pending
        if(result.cursor)query.set('cursor',result.cursor)
      }
      throw new Error('Regularice las acciones abiertas antes de revisar un plan con más de 500 pendientes.')
    }
    Promise.all([api<Person[]>('/respuestas-incidentes/responsables',{signal:request.signal}),unresolved()])
      .then(([users,actions])=>{if(!request.signal.aborted){setPeople(users);setPending(actions);setReady(true)}})
      .catch(failure=>{if(!request.signal.aborted)setError(failure.message)})
    return ()=>request.abort()
  },[path,review])
  if(error)return <p role="alert">{error}</p>
  if(!ready)return <p role="status">Cargando datos del plan…</p>
  return <SaveForm label={review?'Confirmar revisión':'Abrir plan de respuesta'} onSaved={onSaved} run={form=>{
    const exclusions=Object.fromEntries(Object.keys(phases).flatMap(phase=>{
      const reason=String(form.get('excluir_'+phase)||'').trim()
      return reason?[[phase,reason]]:[]
    }))
    return mutate(path+(review?'/revisiones':''),{
      revision_evaluacion:plan.revision_evaluacion_actual,objetivo:form.get('objetivo'),alcance:form.get('alcance'),
      criterio_cierre:form.get('criterio_cierre'),id_responsable:form.get('responsable')||null,fases_no_aplicables:exclusions,
      ...(review?{revision_esperada:plan.revision_respuesta,motivo:form.get('motivo'),
        ratificar:pending.filter(action=>form.get(action.id_accion)==='ratificar').map(action=>action.id_accion),
        cancelar:pending.filter(action=>form.get(action.id_accion)==='cancelar').map(action=>action.id_accion)}:{}),
    })
  }}>
    {!review&&plan.borrador&&<p className="muted text-sm">Borrador de la evaluación vigente. Revise el alcance y el criterio antes de abrir el plan.</p>}
    <Field name="objetivo" label="Objetivo del plan" value={plan.objetivo??plan.borrador?.objetivo}/>
    <Field name="alcance" label="Alcance autorizado" value={plan.alcance??plan.borrador?.alcance}/>
    <Field name="criterio_cierre" label="Criterio de cierre" value={plan.criterio_cierre??plan.borrador?.criterio_cierre}/>
    <label className="block">Responsable del plan<select name="responsable" className={input} defaultValue={plan.id_responsable??''}>
      <option value="">Sin asignar</option>{people.map(person=><option value={person.id_usuario} key={person.id_usuario}>{person.nombre_usuario}</option>)}
    </select></label>
    <fieldset className="grid gap-2 sm:grid-cols-2"><legend>Motivo de las fases que no aplican</legend>
      {Object.entries(phases).map(([phase,label])=><Field key={phase} name={'excluir_'+phase} label={label}
        value={plan.fases_no_aplicables?.[phase as Phase]} required={false}/>)}
    </fieldset>
    {review&&<Field name="motivo" label="Motivo de la revisión"/>}
    {pending.map(action=><label key={action.id_accion} className="block">{action.medida} · {actionStates[action.estado]}
      <select name={action.id_accion} className={input} required defaultValue="">
        <option value="">Seleccione una decisión</option><option value="ratificar">Ratificar</option>
        {['propuesta','aprobada'].includes(action.estado)&&<option value="cancelar">Cancelar</option>}
      </select></label>)}
  </SaveForm>
}

function CreateAction({plan,path,done}:{plan:Plan;path:string;done:()=>void}) {
  return <SaveForm label="Registrar propuesta" onSaved={done} run={form=>mutate(path+'/acciones',{
    revision_evaluacion:plan.revision_evaluacion_actual,revision_esperada:plan.revision_respuesta,
    fase:form.get('fase'),medida:form.get('medida'),objetivo:form.get('objetivo'),justificacion:form.get('justificacion'),
    criterio_verificacion:form.get('criterio_verificacion'),motivo:form.get('motivo'),
    eventos:eventsFrom(form.get('eventos')),referencia:form.get('referencia')||null,
  })}>
    <PhaseSelect excluded={plan.fases_no_aplicables}/><Field name="medida" label="Medida propuesta" short/>
    <Field name="objetivo" label="Objetivo"/><Field name="justificacion" label="Justificación"/>
    <Field name="criterio_verificacion" label="Criterio de verificación"/><Field name="motivo" label="Motivo de registro"/>
    <label className="block">IDs de eventos de la evaluación<input name="eventos" className={input} placeholder="Separados por coma"/></label>
    <Field name="referencia" label="Referencia verificable si no se citan eventos" required={false}/>
  </SaveForm>
}

function Lifecycle({plan,path,done}:{plan:Plan;path:string;done:()=>void}) {
  const available=[...(plan.elegible&&!plan.desactualizada&&plan.estado==='en_respuesta'?['resolver']:[]),
    ...(plan.elegible&&!plan.desactualizada&&plan.estado==='resuelto'?['cerrar']:[]),
    ...(plan.elegible&&['resuelto','cerrado','cancelado'].includes(plan.estado)?['reabrir']:[]),
    ...(!plan.elegible&&['en_respuesta','resuelto'].includes(plan.estado)?['cancelar']:[])]
  const [op,setOp]=useState('')
  if(!available.length)return null
  const label:Record<string,string>={resolver:'Resolver',cerrar:'Cerrar',reabrir:'Reabrir',cancelar:'Cancelar'}
  return <details className="panel p-4"><summary className="font-semibold cursor-pointer">Cambiar estado de respuesta</summary>
    <div className="mt-3"><SaveForm label="Confirmar cambio" onSaved={done} run={form=>mutate(path+'/transiciones',{
      operacion:op,revision_evaluacion:plan.revision_evaluacion_actual,revision_esperada:plan.revision_respuesta,
      motivo:form.get('motivo'),resultado:form.get('resultado')||null,riesgos_pendientes:form.get('riesgos_pendientes')||null,
      sin_acciones:form.get('sin_acciones')||null,referencia:form.get('referencia')||null,
    })}>
      <label className="block">Operación<select className={input} required value={op} onChange={event=>setOp(event.target.value)}>
        <option value="">Seleccione</option>{available.map(key=><option key={key} value={key}>{label[key]}</option>)}</select></label>
      {op&&<Field name="motivo" label="Motivo de la transición"/>}
      {['resolver','cerrar'].includes(op)&&<><Field name="resultado" label="Comprobación del resultado"/>
        <Field name="referencia" label="Evidencia verificable"/></>}
      {op==='resolver'&&<><Field name="riesgos_pendientes" label="Riesgos pendientes"/>
        <Field name="sin_acciones" label="Justificación si ninguna acción fue verificada" required={false}/></>}
    </SaveForm></div>
  </details>
}

const lotState:Record<string,string>={en_proceso:'En proceso',completado:'Completado',fallido:'Fallido',
  vencido:'Vencido',sustituido:'Evaluación o plan actualizado'}
function Recommendations({plan,path,admin,done}:{plan:Plan;path:string;admin:boolean;done:()=>void}) {
  const key=useRef<string|undefined>(undefined)
  const [list,setList]=useState<Lot[]>([]), [error,setError]=useState('')
  const [open,setOpen]=useState(false)
  useMonitorQuery(async signal=>{
    if(!open)return
    try{const values=await api<Lot[]>(path+'/recomendaciones',{signal});if(!signal.aborted){setList(values);setError('')}}
    catch(failure){if(!signal.aborted)setError((failure as Error).message);throw failure}
  },5000,[path,open],DOMAIN)
  return <details className="panel p-4" onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary className="font-semibold cursor-pointer">Recomendaciones fundamentadas</summary>
    <div className="space-y-3 mt-3">
      {admin&&plan.estado==='en_respuesta'&&!plan.desactualizada&&
        <SaveForm label="Solicitar recomendaciones a DeepSeek" onSaved={done} run={async form=>{
          key.current??=crypto.randomUUID()
          const result=await api<Lot>(path+'/recomendaciones',{method:'POST',
            headers:{'Content-Type':'application/json','Idempotency-Key':key.current},
            body:JSON.stringify({revision_evaluacion:plan.revision_evaluacion_actual,revision_esperada:plan.revision_respuesta,
              motivo:form.get('motivo')})})
          setList(values=>[result,...values.filter(lot=>lot.id_lote!==result.id_lote)])
          key.current=undefined
        }}><Field name="motivo" label="Motivo de la solicitud"/></SaveForm>}
      {error&&<p role="alert">{error}</p>}
      {list.map(lot=><article className="border-t line py-2 text-sm" key={lot.id_lote}>
        <strong>{lotState[lot.estado]??lot.estado}</strong>
        {lot.error_codigo&&<p>{lot.error_codigo.replaceAll('_',' ')}</p>}
        {lot.resultado?.abstencion&&<p>Abstención · {lot.resultado.abstencion}</p>}
        {!!lot.resultado?.acciones.length&&<p>{lot.resultado.acciones.length} propuestas registradas</p>}
      </article>)}
    </div>
  </details>
}

function Antecedents({plan,path,admin,done}:{plan:Plan;path:string;admin:boolean;done:()=>void}) {
  const [open,setOpen]=useState(false), [data,setData]=useState<{items:Antecedent[];omitidos:number}>()
  const [selected,setSelected]=useState<Antecedent>(), [error,setError]=useState('')
  useEffect(()=>{
    if(!open)return
    const request=new AbortController()
    api<{items:Antecedent[];omitidos:number}>(path+'/antecedentes',{signal:request.signal})
      .then(item=>{if(!request.signal.aborted)setData(item)})
      .catch(failure=>{if(!request.signal.aborted)setError(failure.message)})
    return ()=>request.abort()
  },[open,path,plan.revision_evaluacion_actual])
  return <details className="panel p-4" onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary className="font-semibold cursor-pointer">Antecedentes de análisis y salvaguardas</summary>
    {error&&<p role="alert">{error}</p>}
    {data&&<div className="space-y-3 mt-3">
      {!data.items.length&&<p className="muted">La evaluación no cita análisis con recomendaciones.</p>}
      {!!data.omitidos&&<p className="muted">{data.omitidos} antecedentes omitidos.</p>}
      {data.items.map(item=><article key={item.id_analisis+':'+item.posicion} className="border-t line pt-2">
        <strong>{item.recomendacion.salvaguarda??'Recomendación histórica'}</strong>
        <p className="text-sm muted">{item.recomendacion.objetivo}</p>
        {item.importable&&admin&&plan.estado==='en_respuesta'&&!plan.desactualizada&&
          <button className="btn-secondary" onClick={()=>setSelected(item)}>Vincular como propuesta</button>}
        {!item.importable&&<p className="text-sm muted">Sin citas suficientes para importar.</p>}
      </article>)}
      {selected&&<SaveForm label="Confirmar vínculo" onSaved={()=>{setSelected(undefined);done()}} run={form=>mutate(path+'/importaciones',{
        revision_evaluacion:plan.revision_evaluacion_actual,revision_esperada:plan.revision_respuesta,
        fase:form.get('fase'),motivo:form.get('motivo'),...(selected.id_salvaguarda?{id_salvaguarda:selected.id_salvaguarda}
          :{id_analisis:selected.id_analisis,posicion:selected.posicion}),
      })}><PhaseSelect excluded={plan.fases_no_aplicables}/><Field name="motivo" label="Justificación del vínculo"/></SaveForm>}
    </div>}
  </details>
}

export function ResponseBoardPage() {
  return <div className="space-y-5"><header className="border-b line pb-4">
    <h1 className="text-2xl font-bold">Respuesta a incidentes</h1>
    <div className="flex flex-wrap gap-4 mt-2"><Link className="accent underline" to="/incidentes">Ver incidentes</Link>
      <Link className="accent underline" to="/salvaguardas">Historial de salvaguardas</Link></div>
  </header><ResponseBoard/></div>
}

export function IncidentResponsePage() {
  const {id}=useParams()
  return id?<IncidentResponse key={id} id={id}/>:null
}

function IncidentResponse({id}:{id:string}) {
  const {session}=useAuth()
  const admin=session?.usuario.rol==='administrador'
  const path=pathFor(id)
  const [plan,setPlan]=useState<Plan>(), [error,setError]=useState(''), [status,setStatus]=useState('')
  const [revision,reload]=useState(0), [editor,setEditor]=useState<'plan'|'accion'>()
  useMonitorQuery(async signal=>{
    try {const result=await api<Plan>(path,{signal});if(!signal.aborted){setPlan(result);setError('')}}
    catch(failure){if(!signal.aborted)setError((failure as Error).message);throw failure}
  },5000,[path,revision],DOMAIN)
  function done(){setEditor(undefined);setStatus('Cambios registrados.');reload(value=>value+1)}
  if(!plan)return error?<div role="alert">{error} <button className="btn-secondary" onClick={()=>reload(value=>value+1)}>Reintentar</button></div>
    :<p role="status">Cargando respuesta…</p>
  const editable=plan.estado==='en_respuesta'&&!plan.desactualizada
  const formKey=plan.revision_respuesta+':'+plan.revision_evaluacion_actual
  return <div className="space-y-5">
    <header className="border-b line pb-4 space-y-2">
      <div className="flex flex-wrap gap-3"><Link className="accent underline" to="/respuesta-incidentes">Tablero de respuesta</Link>
        <Link className="accent underline" to={'/incidentes/'+id}>Evaluación del incidente</Link></div>
      <h1 className="text-2xl font-bold">{plan.evaluacion.titulo}</h1>
      <p>{plan.evaluacion.resumen}</p>
      <p className="muted">Evaluación {plan.revision_evaluacion_actual} · {plan.evaluacion.decision.replaceAll('_',' ')}
        {plan.evaluacion.severidad&&' · '+plan.evaluacion.severidad}</p>
    </header>
    {error&&<p role="alert">{error}</p>}{status&&<p role="status">{status}</p>}
    <section className="panel p-4 space-y-3"><div className="flex flex-wrap items-center gap-3">
      <h2 className="font-semibold">Plan de respuesta</h2><span className="badge">{planStates[plan.estado]}</span>
      {plan.desactualizada&&<span className="badge warn">Evaluación actualizada</span>}</div>
      {!plan.elegible&&<p className="muted">La evaluación actual no habilita nuevas acciones.</p>}
      {plan.id_respuesta&&<dl className="grid gap-3 sm:grid-cols-2">
        <div><dt className="font-semibold">Objetivo</dt><dd>{plan.objetivo}</dd></div>
        <div><dt className="font-semibold">Alcance</dt><dd>{plan.alcance}</dd></div>
        <div><dt className="font-semibold">Criterio de cierre</dt><dd>{plan.criterio_cierre}</dd></div>
        <div><dt className="font-semibold">Versiones</dt><dd>Plan {plan.revision_plan} · Respuesta {plan.revision_respuesta}</dd></div>
        {plan.resolucion?.resultado&&<div><dt className="font-semibold">Resolución</dt><dd>{plan.resolucion.resultado}</dd></div>}
      </dl>}
      {plan.evaluacion.evidencias.length>0&&<details><summary>Evidencias de evaluación</summary><ul className="mt-2">
        {plan.evaluacion.evidencias.map(c=><li key={c.id_evento}><EvidenceLink event={c.id_evento} session={c.id_sesion}/> · {c.grado}</li>)}
      </ul></details>}
      <div className="flex flex-wrap gap-2">
        {admin&&plan.elegible&&['sin_respuesta','en_respuesta'].includes(plan.estado)&&
          <button className="btn-secondary" onClick={()=>setEditor(editor==='plan'?undefined:'plan')}>
            {plan.id_respuesta?'Revisar plan':'Crear plan'}</button>}
        {editable&&<button className="btn-secondary" onClick={()=>setEditor(editor==='accion'?undefined:'accion')}>Proponer acción</button>}
      </div>
      {editor==='plan'&&plan.elegible&&<PlanEditor key={formKey} plan={plan} path={path} onSaved={done}/>}
      {editor==='accion'&&editable&&<CreateAction key={formKey} plan={plan} path={path} done={done}/>}
    </section>
    {plan.id_respuesta&&<>
      {admin&&<Lifecycle key={formKey} plan={plan} path={path} done={done}/>}
      <Recommendations plan={plan} path={path} admin={admin} done={()=>reload(value=>value+1)}/>
      <Antecedents key={formKey} plan={plan} path={path} admin={admin} done={done}/>
      <ResponseBoard incident={id} refresh={revision} onChanged={done}/>
      <section className="panel p-4"><h2 className="font-semibold">Historial de actuaciones</h2><Timeline path={path+'/historial'}/></section>
      <ResponseReport path={path}/>
    </>}
  </div>
}
