import {useState,type FormEvent} from 'react'
import {api,mutate} from '../../auth/client'
import {useMonitorQuery} from '../../monitoring/Realtime'
import {EvidenceLink,eventsFrom,input} from './ResponseBoard'
import {dateTime,phases,priorities,type Person,type Phase,type Plan} from './model'

type Priority=keyof typeof priorities
type DraftAction={clave:string;fase:Phase;medida:string;descripcion:string;objetivo:string;justificacion:string;
  criterio_verificacion:string;prioridad:Priority;rol_sugerido:string;plazo_dias:number;dependencias:string[];mitre:string[];
  eventos:string[];resultado_esperado:string;antecedente?:string|null}
type Proposal={titulo:string;objetivo:string;resumen:string;alcance:string;estrategia:string;prioridad:Priority;
  resultado_esperado:string;criterio_resolucion:string;criterio_cierre:string;eventos:string[];acciones:DraftAction[]}
type Choice={estado:'pendiente'|'elegible'|'rechazada';motivo:string;id_responsable?:string|null;id_accion?:string}
type Version={version:number;motivo:string;creado_en:string;propuesta:{plan?:Proposal;abstencion?:string};decisiones:Record<string,Choice>}
type Assignee=Person&{rol:string;carga:number;en_curso:number}
type Draft={id_borrador:string;creado_en:string;estado:string;vigente:boolean;historico:boolean;error_codigo?:string;
  versiones:Version[];sugerencias?:Record<string,Assignee|null>;responsables?:Assignee[];wip_disponible?:boolean}

const DOMAIN=['respuesta_incidentes'] as const
const stateNames:Record<string,string>={pendiente:'En cola',en_proceso:'Generando',disponible:'Pendiente de revisión',
  abstencion:'Evidencia insuficiente',fallido:'Generación fallida',sustituido:'Evidencia actualizada',aprobado:'Aprobado',rechazado:'Rechazado'}
const errorNames:Record<string,string>={proveedor_sin_configurar:'Revise la configuración de DeepSeek',
  proveedor_no_disponible:'DeepSeek no está disponible',plazo_agotado:'La generación superó el plazo',
  respuesta_o_citas_invalidas:'La respuesta o sus citas no superaron la validación',
  contexto_demasiado_grande:'El contexto supera el límite de la propuesta',contexto_incompatible:'La evidencia guardada tiene un formato incompatible',
  evidencia_modificada:'La evidencia cambió'}
const planFields={titulo:'Título',objetivo:'Objetivo',resumen:'Situación',alcance:'Alcance',estrategia:'Estrategia',
  resultado_esperado:'Resultado esperado',criterio_resolucion:'Criterio de resolución',criterio_cierre:'Criterio de cierre'} as const
const actionFields={medida:'Título',descripcion:'Descripción',objetivo:'Objetivo',justificacion:'Justificación técnica',
  resultado_esperado:'Resultado esperado',criterio_verificacion:'Criterio de verificación'} as const

function Citations({eventos,plan}:{eventos:string[];plan:Plan}){
  return <ul className="flex flex-wrap gap-3 text-sm">{eventos.map(event=>{
    const link=plan.evaluacion.evidencias.find(item=>item.id_evento===event)
    return <li key={event}>{link?<EvidenceLink event={event} session={link.id_sesion}/>:<>Evento #{event}</>}</li>
  })}</ul>
}

function ProposalView({proposal,version,plan}:{proposal:Proposal;version:Version;plan:Plan}){
  return <div className="space-y-3">
    <dl className="grid gap-2 sm:grid-cols-2">{Object.entries(planFields).map(([key,label])=><div key={key}>
      <dt className="font-semibold">{label}</dt><dd>{proposal[key as keyof typeof planFields]}</dd></div>)}</dl>
    <p>Prioridad {priorities[proposal.prioridad]}</p><Citations eventos={proposal.eventos} plan={plan}/>
    {proposal.acciones.map(action=><details key={action.clave} className="rounded border line p-2">
      <summary>{action.clave} · {action.medida} · {priorities[action.prioridad]}
        {version.decisiones[action.clave]?.estado==='rechazada'&&' · Rechazada'}
        {version.decisiones[action.clave]?.id_accion&&' · Aprobada'}</summary>
      <div className="space-y-2 p-2"><p>{phases[action.fase]} · Rol {action.rol_sugerido} · Plazo {action.plazo_dias} días</p>
        {(Object.keys(actionFields) as Array<keyof typeof actionFields>).filter(field=>field!=='medida').map(field=><p key={field}>
          <strong>{actionFields[field]}</strong> {action[field]}</p>)}
        {!!action.dependencias.length&&<p>Depende de {action.dependencias.join(', ')}</p>}
        {!!action.mitre.length&&<p>MITRE {action.mitre.join(', ')}</p>}
        {action.antecedente&&<p>Salvaguarda de origen {action.antecedente}</p>}
        <Citations eventos={action.eventos} plan={plan}/>
      </div>
    </details>)}
  </div>
}

function emptyAction(proposal:Proposal):DraftAction {
  const next=Array.from({length:99},(_,index)=>'A'+(index+1)).find(key=>!proposal.acciones.some(item=>item.clave===key))!
  return {clave:next,fase:'investigacion',medida:'',descripcion:'',objetivo:'',justificacion:'',criterio_verificacion:'',
    prioridad:proposal.prioridad,rol_sugerido:'indistinto',plazo_dias:2,dependencias:[],mitre:[],eventos:[],resultado_esperado:''}
}

function DraftEditor({draft,version,plan,path,onSaved}:{draft:Draft;version:Version;plan:Plan;path:string;onSaved:()=>void}){
  const [proposal,setProposal]=useState(version.propuesta.plan!)
  const [decisions,setDecisions]=useState(version.decisiones)
  const [busy,setBusy]=useState(false),[error,setError]=useState('')
  function changeAction(key:string,changes:Partial<DraftAction>){
    setProposal(value=>({...value,acciones:value.acciones.map(item=>item.clave===key?{...item,...changes}:item)}))
  }
  function setChoice(key:string,changes:Partial<Choice>){
    setDecisions(current=>({...current,[key]:{...(current[key]??{motivo:'',estado:'pendiente'}),...changes}}))
  }
  async function submit(event:FormEvent<HTMLFormElement>){
    event.preventDefault();setBusy(true);setError('')
    const data=new FormData(event.currentTarget)
    try {
      await mutate(path,{revision_evaluacion:plan.revision_evaluacion_actual,revision_esperada:version.version,plan:proposal,
        motivo:data.get('motivo'),decisiones:Object.fromEntries(Object.entries(decisions)
          .filter(([key])=>proposal.acciones.some(item=>item.clave===key))
          .map(([key,item])=>[key,{estado:item.estado,id_responsable:item.id_responsable||null,motivo:item.motivo||data.get('motivo')}]))},'PUT')
      onSaved()
    } catch(failure){setError((failure as Error).message)}
    finally{setBusy(false)}
  }
  return <form className="space-y-3" onSubmit={submit}>
    <div className="grid gap-2 sm:grid-cols-2">{Object.entries(planFields).map(([key,label])=><label key={key}>{label}
      <textarea className={input} value={proposal[key as keyof typeof planFields]} required minLength={key==='titulo'?3:8}
        maxLength={key==='titulo'?200:2000} onChange={e=>setProposal({...proposal,[key]:e.target.value})}/></label>)}</div>
    <label>Prioridad del plan<select className={input} value={proposal.prioridad}
      onChange={e=>setProposal({...proposal,prioridad:e.target.value as Priority})}>{Object.entries(priorities).map(([key,label])=>
        <option value={key} key={key}>{label}</option>)}</select></label>
    <label>Eventos del plan<input className={input} defaultValue={proposal.eventos.join(', ')} required
      onChange={e=>setProposal({...proposal,eventos:eventsFrom(e.target.value)})}/></label>
    {proposal.acciones.map((action,index)=><details key={action.clave} open className="border line rounded p-2">
      <summary>{action.clave} · {action.medida||'Nueva actuación'}</summary>
      <fieldset disabled={!!decisions[action.clave]?.id_accion} className="space-y-2 py-2">
        {Object.entries(actionFields).map(([key,label])=><label className="block" key={key}>{label}
          <textarea className={input} value={action[key as keyof typeof actionFields]} required minLength={key==='medida'?3:8}
            maxLength={key==='medida'?200:2000} onChange={e=>changeAction(action.clave,{[key]:e.target.value})}/></label>)}
        <div className="grid gap-2 sm:grid-cols-3">
          <label>Fase<select className={input} value={action.fase} onChange={e=>changeAction(action.clave,{fase:e.target.value as Phase})}>
            {Object.entries(phases).map(([key,label])=><option value={key} key={key}>{label}</option>)}</select></label>
          <label>Prioridad<select className={input} value={action.prioridad}
            onChange={e=>changeAction(action.clave,{prioridad:e.target.value as Priority})}>{Object.entries(priorities).map(([key,label])=>
              <option value={key} key={key}>{label}</option>)}</select></label>
          <label>Plazo en días<input type="number" min={0} max={30} className={input} value={action.plazo_dias}
            onChange={e=>changeAction(action.clave,{plazo_dias:Number(e.target.value)})}/></label>
          <label>Perfil<select className={input} value={action.rol_sugerido} onChange={e=>changeAction(action.clave,{rol_sugerido:e.target.value})}>
            <option value="analista">Analista</option><option value="administrador">Administrador</option><option value="indistinto">Indistinto</option></select></label>
          <label>Eventos<input className={input} defaultValue={action.eventos.join(', ')} required
            onChange={e=>changeAction(action.clave,{eventos:eventsFrom(e.target.value)})}/></label>
          <label>Técnicas MITRE<input className={input} defaultValue={action.mitre.join(', ')}
            onChange={e=>changeAction(action.clave,{mitre:eventsFrom(e.target.value)})}/></label>
        </div>
        {index>0&&<label>Dependencias<select multiple className={input} value={action.dependencias}
          onChange={e=>changeAction(action.clave,{dependencias:Array.from(e.currentTarget.selectedOptions,item=>item.value)})}>
          {proposal.acciones.slice(0,index).map(item=><option value={item.clave} key={item.clave}>{item.clave} · {item.medida}</option>)}</select></label>}
        <label>Decisión<select className={input} value={decisions[action.clave]?.estado??'pendiente'}
          onChange={e=>setChoice(action.clave,{estado:e.target.value as Choice['estado']})}>
          <option value="pendiente">Pendiente</option>{plan.elegible&&<option value="elegible">Preseleccionar para aprobación</option>}
          <option value="rechazada">Rechazar acción</option></select></label>
        <label>Responsable<select className={input} value={decisions[action.clave]?.id_responsable??''}
          onChange={e=>setChoice(action.clave,{id_responsable:e.target.value||null})}>
          <option value="">Sugerencia automática{draft.sugerencias?.[action.clave]?' · '+draft.sugerencias[action.clave]?.nombre_usuario:''}</option>
          {draft.responsables?.map(person=><option key={person.id_usuario} value={person.id_usuario}>
            {person.nombre_usuario} · {person.rol} · {person.carga} asignadas, {person.en_curso} en curso</option>)}</select></label>
        {decisions[action.clave]?.estado==='rechazada'&&<label>Motivo de rechazo<input className={input} minLength={8} required
          value={decisions[action.clave]?.motivo??''} onChange={e=>setChoice(action.clave,{motivo:e.target.value})}/></label>}
        {proposal.acciones.length>1&&<button type="button" className="btn-secondary" onClick={()=>setProposal(value=>({...value,
          acciones:value.acciones.filter(item=>item.clave!==action.clave).map(item=>({...item,dependencias:item.dependencias.filter(key=>key!==action.clave)}))
        }))}>Retirar acción</button>}
      </fieldset>
    </details>)}
    {proposal.acciones.length<8&&<button type="button" className="btn-secondary"
      onClick={()=>setProposal({...proposal,acciones:[...proposal.acciones,emptyAction(proposal)]})}>Agregar acción</button>}
    <label className="block">Motivo de la revisión<textarea name="motivo" className={input} required minLength={8} maxLength={2000}/></label>
    {error&&<p role="alert">{error}</p>}<button className="btn" disabled={busy}>Guardar revisión</button>
  </form>
}

export function DraftPanel({path,plan,admin,onChanged}:{path:string;plan:Plan;admin:boolean;onChanged:()=>void}){
  const [items,setItems]=useState<Draft[]>([]),[enabled,setEnabled]=useState(false),[picked,setPicked]=useState('')
  const [detail,setDetail]=useState<Draft>(),[selectedVersion,setVersion]=useState(0)
  const [edit,setEdit]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[refresh,reload]=useState(0)
  const endpoint=path+'/borradores', id=picked||items[0]?.id_borrador
  useMonitorQuery(async signal=>{
    try {
      const list=await api<{items:Draft[];generacion_habilitada:boolean}>(endpoint,{signal})
      if(!signal.aborted){setItems(list.items);setEnabled(list.generacion_habilitada)}
    }catch(failure){if(!signal.aborted)setError((failure as Error).message);throw failure}
  },5000,[endpoint,refresh],DOMAIN)
  useMonitorQuery(async signal=>{
    if(!id)return
    const result=await api<Draft>(endpoint+'/'+id,{signal})
    if(!signal.aborted)setDetail(result)
  },5000,[endpoint,id,refresh],DOMAIN)
  const draft=detail?.id_borrador===id?detail:items.find(item=>item.id_borrador===id)
  const version=draft?.versiones.find(item=>item.version===selectedVersion)??draft?.versiones[0]
  const proposal=version?.propuesta.plan
  const canEdit=admin&&draft?.estado==='disponible'&&draft.vigente&&version?.version===draft.versiones[0]?.version
  function changed(){setEdit(false);setVersion(0);reload(value=>value+1);onChanged()}
  async function operate(event:FormEvent<HTMLFormElement>){
    event.preventDefault();setBusy(true);setError('')
    const data=new FormData(event.currentTarget), operation=(event.nativeEvent as SubmitEvent).submitter?.getAttribute('value')
    try {
      if(operation==='otra'){
        const job=await mutate<{id_borrador:string}>(endpoint,{motivo:data.get('motivo')})
        setPicked(job.id_borrador)
      }else if(version&&draft){
        const chosen=data.getAll('accion')
        if(operation==='aprobar'&&!chosen.length)throw new Error('Seleccione al menos una acción elegible.')
        await mutate(endpoint+'/'+draft.id_borrador+'/'+operation,{motivo:data.get('motivo'),
          revision_evaluacion:plan.revision_evaluacion_actual,revision_esperada:version.version,
          ...(operation==='aprobar'?{acciones:chosen}:{})})
      }
      changed()
    }catch(failure){setError((failure as Error).message)}finally{setBusy(false)}
  }
  return <section className="panel p-4 space-y-3"><h2 className="font-semibold">Borradores de respuesta</h2>
    {error&&<p role="alert">{error}</p>}
    {!items.length&&<p className="muted">{enabled?'Sin borradores registrados.':'Generación automática deshabilitada.'}</p>}
    {!!items.length&&<div className="flex flex-wrap gap-3"><label>Propuesta<select className={input} value={id} onChange={e=>{
      setPicked(e.target.value);setVersion(0);setEdit(false)
    }}>{items.map(item=><option value={item.id_borrador} key={item.id_borrador}>
      {dateTime(item.creado_en)} · {stateNames[item.estado]}{item.historico?' · Histórica':''}</option>)}</select></label>
      {!!draft?.versiones.length&&<label>Versión<select className={input} value={version?.version} onChange={e=>{
        setVersion(Number(e.target.value));setEdit(false)
      }}>{draft.versiones.map(item=><option value={item.version} key={item.version}>Versión {item.version}</option>)}</select></label>}</div>}
    {draft&&<p>{stateNames[draft.estado]}{!draft.vigente&&' · Evidencia desactualizada'}</p>}
    {draft?.error_codigo&&<p className="muted">{errorNames[draft.error_codigo]??'No se completó la generación'}</p>}
    {version&&<p className="muted">{dateTime(version.creado_en)} · {version.motivo}</p>}
    {version?.propuesta.abstencion&&<p>{version.propuesta.abstencion}</p>}
    {proposal&&version&&<ProposalView proposal={proposal} version={version} plan={plan}/>}
    {canEdit&&<button className="btn-secondary" onClick={()=>setEdit(!edit)}>{edit?'Cerrar edición':'Editar borrador y responsables'}</button>}
    {canEdit&&edit&&draft&&version&&<DraftEditor key={id+':'+version.version} draft={draft} version={version} path={endpoint+'/'+id}
      plan={plan} onSaved={changed}/>}
    {admin&&!edit&&(enabled||canEdit)&&<form className="space-y-3 border-t line pt-3" onSubmit={operate}>
      {canEdit&&plan.elegible&&proposal&&<fieldset><legend>Acciones para aprobación</legend>
        {proposal.acciones.filter(action=>version?.decisiones[action.clave]?.estado!=='rechazada'&&
          !version?.decisiones[action.clave]?.id_accion).map(action=><label className="block" key={action.clave}>
          <input name="accion" type="checkbox" value={action.clave} defaultChecked/> {action.clave} · {action.medida}
          {version?.decisiones[action.clave]?.id_responsable?' · Responsable revisado':draft?.sugerencias?.[action.clave]?
            ' · '+draft.sugerencias[action.clave]?.nombre_usuario:' · Pendiente de asignación'}</label>)}</fieldset>}
      {canEdit&&plan.elegible&&draft?.wip_disponible===false&&<p className="muted">WIP completo. El inicio queda sujeto a capacidad.</p>}
      <label className="block">Motivo<textarea className={input} required name="motivo" minLength={8} maxLength={2000}/></label>
      <div className="flex flex-wrap gap-2">{canEdit&&plan.elegible&&<button className="btn" value="aprobar" disabled={busy}>Aprobar selección</button>}
        {canEdit&&<button className="btn-secondary" value="rechazar" disabled={busy}>Rechazar borrador</button>}
        {enabled&&<button className="btn-secondary" value="otra" disabled={busy||items.some(item=>['pendiente','en_proceso'].includes(item.estado))}>Solicitar nueva propuesta</button>}</div>
    </form>}
  </section>
}
