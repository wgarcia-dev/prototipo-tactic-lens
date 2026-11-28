import {useEffect,useState,type FormEvent} from 'react'
import {Link} from 'react-router-dom'
import {useDraggable,useDroppable} from '@dnd-kit/core'
import {BoardDrawer,KanbanInteraction} from '../../analysis/SafeguardBoard'
import {api,mutate} from '../../auth/client'
import {useAuth} from '../../auth/context'
import {useMonitorQuery} from '../../monitoring/Realtime'
import {actionStates,available,columns,dateTime,laneOf,lanes,laneStates,moves,operations,origins,pathFor,phases,priorities,
  type Action,type Config,type History,type Lane,type Operation,type Page,type Person} from './model'

const DOMAIN=['respuesta_incidentes'] as const
const emptyPage:Page<Action>={items:[],cursor:null}
const empty:Record<Lane,Page<Action>>={por_decidir:emptyPage,aprobadas:emptyPage,en_curso:emptyPage,
  por_verificar:emptyPage,finalizadas:emptyPage}
export const input='input w-full mt-1'
export const eventsFrom=(value:FormDataEntryValue|null)=>String(value??'').split(/[\s,]+/).filter(Boolean)

export function EvidenceLink({event,session}:{event:string;session:string}) {
  return <Link className="accent underline" to={'/sesiones/'+session+'?evento='+event}>Evento #{event}</Link>
}

export function Timeline({path,active=true}:{path:string;active?:boolean}) {
  const [current,setCurrent]=useState<Page<History>>({items:[],cursor:null})
  const [extra,setExtra]=useState<History[]>([])
  const [more,setMore]=useState<string|null>()
  const [busy,setBusy]=useState(false), [error,setError]=useState('')
  useMonitorQuery(async signal=>{
    if(!active)return
    try {
      const result=await api<Page<History>>(path,{signal})
      if(!signal.aborted){setCurrent(result);setError('')}
    } catch(failure) {if(!signal.aborted)setError((failure as Error).message);throw failure}
  },5000,[path,active],DOMAIN)
  const cursor=more===undefined?current.cursor:more
  async function loadMore(){
    if(!cursor||busy)return
    setBusy(true)
    try {
      const result=await api<Page<History>>(path+(path.includes('?')?'&':'?')+'cursor='+cursor)
      setExtra(items=>[...items,...result.items]);setMore(result.cursor);setError('')
    } catch(failure) {setError((failure as Error).message)}
    finally {setBusy(false)}
  }
  const entries=[...new Map([...current.items,...extra].map(item=>[item.id_cambio,item])).values()]
  return <div className="space-y-2">
    {error&&<p role="alert">{error}</p>}
    {entries.map(entry=><article key={entry.id_cambio} className="border-b line py-2 text-sm">
      <strong>{entry.operacion.replaceAll('_',' ')}</strong>
      <p className="muted">{dateTime(entry.creado_en)} · {entry.actor} · Evaluación {entry.revision_evaluacion}</p>
      <p className="break-words">{entry.motivo}</p>
      {['resultado','referencia','estado'].map(key=>typeof entry.detalle[key]==='string'
        ?<p key={key} className="break-words">{String(entry.detalle[key])}</p>:null)}
    </article>)}
    {cursor&&<button className="btn-secondary" disabled={busy} onClick={()=>void loadMore()}>Más actuaciones</button>}
  </div>
}

function Card({action,draggable,open}: {action:Action;draggable:boolean;open:()=>void}) {
  const drag=useDraggable({id:action.id_accion,data:{task:action,stage:laneOf(action.estado)},disabled:!draggable})
  return <article ref={drag.setNodeRef} className="kanban-card" data-dragging={drag.isDragging}>
    <div className="kanban-card-head">
      <button className="kanban-card-main text-left" aria-haspopup="dialog" onClick={open}>
        <strong className="accent block break-words">{action.medida}</strong>
        {action.codigo_accion&&<span className="kanban-card-meta">{action.codigo_incidente} · {action.codigo_accion}</span>}
        <span className="kanban-card-meta">{phases[action.fase]} · {actionStates[action.estado]}</span>
        {action.prioridad&&<span className="kanban-card-meta">{priorities[action.prioridad]} · {origins[action.origen_plan??'manual']}</span>}
        <span className="kanban-card-meta muted">{action.responsable??'Sin asignar'}{action.vence_en&&' · Vence '+action.vence_en}</span>
        {action.vencida&&<span className="badge warn">Vencida</span>}
      </button>
      {draggable&&<button className="kanban-grip" type="button" ref={drag.setActivatorNodeRef} {...drag.attributes}
        {...drag.listeners} aria-label={'Mover '+action.medida}>⠿</button>}
    </div>
    <Link to={pathFor(action.id_incidente)} className="accent underline text-xs break-words">{action.incidente_titulo}</Link>
  </article>
}

function Column({lane,page,allowed,active,busy,open,more}:{
  lane:Lane;page:Page<Action>;allowed:(action:Action)=>Lane[];active:Action|null;busy:boolean;
  open:(action:Action)=>void;more:()=>void;
}) {
  const {setNodeRef,isOver}=useDroppable({id:lane})
  const target=!!active&&allowed(active).includes(lane)
  return <section ref={setNodeRef} className="panel kanban-column" data-target={target} data-over={target&&isOver}>
    <header className="kanban-column-header"><h3 className="font-semibold">{lanes[lane]}</h3></header>
    <div className="kanban-scroll" role="region" tabIndex={0} aria-label={'Tarjetas de '+lanes[lane]}>
      {page.items.map(item=><Card key={item.id_accion} action={item} open={()=>open(item)} draggable={allowed(item).length>0}/>)}
      {!page.items.length&&<p className="muted text-sm">Sin tarjetas.</p>}
      {page.cursor&&<button className="btn-secondary w-full" onClick={more} disabled={busy}>Cargar más</button>}
    </div>
  </section>
}

function ActionEditor({initial,requested,people,onClose,onSaved}:{
  initial:Action;requested?:Operation;people:Person[];onClose:()=>void;onSaved:()=>void;
}) {
  const {session}=useAuth()
  const admin=session?.usuario.rol==='administrador'
  const [action,setAction]=useState<Action>(initial), [operation,setOperation]=useState<Operation|''>(requested??'')
  const [draft,setDraft]=useState({action:initial.revision_accion,evaluation:initial.revision_evaluacion_actual})
  const [busy,setBusy]=useState(false), [error,setError]=useState('')
  const path=pathFor(initial.id_incidente)+'/acciones/'+initial.id_accion
  useMonitorQuery(async signal=>{
    try {
      const result=await api<Action>(path,{signal})
      if(!signal.aborted)setAction(result)
    } catch(failure) {if(!signal.aborted)setError((failure as Error).message);throw failure}
  },5000,[path],DOMAIN)
  const choices=available(action,admin,session?.usuario.id_usuario)
  const stale=draft.action!==action.revision_accion||draft.evaluation!==action.revision_evaluacion_actual
  const operationAllowed=!!operation&&choices.includes(operation)
  const needsResult=['ejecutar','verificar','devolver'].includes(operation)||
    operation==='cancelar'&&['ejecutada','en_curso'].includes(action.estado)

  async function save(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(!operationAllowed||busy||stale)return
    const form=new FormData(event.currentTarget)
    setBusy(true);setError('')
    try {
      await mutate(path+'/transiciones',{operacion:operation,revision_evaluacion:draft.evaluation,
        revision_esperada:draft.action,motivo:form.get('motivo'),
        id_responsable:form.get('responsable')||null,vence_en:form.get('vence_en')||null,
        resultado:form.get('resultado')||null,referencia:form.get('referencia')||null,eventos:eventsFrom(form.get('eventos'))})
      onSaved();onClose()
    } catch(failure) {
      setError((failure as Error).message)
      api<Action>(path).then(setAction).catch(()=>{})
    } finally {setBusy(false)}
  }
  return <BoardDrawer title={action.medida} onClose={onClose}>
    <p className="text-sm muted">{phases[action.fase]} · {actionStates[action.estado]}</p>
    <p className="text-sm muted">Revisión de evaluación validada · {action.revision_validada}</p>
    <p>{action.objetivo}</p><p>{action.justificacion}</p>
    {action.procedencia?.descripcion&&<p>{action.procedencia.descripcion}</p>}
    {action.procedencia?.resultado_esperado&&<p><strong>Resultado esperado</strong> {action.procedencia.resultado_esperado}</p>}
    {!!action.procedencia?.mitre?.length&&<p>MITRE {action.procedencia.mitre.join(', ')}</p>}
    {!!action.procedencia?.dependencias?.length&&<p>Acciones predecesoras {action.procedencia.dependencias.length}</p>}
    <p><strong>Criterio de verificación</strong> {action.criterio_verificacion}</p>
    {action.desactualizada&&<p className="badge warn">Plan desactualizado</p>}
    {error&&<p role="alert">{error}</p>}
    {stale&&<p role="status">La acción cambió. <button className="btn-secondary"
      onClick={()=>{setDraft({action:action.revision_accion,evaluation:action.revision_evaluacion_actual});setOperation('');setError('')}}>
      Revisar nueva versión</button></p>}
    {choices.length>0&&<form onSubmit={save} className="space-y-3 border-t line pt-3">
      <label className="block">Operación<select className={input} value={operationAllowed?operation:''}
        onChange={event=>setOperation(event.target.value as Operation|'')} required>
        <option value="">Seleccione una operación</option>
        {choices.map(choice=><option value={choice} key={choice}>{operations[choice]}</option>)}
      </select></label>
      {operationAllowed&&<>
        {operation==='asignar'&&<>
          <label className="block">Responsable<select className={input} name="responsable" required defaultValue={action.id_responsable??''}>
            <option value="">Seleccione</option>{people.map(person=><option value={person.id_usuario} key={person.id_usuario}>{person.nombre_usuario}</option>)}</select></label>
          <label className="block">Vence<input type="date" name="vence_en" className={input} defaultValue={action.vence_en??''}/></label>
        </>}
        <label className="block">Motivo<textarea className={input} name="motivo" required minLength={8} maxLength={2000}/></label>
        {(needsResult||operation==='avanzar')&&<>
          <label className="block">Resultado<textarea className={input} name="resultado" required={needsResult} minLength={8} maxLength={2000}/></label>
          <label className="block">Referencia verificable<input className={input} name="referencia" minLength={8} maxLength={2000}/></label>
          <label className="block">IDs de eventos citados<input className={input} name="eventos" placeholder="Separados por coma"/></label>
        </>}
        <button className="btn" disabled={busy||stale}>{busy?'Guardando…':'Confirmar '+operations[operation as Operation].toLowerCase()}</button>
      </>}
    </form>}
    {!!action.evidencia?.length&&<section><h3 className="font-semibold">Evidencia</h3>
      <ul className="space-y-1 text-sm">{action.evidencia.map(item=><li key={item.id_evidencia}>
        {item.tipo} · {item.id_evento&&item.id_sesion?<EvidenceLink event={item.id_evento} session={item.id_sesion}/>:item.referencia}</li>)}</ul>
      {action.hay_mas_evidencia&&<p className="muted">Se muestran las últimas 100 referencias. Consulte el historial y el informe para el alcance restante.</p>}
    </section>}
    <h3 className="font-semibold">Historial de la acción</h3>
    <Timeline path={pathFor(initial.id_incidente)+'/historial?id_accion='+initial.id_accion}/>
  </BoardDrawer>
}

function HistoricalDrafts({enabled}:{enabled:boolean}){
  const [preview,setPreview]=useState<{id_incidente:string}[]>(),[queued,setQueued]=useState<number>(),
    [error,setError]=useState(''),[busy,setBusy]=useState(false)
  async function submit(vista_previa:boolean){
    setBusy(true);setError('')
    try {
      const result=await mutate<{items:{id_incidente:string}[];total:number}>('/respuestas-incidentes/automatizacion/retrospectiva',
        {limite:21,vista_previa})
      if(vista_previa){setPreview(result.items);setQueued(undefined)}
      else{setQueued(result.total);setPreview(undefined)}
    }catch(failure){setError((failure as Error).message)}finally{setBusy(false)}
  }
  return <details className="panel p-3"><summary>Borradores para candidatos históricos</summary>
    <div className="space-y-2 mt-2"><button className="btn-secondary" disabled={busy} onClick={()=>void submit(true)}>Previsualizar lote histórico</button>
      {preview&&<p>{preview.length} candidatos con evidencia verificable y sin borrador.</p>}
      {!!preview?.length&&<ul className="text-sm max-h-48 overflow-auto">{preview.map(item=><li key={item.id_incidente}>
        <Link className="accent underline" to={pathFor(item.id_incidente)}>INC-{item.id_incidente.slice(0,8)}</Link></li>)}</ul>}
      {!!preview?.length&&<button className="btn" disabled={!enabled||busy} onClick={()=>void submit(false)}>Encolar borradores en DeepSeek</button>}
      {!enabled&&<p className="muted">La generación con DeepSeek está deshabilitada.</p>}
      {queued!==undefined&&<p role="status">{queued} borradores encolados.</p>}
      {error&&<p role="alert">{error}</p>}</div>
  </details>
}

export function ResponseBoard({incident,actionId,refresh=0,onChanged}:{incident?:string;actionId?:string|null;refresh?:number;onChanged?:()=>void}) {
  const {session}=useAuth()
  const admin=session?.usuario.rol==='administrador', actor=session?.usuario.id_usuario
  const [pages,setPages]=useState(empty)
  const [depths,setDepths]=useState<Partial<Record<Lane,number>>>({})
  const [people,setPeople]=useState<Person[]>([]), [config,setConfig]=useState<Config>()
  const [error,setError]=useState(''), [loading,setLoading]=useState(true), [saving,setSaving]=useState(false)
  const [refreshLocal,reload]=useState(0)
  const [filter,setFilter]=useState({incident:incident??'',person:'',state:'',prioridad:'',origen:'',vencimiento:'',mias:false})
  const [selected,setSelected]=useState<{action:Action;operation?:Operation}>()
  useEffect(()=>{
    if(!incident||!actionId)return
    const controller=new AbortController()
    api<Action>(pathFor(incident)+'/acciones/'+encodeURIComponent(actionId),{signal:controller.signal})
      .then(action=>{if(!controller.signal.aborted)setSelected({action})})
      .catch(failure=>{if(!controller.signal.aborted)setError(failure.message)})
    return ()=>controller.abort()
  },[incident,actionId])
  const boardPath='/respuestas-incidentes/acciones'
  function query(lane:Lane,cursor?:string) {
    const params=new URLSearchParams({limite:'12'})
    for(const state of laneStates[lane])if(!filter.state||filter.state===state)params.append('estado',state)
    if(filter.incident)params.set('id_incidente',filter.incident)
    if(filter.person)params.set('id_responsable',filter.person)
    if(filter.mias)params.set('mias','true')
    for(const key of ['prioridad','origen','vencimiento'] as const)if(filter[key])params.set(key,filter[key])
    if(cursor)params.set('cursor',cursor)
    return boardPath+'?'+params
  }
  useMonitorQuery(async signal=>{
    try {
      const results=await Promise.all(columns.map(async lane=>{
        if(filter.state&&!laneStates[lane].includes(filter.state as Action['estado']))return [lane,emptyPage] as const
        const items:Action[]=[]
        let cursor:string|null=null
        for(let index=0;index<(depths[lane]??1);index++){
          const result:Page<Action>=await api(query(lane,cursor??undefined),{signal})
          items.push(...result.items)
          cursor=result.cursor
          if(!cursor)break
        }
        return [lane,{items,cursor}] as const
      }))
      if(!signal.aborted){setPages(Object.fromEntries(results) as typeof pages);setError('')}
    } catch(failure) {if(!signal.aborted)setError((failure as Error).message);throw failure}
    finally {if(!signal.aborted)setLoading(false)}
  },5000,[filter,depths,refresh,refreshLocal],DOMAIN)
  useMonitorQuery(async signal=>{
    const values=await Promise.all([api<Person[]>('/respuestas-incidentes/responsables',{signal}),
      api<Config>('/respuestas-incidentes/configuracion',{signal})])
    if(!signal.aborted){setPeople(values[0]);setConfig(values[1])}
  },5000,[],DOMAIN)
  function change(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    const form=new FormData(event.currentTarget)
    setPages(empty);setDepths({});setLoading(true)
    setFilter({...filter,incident:incident??String(form.get('incidente')??'').trim(),person:String(form.get('responsable')??''),
      state:String(form.get('estado')??''),prioridad:String(form.get('prioridad')??''),origen:String(form.get('origen')??''),
      vencimiento:String(form.get('vencimiento')??'')})
  }
  const allowed=(action:Action)=>Object.keys(moves(action,admin,actor)) as Lane[]
  async function saveConfig(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(!config)return
    const form=new FormData(event.currentTarget)
    setSaving(true)
    try {
      const saved=await mutate<Config>('/respuestas-incidentes/configuracion',{revision_esperada:config.revision_config,
        wip_activo:form.has('activo'),limite_wip:Number(form.get('limite'))},'PUT')
      setConfig({...config,...saved})
      setError('')
    } catch(failure) {setError((failure as Error).message)}
    finally {setSaving(false)}
  }
  return <section className="space-y-4">
    <div className="flex justify-between flex-wrap gap-3"><h2 className="font-semibold text-xl">{filter.mias?'Mis acciones':'Tablero de respuesta'}</h2>
      <button className="btn-secondary" aria-pressed={filter.mias} onClick={()=>{
        setLoading(true);setDepths({});setFilter({...filter,mias:!filter.mias})
      }}>{filter.mias?'Todas las acciones':'Mis acciones'}</button>
      {config&&<span className="badge">{config.wip_activo?'Límite WIP '+config.limite_wip:'Sin límite WIP'}</span>}</div>
    <form onSubmit={change} className="panel p-3 flex flex-wrap items-end gap-3">
      {!incident&&<label>Incidente<input className={input} name="incidente" placeholder="Identificador UUID"/></label>}
      <label>Responsable<select className={input} name="responsable" disabled={filter.mias}><option value="">Todos</option>
        {people.map(person=><option value={person.id_usuario} key={person.id_usuario}>{person.nombre_usuario}</option>)}</select></label>
      <label>Estado<select className={input} name="estado"><option value="">Todos</option>
        {Object.entries(actionStates).map(([key,label])=><option key={key} value={key}>{label}</option>)}</select></label>
      <label>Prioridad<select className={input} name="prioridad"><option value="">Todas</option>
        {Object.entries(priorities).map(([key,label])=><option key={key} value={key}>{label}</option>)}</select></label>
      <label>Procedencia<select className={input} name="origen"><option value="">Todas</option>
        {Object.entries(origins).map(([key,label])=><option key={key} value={key}>{label}</option>)}</select></label>
      <label>Vencimiento<select className={input} name="vencimiento"><option value="">Todos</option>
        <option value="vencida">Vencida</option><option value="proxima">Próxima</option><option value="sin_fecha">Sin fecha</option></select></label>
      <button className="btn-secondary" disabled={saving}>Aplicar filtros</button>
    </form>
    {admin&&people.some(person=>person.carga!==undefined)&&<details className="panel p-3"><summary>Carga por responsable</summary>
      <ul className="mt-2">{people.map(person=><li key={person.id_usuario}>{person.nombre_usuario} · {person.carga} abiertas · {person.en_curso} en curso</li>)}</ul>
    </details>}
    {admin&&!incident&&config?.automatizacion_disponible&&<HistoricalDrafts enabled={!!config.generacion_habilitada}/>}
    {admin&&config&&!incident&&<details className="panel p-3"><summary>Configurar límite WIP</summary>
      <form key={config.revision_config} onSubmit={saveConfig} className="flex flex-wrap items-end gap-3 mt-2">
        <label><input type="checkbox" name="activo" defaultChecked={config.wip_activo}/> Límite activo</label>
        <label>Límite<input className={input} type="number" name="limite" min={1} max={10000} defaultValue={config.limite_wip} required/></label>
        <button className="btn-secondary" disabled={saving}>Guardar capacidad</button>
      </form></details>}
    {error&&<div role="alert">{error} <button className="btn-secondary" onClick={()=>reload(value=>value+1)}>Reintentar</button></div>}
    {loading&&<p role="status" className="muted">Cargando acciones…</p>}
    <KanbanInteraction columns={columns} labels={lanes} allowed={allowed} preview={(action:Action)=>action.medida}
      onMove={(action,lane)=>setSelected({action,operation:moves(action,admin,actor)[lane]})}>
      {(active,board)=><div ref={board} className="safeguard-kanban response-kanban" aria-label="Kanban de respuesta">
        {columns.map(lane=><Column key={lane} lane={lane} active={active} allowed={allowed} busy={loading}
          page={pages[lane]} open={action=>setSelected({action})}
          more={()=>{setLoading(true);setDepths(values=>({...values,[lane]:(values[lane]??1)+1}))}}/>)}
      </div>}
    </KanbanInteraction>
    {selected&&<ActionEditor key={selected.action.id_accion} initial={selected.action} requested={selected.operation} people={people}
      onClose={()=>setSelected(undefined)} onSaved={()=>{if(onChanged)onChanged();else reload(value=>value+1)}}/>}
  </section>
}
