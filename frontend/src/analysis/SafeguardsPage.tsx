import {useState, type FormEvent} from 'react'
import {Link, useSearchParams} from 'react-router-dom'
import {api, mutate} from '../auth/client'
import {useAuth} from '../auth/context'
import {useMonitorQuery, useRealtime} from '../monitoring/Realtime'
import {eventEvidencePath} from './iocEvidence'
import {BoardDrawer, SafeguardBoard, allowedMoves, columns, risks, states, type Page, type Stage, type Task, type Wip} from './SafeguardBoard'

const indicatorLabels:Record<string,string> = {total:'Total',...states,sin_asignar:'Sin asignar',vencidas:'Vencidas'}
const pageSize = 25
const initialBatches = {pendiente:1,en_desarrollo:1,realizada:1}
const emptyPage:Page = {items:[],total:0}
const initialPages = {pendiente:emptyPage,en_desarrollo:emptyPage,realizada:emptyPage}
type Analyst = {id_usuario:string;nombre_usuario:string}
type Origin = {id_analisis:string;posicion:number;fecha_fin:string;recomendacion:Record<string,unknown>;
  valoracion:{nivel:keyof typeof risks;fundamento:string;confianza:string;condiciones:string[];eventos:string[]}}
type Detail = Task & {origenes:Origin[];historial:{id_cambio:number;creado_en:string;operacion:string;actor:string;detalle:Record<string,string|null>}[]}
type Operation = 'asignacion'|'estado'|'avance'|'evidencia'|'reapertura'
const dateTime = (value:string|null) => value ? new Date(value).toLocaleString('es-EC',{timeZone:'America/Guayaquil'}) : '—'
const filterNames = {q:'Código o nombre',id_sesion:'Identificador de sesión',desde:'Desde',hasta:'Hasta'}
const historyLabels:Record<string,string>={asignacion:'Asignación',estado:'Estado',avance:'Avance',evidencia:'Evidencia',reapertura:'Reapertura',
  anterior:'Anterior',responsable:'ID del responsable',nombre_responsable:'Responsable',vence_en:'Vence',resultado:'Resultado',
  criterio_aplicado:'Validación aplicada',observacion:'Observación',justificacion:'Justificación'}
const display = (value:unknown) => typeof value==='string' ? value : Array.isArray(value) ? value.map(item=>
  typeof item==='string' ? item : typeof item?.codigo==='string' ? item.codigo : '').filter(Boolean).join(', ') : ''

export function SafeguardsPage() {
  const {session} = useAuth()
  const {connected} = useRealtime()
  const [params,setParams] = useSearchParams()
  const selected = params.get('id')
  const [filters,setFilters] = useState<Record<string,string>>({})
  const [pages,setPages] = useState(initialPages)
  const [batches,setBatches] = useState(initialBatches)
  const [indicators,setIndicators] = useState<Record<string,number>>({})
  const [wip,setWip] = useState<Wip|null>(null)
  const [configuring,setConfiguring] = useState(false)
  const [configError,setConfigError] = useState('')
  const [requestedMove,setRequestedMove] = useState<{id:string;stage:Stage}|null>(null)
  const [analysts,setAnalysts] = useState<Analyst[]>([])
  const [detail,setDetail] = useState<Detail|null>(null)
  const [revision,reload] = useState(0)
  const [listError,setListError] = useState('')
  const [detailError,setDetailError] = useState('')
  const [busy,setBusy] = useState(false)
  const [loading,setLoading] = useState(true)
  const admin = session?.usuario.rol === 'administrador'
  const canEdit = admin || !!session?.usuario.id_usuario && detail?.id_responsable === session.usuario.id_usuario

  useMonitorQuery(async signal => {
    const query = new URLSearchParams(Object.entries(filters).filter(([,value])=>value.trim()))
    setListError('')
    await new Promise<void>(resolve=>window.setTimeout(resolve,180))
    if(signal.aborted)return
    try {
      const [pendiente,en_desarrollo,realizada]=await Promise.all(columns.map(async stage=>{
        if (filters.estado && filters.estado!==stage) return emptyPage
        const pages = await Promise.all(Array.from({length:batches[stage]},(_,index)=>{
          const pageQuery = new URLSearchParams(query)
          pageQuery.set('estado',stage)
          pageQuery.set('limite',String(pageSize))
          pageQuery.set('offset',String(index*pageSize))
          return api<Page>('/salvaguardas?'+pageQuery,{signal})
        }))
        return {items:[...new Map(pages.flatMap(page=>page.items).map(item=>[item.id_salvaguarda,item])).values()],total:pages[0].total}
      }))
      if(!signal.aborted)setPages({pendiente,en_desarrollo,realizada})
    } catch(error) {
      if(!signal.aborted)setListError((error as Error).message)
      throw error
    } finally {
      if(!signal.aborted)setLoading(false)
    }
  },5000,[filters,batches,revision],['salvaguardas'])
  useMonitorQuery(async signal => {
    try {
      const {wip,...counts}=await api<Record<string,number>&{wip:Wip}>('/salvaguardas/indicadores',{signal})
      if(!signal.aborted){setWip(wip);setIndicators(counts)}
    } catch(error) {if(!signal.aborted)setListError((error as Error).message);throw error}
  },5000,[revision],['salvaguardas'])
  useMonitorQuery(async signal => {
    try {
      const people=await api<Analyst[]>('/salvaguardas/analistas',{signal})
      if(!signal.aborted)setAnalysts(people)
    } catch(error) {if(!signal.aborted)setListError((error as Error).message);throw error}
  },60000)
  useMonitorQuery(async signal => {
    if(!selected){setDetail(null);return}
    setDetail(current=>current?.id_salvaguarda===selected?current:null)
    try {
      const value=await api<Detail>('/salvaguardas/'+selected,{signal})
      if(!signal.aborted)setDetail(value)
    } catch(error) {if(!signal.aborted)setDetailError((error as Error).message);throw error}
  },5000,[selected,revision],['salvaguardas'])

  function filter(key:string,value:string){setLoading(true);setBatches(initialBatches);setFilters(old=>({...old,[key]:value}))}
  function select(id:string|null){
    if(busy)return
    setDetailError('')
    setRequestedMove(null)
    const next = new URLSearchParams(params)
    if(id)next.set('id',id)
    else next.delete('id')
    setParams(next,{preventScrollReset:true})
  }
  function move(task:Task,stage:Stage){select(task.id_salvaguarda);setRequestedMove({id:task.id_salvaguarda,stage})}
  async function saveConfig(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setBusy(true);setConfigError('')
    try{
      setWip(await mutate<Wip>('/salvaguardas/configuracion',{
        wip_activo:form.has('wip_activo'),limite_wip:Number(form.get('limite_wip'))},'PUT'))
      setConfiguring(false)
      if(!connected)reload(old=>old+1)
    }catch(error){setConfigError((error as Error).message)}
    finally{setBusy(false)}
  }
  async function submit(event:FormEvent<HTMLFormElement>, operation:Operation, fixed:Record<string,unknown>={}) {
    event.preventDefault()
    if(!detail || busy)return
    const form=event.currentTarget
    const data=Object.fromEntries(new FormData(form))
    if(data.vence_en==='')Object.assign(data,{vence_en:null})
    setBusy(true)
    setDetailError('')
    try{
      await mutate('/salvaguardas/'+detail.id_salvaguarda+'/'+operation,{...data,...fixed})
      form.reset()
      if(requestedMove?.id===detail.id_salvaguarda&&(operation==='estado'||operation==='reapertura'))select(null)
      if(!connected)reload(old=>old+1)
    }catch(error){setDetailError((error as Error).message);reload(old=>old+1)}
    finally{setBusy(false)}
  }
  const origin = detail?.origenes[0]
  const destination = requestedMove?.id===detail?.id_salvaguarda ? requestedMove?.stage : undefined
  const validDestination = !destination || !!detail && allowedMoves(detail,admin,session?.usuario.id_usuario).includes(destination)
  const transition = detail&&canEdit&&validDestination&&transitionForm(detail,destination)

  function transitionForm(task:Detail,destination?:Stage){
    if(task.estado==='pendiente')return <form onSubmit={e=>void submit(e,'estado',{estado:'en_desarrollo'})} className="space-y-2">
      {admin&&!analysts.some(a=>a.id_usuario===task.id_responsable)&&<label className="block">Asignar analista activo
        <select className="input block w-full" name="responsable" required defaultValue="">
          <option value="">Seleccionar</option>{analysts.map(a=><option key={a.id_usuario} value={a.id_usuario}>{a.nombre_usuario}</option>)}
        </select></label>}
      <button className="btn" disabled={busy}>Iniciar ejecución</button></form>
    if(task.estado==='en_desarrollo')return <form onSubmit={e=>void submit(e,'estado',{estado:'realizada'})} className="space-y-2">
      {Object.entries({resultado:'Resultado de implementación',evidencia:'Evidencia de cumplimiento',criterio_aplicado:'Criterio de validación aplicado',observacion:'Observaciones'}).map(([key,label])=>
        <label key={key} className="block">{label}<textarea className="input block w-full" name={key} required={key!=='observacion'} minLength={8} maxLength={key==='criterio_aplicado'?2000:4000}/></label>)}
      <button className="btn" disabled={busy}>Marcar realizada</button></form>
    if(admin)return <form onSubmit={e=>void submit(e,'reapertura',destination?{estado:destination}:{})} className="space-y-2">
      {!destination&&<label className="block">Destino de la reapertura<select className="input block w-full" name="estado" defaultValue="en_desarrollo">
        <option value="en_desarrollo">En desarrollo</option><option value="pendiente">Pendientes</option></select></label>}
      <label className="block">Justificación de reapertura<textarea className="input block w-full" name="observacion" required minLength={12} maxLength={4000}/></label>
      <button className="btn-secondary" disabled={busy}>Reabrir salvaguarda</button></form>
  }
  return <section className="space-y-5">
    <header className="flex flex-wrap items-start justify-between gap-3"><div><h1 className="text-2xl font-bold">Salvaguardas</h1>
      <p className="muted">Gestiona las medidas propuestas y conserva las evidencias de su implementación.</p></div>
      <div className="flex flex-wrap gap-2">
      <Link className="btn-secondary" to="/salvaguardas/propuestas">Revisión de propuestas</Link>
      {admin&&<button type="button" className="btn-secondary" disabled={!wip} onClick={()=>{setConfigError('');setConfiguring(true)}}>Configurar tablero</button>}</div></header>
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-6" aria-label="Indicadores">
      {Object.entries(indicatorLabels).map(([key,label])=><div className="panel p-3" key={key}><p className="muted text-xs">{label}</p>
        <p className="text-xl font-semibold">{indicators[key]??'—'}</p></div>)}
    </div>
    <div className="panel p-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Filtros">
      {Object.entries(filterNames).map(([key,label])=><label key={key} className="text-sm">{label}
        <input className="input w-full mt-1" type={key==='desde'||key==='hasta'?'date':'text'} value={filters[key]??''}
          onChange={event=>filter(key,event.target.value)}/></label>)}
      {Object.entries({estado:['Estado',states],riesgo:['Riesgo inicial',risks],prioridad:['Prioridad',
          {baja:'Baja',media:'Media',alta:'Alta',inmediata:'Inmediata'}]} as const).map(([key,[label,choices]])=>
        <label key={key} className="text-sm">{label}<select className="input w-full mt-1" value={filters[key]??''}
          onChange={event=>filter(key,event.target.value)}><option value="">Todos</option>
          {Object.entries(choices).map(([value,name])=><option key={value} value={value}>{name}</option>)}</select></label>)}
      <label className="text-sm">Analista<select className="input w-full mt-1" value={filters.responsable??''}
        onChange={event=>filter('responsable',event.target.value)}><option value="">Todos</option>
        {analysts.map(a=><option key={a.id_usuario} value={a.id_usuario}>{a.nombre_usuario}</option>)}</select></label>
      <label className="text-sm flex items-center gap-2"><input type="checkbox" checked={filters.mias==='true'}
        onChange={event=>filter('mias',event.target.checked?'true':'')}/> Mis salvaguardas</label>
      <label className="text-sm">Ordenar por<select className="input w-full mt-1" value={filters.orden??'creacion'} onChange={event=>filter('orden',event.target.value)}>
        <option value="creacion">Fecha de creación · más reciente</option><option value="prioridad">Prioridad · mayor primero</option>
        <option value="riesgo">Riesgo · mayor primero</option><option value="vencimiento">Fecha límite · más próxima</option>
      </select></label>
    </div>
    {listError&&<p role="alert" className="text-red-300">{listError}</p>}
    {loading&&<p className="muted" role="status">Cargando salvaguardas…</p>}
    <SafeguardBoard pages={pages} wip={wip} loading={loading} selected={selected} admin={admin}
      userId={session?.usuario.id_usuario} onSelect={select} onMove={move}
      onMore={stage=>setBatches(old=>({...old,[stage]:old[stage]+1}))}/>
    {configuring&&wip&&<BoardDrawer title="Configurar tablero" onClose={()=>{if(!busy)setConfiguring(false)}}>
      <p>En desarrollo: {wip.en_desarrollo} · {wip.wip_activo?`Espacios disponibles: ${wip.disponibles}`:'Sin límite WIP'}</p>
      {configError&&<p role="alert" className="text-red-300">{configError}</p>}
      <form onSubmit={e=>void saveConfig(e)} className="space-y-4">
        <label className="flex items-center gap-2"><input name="wip_activo" type="checkbox" defaultChecked={wip.wip_activo}/> Activar límite WIP</label>
        <label className="block">Máximo de salvaguardas en desarrollo
          <input className="input block w-full" name="limite_wip" type="number" min={1} max={10000} step={1} required defaultValue={wip.limite_wip}/></label>
        <button className="btn" disabled={busy}>Guardar configuración</button>
      </form>
    </BoardDrawer>}
    {selected&&<BoardDrawer key={selected} title={detail?.id_salvaguarda===selected ? detail.codigo+' · '+detail.nombre : 'Detalle de la salvaguarda'}
      onClose={()=>select(null)}>
      {detailError&&<p role="alert" className="text-red-300">{detailError}</p>}
      {!detail&&!detailError&&<p role="status" className="muted">Cargando detalle…</p>}
      {detail?.id_salvaguarda===selected&&origin&&<>
        {destination&&!validDestination&&<p role="alert">La salvaguarda cambió desde que se inició el movimiento. Vuelve a elegir el destino.</p>}
        {destination&&transition&&<section className="border line rounded-lg p-3 space-y-2">
          <h3 className="font-semibold">Confirmar movimiento a {states[destination]}</h3>{transition}
          <button type="button" className="btn-secondary" disabled={busy} onClick={()=>select(null)}>Cancelar movimiento</button>
        </section>}
        <p>{display(origin.recomendacion.justificacion)||display(origin.recomendacion.riesgo)}</p>
        <p>{display(origin.recomendacion.activo)} · {states[detail.estado]} · Prioridad {detail.prioridad??'sin definir'}</p>
        <Link className="accent underline" to={'/sesiones/'+detail.id_sesion}>Sesión de origen</Link>
        <div className="space-y-2">
          <h3 className="font-semibold">Evaluación e implementación</h3>
          {detail.origenes.map(item=><details key={item.id_analisis+':'+item.posicion} open={item===origin} className="border line rounded-lg p-3">
            <summary>{dateTime(item.fecha_fin)} · Propuesta {item.posicion} · {risks[item.valoracion.nivel]}</summary>
            <Link className="accent underline" to={'/sesiones/'+detail.id_sesion+'?analisis='+item.id_analisis}>Ver análisis de origen</Link>
            <dl className="space-y-2 text-sm mt-2">
              {Object.entries({Riesgo:item.recomendacion.riesgo,Fundamento:item.valoracion.fundamento,Confianza:item.valoracion.confianza,
                Condiciones:item.valoracion.condiciones,Objetivo:item.recomendacion.objetivo,Medidas:item.recomendacion.medidas,
                'Criterio de validación':item.recomendacion.validacion,MITRE:item.recomendacion.tecnicas_relacionadas}).map(([key,value])=>
                display(value)&&<div key={key}><dt className="font-semibold">{key}</dt><dd className="whitespace-pre-wrap">{display(value)}</dd></div>)}
            </dl>
            <p className="mt-2">Evidencias {item.valoracion.eventos.map(id=><Link key={id} className="accent underline mr-2" to={eventEvidencePath(detail.id_sesion,id)}>#{id}</Link>)}</p>
          </details>)}
        </div>
        <h3 className="font-semibold">Asignación y seguimiento</h3>
        <dl className="grid sm:grid-cols-3 gap-2 text-sm">
          {Object.entries({Responsable:detail.responsable??'Sin asignar',Creada:dateTime(detail.creado_en),Asignada:dateTime(detail.asignado_en),
            Iniciada:dateTime(detail.iniciado_en),Vence:detail.vence_en??'—',Finalizada:dateTime(detail.finalizado_en)}).map(([key,value])=>
            <div key={key}><dt className="muted">{key}</dt><dd>{value}</dd></div>)}
        </dl>
        {admin&&<form key={'assign'+detail.id_salvaguarda+detail.asignado_en} onSubmit={e=>void submit(e,'asignacion')} className="flex flex-wrap items-end gap-3">
          <label>Analista <select className="input block" name="responsable" required defaultValue={analysts.some(a=>a.id_usuario===detail.id_responsable)?detail.id_responsable! : ''}>
            <option value="">Seleccionar</option>{analysts.map(a=><option key={a.id_usuario} value={a.id_usuario}>{a.nombre_usuario}</option>)}</select></label>
          <label>Fecha límite <input className="input block" type="date" name="vence_en" defaultValue={detail.vence_en??''}/></label>
          <button className="btn" disabled={busy}>Guardar asignación</button>
        </form>}
        {!destination&&transition&&<div className="border line rounded-lg p-3">{transition}</div>}
        {canEdit&&detail.estado==='en_desarrollo'&&<div className="space-y-3">
          <form onSubmit={e=>void submit(e,'avance')} className="space-y-2"><label>Avance u observación<textarea className="input block w-full" name="observacion" required minLength={8} maxLength={4000}/></label>
            <button className="btn-secondary" disabled={busy}>Guardar avance</button></form>
          <form onSubmit={e=>void submit(e,'evidencia')} className="space-y-2"><label>Evidencia de implementación<textarea className="input block w-full" name="evidencia" required minLength={8} maxLength={4000}/></label>
            <button className="btn-secondary" disabled={busy}>Guardar evidencia</button></form>
        </div>}
        <h3 className="font-semibold">Historial</h3>
        {detail.historial.length?<ol className="space-y-2">
          {detail.historial.map(entry=><li key={entry.id_cambio} className="border line rounded-lg p-3 text-sm">
            <strong>{historyLabels[entry.operacion]??entry.operacion}</strong> · {entry.actor} · {dateTime(entry.creado_en)}
            <dl>{Object.entries(entry.detalle).filter(([,value])=>value).map(([key,value])=><div key={key} className="mt-1">
              <dt className="muted">{historyLabels[key]??key}</dt><dd className="whitespace-pre-wrap break-words">{value}</dd></div>)}</dl>
          </li>)}</ol>:<p className="muted">Aún no hay cambios de seguimiento.</p>}
      </>}
    </BoardDrawer>}
  </section>
}
