import {useEffect,useState,type FormEvent,type ReactNode} from 'react'
import {Link,useParams,useSearchParams} from 'react-router-dom'
import {api,mutate} from '../auth/client'
import {useAuth} from '../auth/context'
import {useMonitorQuery} from '../monitoring/Realtime'
import {dateTime,decisions,evidencePath,modes,priorities,responseEligible,severities,
  type Decision,type Evaluation,type Incident,type Page} from './evaluationModel'

const domain=['incidentes'] as const
const input='input w-full mt-1'
const picker=(values:Record<string,string>)=>Object.entries(values).map(([value,label])=><option key={value} value={value}>{label}</option>)
const historicalLabels:Record<string,string>={recuperable_directamente:'Evidencia histórica verificada',
  recuperable_con_revision:'Citas y recibos verificados',requiere_reevaluacion:'Pendiente de reevaluación'}

function Save({children,onSave,label}:{children:ReactNode;onSave:(data:FormData)=>Promise<void>;label:string}) {
  const [busy,setBusy]=useState(false),[error,setError]=useState('')
  async function submit(event:FormEvent<HTMLFormElement>){
    event.preventDefault()
    if(busy)return
    setBusy(true);setError('')
    try{await onSave(new FormData(event.currentTarget))}
    catch(failure){setError((failure as Error).message)}
    finally{setBusy(false)}
  }
  return <form onSubmit={submit} className="space-y-3">{children}
    {error&&<p role="alert">{error}</p>}<button className="btn" disabled={busy}>{busy?'Guardando…':label}</button>
  </form>
}

type HistoricalPreview={revision_vista_previa:string;
  resumen:{analisis_revisados:number;sesiones_revisadas:number;recuperable_directamente:number;recuperable_con_revision:number;
    requiere_reevaluacion:number;sesion_ya_registrada:number;sin_indicios_suficientes:number;salvaguardas_con_citas_compatibles:number};
  seleccion:{id_analisis:string;id_sesion:string;actividad_desde:string;estado:string;modalidad:keyof typeof modes;
    salvaguardas:{citas_compatibles:boolean}[]}[];
  sesiones:{id_analisis:string;id_sesion:string;estado:string}[]}

function HistoricalRecovery({onSaved}:{onSaved:()=>void}) {
  const [preview,setPreview]=useState<HistoricalPreview>()
  const [registered,setRegistered]=useState<string[]>([])
  const [busy,setBusy]=useState(false),[error,setError]=useState('')
  async function load() {
    setBusy(true);setError('');setPreview(undefined);setRegistered([])
    try {setPreview(await api<HistoricalPreview>('/incidentes/retrospectiva'))}
    catch(failure){setError((failure as Error).message)}
    finally{setBusy(false)}
  }
  return <details className="panel p-4">
    <summary className="font-semibold cursor-pointer">Recuperar actividad histórica</summary>
    <div className="mt-3 space-y-3">
      <button type="button" className="btn-secondary" disabled={busy} onClick={()=>void load()}>{busy?'Preparando…':'Generar vista previa'}</button>
      {error&&<p role="alert">{error}</p>}
      {!!registered.length&&<div role="status"><p>Se registraron {registered.length} candidatos.</p>{registered.map(id=>
        <Link className="accent underline block" key={id} to={'/incidentes/'+id}>{id}</Link>)}</div>}
      {preview&&<>
        <p>{preview.resumen.analisis_revisados} análisis en {preview.resumen.sesiones_revisadas} sesiones.</p>
        <ul className="list-disc pl-5 text-sm">
          <li>{preview.resumen.recuperable_directamente} con evidencia histórica verificada</li>
          <li>{preview.resumen.recuperable_con_revision} con citas y recibos verificados que requieren contrastar el análisis</li>
          <li>{preview.resumen.requiere_reevaluacion} pendientes de reevaluación</li>
          <li>{preview.resumen.sesion_ya_registrada} ya registradas y {preview.resumen.sin_indicios_suficientes} sin indicios suficientes</li>
          <li>{preview.resumen.salvaguardas_con_citas_compatibles} salvaguardas con citas compatibles para revisión posterior</li>
        </ul>
        {!!preview.seleccion.length&&<div className="overflow-auto max-h-64"><table className="w-full text-sm text-left" aria-label="Candidatos históricos">
          <thead><tr>{['Análisis','Actividad original','Modalidad','Evidencia'].map(col=><th className="p-2" scope="col" key={col}>{col}</th>)}</tr></thead>
          <tbody>{preview.seleccion.map(row=><tr className="border-t line" key={row.id_sesion}>
            <td className="p-2"><Link className="accent underline" to={'/sesiones/'+row.id_sesion+'?analisis='+row.id_analisis}>{row.id_analisis}</Link></td>
            <td className="p-2 whitespace-nowrap">{dateTime(row.actividad_desde)}</td><td className="p-2">{modes[row.modalidad]}</td>
            <td className="p-2">{historicalLabels[row.estado]}</td></tr>)}</tbody>
        </table></div>}
        {preview.resumen.requiere_reevaluacion>0&&<details><summary>Sesiones pendientes de reevaluación</summary>
          {preview.sesiones.filter(row=>row.estado==='requiere_reevaluacion').map(row=><Link key={row.id_sesion}
            className="accent underline block" to={'/sesiones/'+row.id_sesion+'?analisis='+row.id_analisis}>{row.id_analisis}</Link>)}</details>}
        {!!preview.seleccion.length&&<Save key={preview.revision_vista_previa} label="Registrar candidatos de esta vista previa" onSave={async data=>{
          const result=await mutate<{incidentes:string[]}>('/incidentes/retrospectiva',{
            revision_vista_previa:preview.revision_vista_previa,motivo:data.get('motivo')})
          setRegistered(result.incidentes);setPreview(undefined);onSaved()
        }}><p className="muted text-sm">Los candidatos requieren revisión humana para habilitar un plan de respuesta.</p>
          <label className="block">Motivo de la recuperación<textarea className={input} name="motivo" minLength={12} maxLength={2000} required/></label>
        </Save>}
      </>}
    </div>
  </details>
}

export function IncidentListPage() {
  const {session}=useAuth()
  const [params,setParams]=useSearchParams()
  const [page,setPage]=useState<Page>({items:[],cursor:null}),[extra,setExtra]=useState<Page>()
  const [summary,setSummary]=useState<{total:number;distribucion:{decision:Decision;total:number}[];retrospectiva_disponible?:boolean}>()
  const [newCase,setNewCase]=useState(''),[error,setError]=useState(''),[loading,setLoading]=useState(true)
  const [busy,setBusy]=useState(false),[retry,reload]=useState(0)
  const key=params.toString()
  const filter=new URLSearchParams(key)
  filter.delete('analisis')
  const path='/incidentes?'+filter.toString()
  useMonitorQuery(async signal=>{
    try {
      const result=await api<Page>(path,{signal})
      if(!signal.aborted){setPage(result);setExtra(undefined);setError('')}
    } catch(failure){if(!signal.aborted)setError((failure as Error).message);throw failure}
    finally{if(!signal.aborted)setLoading(false)}
  },5000,[path,retry],domain)
  useMonitorQuery(async signal=>{
    const result=await api<NonNullable<typeof summary>>('/incidentes/resumen',{signal})
    if(!signal.aborted)setSummary(result)
  },5000,[retry],domain)
  const cursor=extra?extra.cursor:page.cursor
  async function more(){
    if(!cursor||busy)return
    setBusy(true)
    try {
      const next=await api<Page>(path+'&cursor='+encodeURIComponent(cursor))
      setExtra(previous=>({items:[...(previous?.items??[]),...next.items],cursor:next.cursor}))
    } catch(failure){setError((failure as Error).message)}
    finally{setBusy(false)}
  }
  function submit(event:FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const values=new FormData(event.currentTarget), next=new URLSearchParams()
    for(const [name,value] of values)if(String(value).trim())next.set(name,String(value).trim())
    if(params.has('id_sesion'))next.set('id_sesion',params.get('id_sesion')!)
    if(next.toString()===key){reload(n=>n+1);return}
    setLoading(true);setPage({items:[],cursor:null});setExtra(undefined);setParams(next)
  }
  const items=[...new Map([...page.items,...(extra?.items??[])].map(item=>[item.id_incidente,item])).values()]
  return <div className="space-y-5">
    <header className="border-b line pb-4"><h1 className="text-2xl font-bold">Incidentes</h1>
      <p className="muted">Evaluaciones vigentes en los sensores autorizados.</p></header>
    {summary&&<div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
      <div className="panel p-3"><p className="muted text-sm">Total</p><strong className="text-xl">{summary.total}</strong></div>
      {Object.entries(decisions).map(([value,label])=><div className="panel p-3" key={value}>
        <p className="muted text-sm">{label}</p><strong className="text-xl">{summary.distribucion.filter(row=>row.decision===value)
          .reduce((subtotal,row)=>subtotal+row.total,0)}</strong></div>)}
    </div>}
    {params.has('id_sesion')&&<p>Filtrado por sesión. <Link className="accent underline" to="/incidentes">Ver todos</Link></p>}
    {session?.usuario.rol==='administrador'&&<details className="panel p-4" open={params.has('analisis')||undefined}>
      <summary className="font-semibold cursor-pointer">Registrar desde un análisis guardado</summary>
      <div className="mt-3"><Save label="Registrar incidente" onSave={async form=>{
        const result=await mutate<Evaluation>('/incidentes',{id_analisis:form.get('id_analisis'),motivo:form.get('motivo')})
        setNewCase(result.id_incidente);reload(n=>n+1)
      }}>
        <label className="block">Identificador del análisis<input className={input} name="id_analisis" required defaultValue={params.get('analisis')??''}/></label>
        <label className="block">Motivo<textarea className={input} name="motivo" minLength={12} maxLength={2000} required/></label>
      </Save>{newCase&&<Link className="accent underline" to={'/incidentes/'+newCase}>Abrir incidente registrado</Link>}</div>
    </details>}
    {session?.usuario.rol==='administrador'&&summary?.retrospectiva_disponible&&<HistoricalRecovery onSaved={()=>reload(n=>n+1)}/>}
    <form key={key} onSubmit={submit} className="panel p-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <label>Buscar<input className={input} name="q" maxLength={100} defaultValue={params.get('q')??''} placeholder="Título, ID o sesión"/></label>
      <label>Decisión<select className={input} name="decision" defaultValue={params.get('decision')??''}><option value="">Todas</option>{picker(decisions)}</select></label>
      <label>Severidad<select className={input} name="severidad" defaultValue={params.get('severidad')??''}><option value="">Todas</option>
        {severities.map(value=><option key={value}>{value}</option>)}</select></label>
      <label>Prioridad<select className={input} name="prioridad" defaultValue={params.get('prioridad')??''}><option value="">Todas</option>{picker(priorities)}</select></label>
      <label>Modalidad<select className={input} name="modalidad" defaultValue={params.get('modalidad')??''}><option value="">Todas</option>{picker(modes)}</select></label>
      <label>Orden<select className={input} name="orden" defaultValue={params.get('orden')??'recientes'}>
        {picker({recientes:'Más recientes',antiguos:'Más antiguos',severidad:'Severidad'})}</select></label>
      <button className="btn-secondary self-end">Aplicar filtros</button>
    </form>
    {error&&<p role="alert">{error} <button className="btn-secondary" onClick={()=>reload(n=>n+1)}>Reintentar</button></p>}
    {loading?<p role="status">Cargando incidentes…</p>:!items.length&&!error&&<p className="muted">Sin incidentes para estos filtros.</p>}
    {!!items.length&&<div className="panel overflow-auto"><table className="w-full text-sm text-left" aria-label="Incidentes">
      <thead><tr>{['Incidente','Decisión','Severidad','Prioridad','Modalidad','Actualización'].map(col=><th className="p-3" scope="col" key={col}>{col}</th>)}</tr></thead>
      <tbody>{items.map(item=><tr className="border-t line" key={item.id_incidente}>
        <td className="p-3"><Link className="accent underline" to={'/incidentes/'+item.id_incidente}>{item.titulo}</Link></td>
        <td className="p-3">{decisions[item.decision]}</td><td className="p-3">{item.severidad??'Por determinar'}</td>
        <td className="p-3">{priorities[item.prioridad]}</td><td className="p-3">{item.modalidades.map(mode=>modes[mode]).join(', ')}</td>
        <td className="p-3">{dateTime(item.actualizado_en)}</td>
      </tr>)}</tbody>
    </table></div>}
    {cursor&&<button className="btn-secondary" disabled={busy} onClick={()=>void more()}>Cargar más</button>}
  </div>
}

function ReviewForm({incident,onSaved}:{incident:Incident;onSaved:()=>void}) {
  const [draft]=useState(incident)
  const stale=draft.revision_actual!==incident.revision_actual
  if(stale)return <p role="status">La evaluación cambió. Cierre y vuelva a abrir la revisión para consultar los cambios.</p>
  return <Save label="Confirmar revisión" onSave={async form=>{
    await mutate('/incidentes/'+incident.id_incidente+'/revisiones',{
      revision_esperada:draft.revision_actual,decision:form.get('decision'),severidad:form.get('severidad')||null,
      prioridad:form.get('prioridad'),motivo:form.get('motivo'),resumen:form.get('resumen'),
      corroboracion:form.get('corroboracion')||null,impacto_confirmado:form.get('impacto_confirmado')||null,
      recursos_confirmados:String(form.get('recursos')??'').split('\n').map(value=>value.trim()).filter(Boolean),
      eventos:form.getAll('eventos'),
    })
    onSaved()
  }}>
    <div className="grid sm:grid-cols-3 gap-3">
      <label>Decisión<select name="decision" className={input} defaultValue={draft.decision}>{picker(decisions)}</select></label>
      <label>Severidad<select name="severidad" className={input} defaultValue={draft.severidad??''}><option value="">Por determinar</option>
        {severities.map(value=><option key={value}>{value}</option>)}</select></label>
      <label>Prioridad<select name="prioridad" className={input} defaultValue={draft.prioridad}>{picker(priorities)}</select></label>
    </div>
    {(['resumen','motivo','impacto_confirmado','corroboracion','recursos'] as const).map(key=><label key={key} className="block">
      {{resumen:'Resumen de evaluación',motivo:'Justificación de la decisión',impacto_confirmado:'Impacto corroborado',
        corroboracion:'Referencia independiente',recursos:'Recursos confirmados, uno por línea'}[key]}
      <textarea className={input} name={key} required={key==='resumen'||key==='motivo'} minLength={key==='recursos'?undefined:12}
        maxLength={2000} defaultValue={key==='resumen'?draft.resumen:key==='recursos'?draft.alcance.recursos_confirmados.join('\n'):
          key==='impacto_confirmado'||key==='corroboracion'?draft.detalle[key]??'':''}/></label>)}
    <fieldset className="max-h-52 overflow-auto border line rounded p-3"><legend>Citas de respaldo</legend>
      {draft.evidencias.map(c=><label className="block text-sm" key={c.id_evento}>
        <input type="checkbox" name="eventos" value={c.id_evento} defaultChecked/> Evento #{c.id_evento} · {c.grado.replaceAll('_',' ')}
      </label>)}
    </fieldset>
  </Save>
}

export function IncidentDetailPage() {
  const {id}=useParams()
  return id?<IncidentDetail key={id} id={id}/>:null
}

function IncidentDetail({id}:{id:string}) {
  const {session}=useAuth()
  const [current,setCurrent]=useState<Incident>(),[historical,setHistorical]=useState<Evaluation>()
  const [number,setNumber]=useState<number>(),[error,setError]=useState(''),[historyError,setHistoryError]=useState('')
  const [revision,reload]=useState(0),[editing,setEditing]=useState(false)
  const path='/incidentes/'+id
  useMonitorQuery(async signal=>{
    try{const data=await api<Incident>(path,{signal});if(!signal.aborted){setCurrent(data);setError('')}}
    catch(failure){if(!signal.aborted)setError((failure as Error).message);throw failure}
  },5000,[path,revision],domain)
  useEffect(()=>{
    if(number===undefined)return
    const request=new AbortController()
    setHistorical(undefined);setHistoryError('')
    api<Evaluation>(path+'/evaluaciones/'+number,{signal:request.signal}).then(view=>{if(!request.signal.aborted)setHistorical(view)})
      .catch(failure=>{if(!request.signal.aborted)setHistoryError(failure.message)})
    return ()=>request.abort()
  },[path,number])
  if(!current)return error?<p role="alert">{error} <button className="btn-secondary" onClick={()=>reload(n=>n+1)}>Reintentar</button></p>:
    <p role="status">Cargando incidente…</p>
  const view=number===undefined?current:historical
  return <div className="space-y-5">
    <header className="border-b line pb-4 space-y-2"><Link className="accent underline" to="/incidentes">Lista de incidentes</Link>
      <h1 className="text-2xl font-bold">{current.titulo}</h1>
      <p className="muted">{decisions[current.decision]} · {current.severidad??'Por determinar'} · {priorities[current.prioridad]}</p>
      {responseEligible(current)&&<Link className="btn inline-flex" to={path+'/respuesta'}>Abrir plan de respuesta</Link>}
    </header>
    {error&&<p role="alert">{error}</p>}{historyError&&<p role="alert">{historyError}</p>}
    <section className="panel p-4 space-y-3">
      <div className="flex flex-wrap justify-between gap-3"><h2 className="font-semibold">Evaluación y revisiones</h2>
        <label>Versión<select className={input} value={number??''} onChange={event=>{
          setNumber(event.target.value?Number(event.target.value):undefined);setEditing(false)
        }}><option value="">Vigente · {current.revision_actual}</option>
          {current.historial.filter(row=>row.revision_evaluacion!==current.revision_actual).map(row=>
            <option value={row.revision_evaluacion} key={row.revision_evaluacion}>Revisión {row.revision_evaluacion} · {decisions[row.decision]}</option>)}
        </select></label></div>
      {view?<><p className="badge">{number===undefined?'Evaluación vigente':'Evaluación histórica'}</p>
        <p>{view.resumen}</p><p className="muted">{dateTime(view.evaluado_en)} · {view.clasificacion.replaceAll('_',' ')}</p>
        <p className="text-sm">{decisions[view.decision]} · {view.severidad??'Por determinar'} · {priorities[view.prioridad]}</p>
        {view.detalle.motivo&&<p>{view.detalle.motivo}</p>}
        {!!view.detalle.retrospectiva?.length&&<div className="text-sm space-y-1">
          {view.registrado_en&&<p>Registro del incidente · {dateTime(view.registrado_en)}</p>}
          {view.detalle.retrospectiva.map(entry=><div key={entry.id_analisis} className="border-t line pt-1">
            <p>Actividad original · {dateTime(entry.actividad_desde)} – {dateTime(entry.actividad_hasta)}</p>
            <p className="muted">{entry.base_evidencia==='recibos_y_citas'?
              'Citas y recibos verificados. La huella completa del análisis original sigue sin verificación.':
              'Evidencia histórica verificada mediante la huella guardada.'}</p>
          </div>)}
        </div>}
        {view.detalle.impacto_confirmado?<p>Impacto corroborado · {view.detalle.impacto_confirmado}</p>:
          <p className="muted">Impacto organizacional sin corroboración independiente.</p>}
        {view.detalle.corroboracion&&<p className="break-words">Referencia · {view.detalle.corroboracion}</p>}
        {!view.evidencia_verificable&&<p role="status">El contenido actual difiere de la evidencia de esta revisión.</p>}
        <p className="muted text-xs break-all">Huella SHA-256 · {view.evidencia_sha256}</p>
        <details><summary>Evaluaciones técnicas de origen</summary>{view.detalle.analisis?.map(item=><details key={item.id_analisis} className="mt-2">
          <summary>{modes[item.modalidad_al_analizar]} · {item.severidad??'Por determinar'}</summary>
          <pre className="whitespace-pre-wrap break-words text-xs">{JSON.stringify(item.impacto_tecnico,null,2)}</pre>
        </details>)}</details></>:<p role="status">Cargando revisión…</p>}
      {number===undefined&&session?.usuario.rol==='administrador'&&current.evidencia_verificable&&
        <button className="btn-secondary" onClick={()=>setEditing(!editing)}>{editing?'Cerrar revisión':'Revisar evaluación'}</button>}
      {editing&&<ReviewForm incident={current} onSaved={()=>{setEditing(false);reload(n=>n+1)}}/>}
    </section>
    <section className="panel p-4 space-y-2"><h2 className="font-semibold">Sesiones y correlación</h2>
      {current.sesiones.map(row=><div key={row.id_sesion}>
        <Link className="accent underline" to={'/sesiones/'+row.id_sesion}>{row.cowrie_session_id}</Link>
        <span className="muted"> · {dateTime(row.fecha_inicio)}</span>
        {current.correlaciones.filter(c=>c.id_sesion===row.id_sesion&&c.sha256).map(c=><p className="text-sm break-words" key={c.metodo}>
          Artefacto SHA-256 {c.sha256} · eventos {c.eventos?.join(', ')}. {c.limitacion}</p>)}
      </div>)}
      {current.analisis.map(item=><Link key={item.id_analisis} className="accent underline block text-sm"
        to={'/sesiones/'+item.id_sesion+'?analisis='+item.id_analisis}>Análisis de origen · revisión {item.revision_ingreso}</Link>)}
    </section>
    <section className="panel p-4 space-y-3"><h2 className="font-semibold">Evidencias {number!==undefined&&'de la revisión '+number}</h2>
      <p className="muted text-sm">{view?.evidencias.length??0} citas. Los resultados del señuelo requieren corroboración para afirmar efectos externos.</p>
      {(number===undefined?current.eventos:view?.evidencias??[]).map(c=><article key={c.id_evento} className="border-t line pt-2 text-sm">
        <Link className="accent underline" to={evidencePath(c.id_sesion,c.id_evento)}>Evento #{c.id_evento}</Link>
        <span> · {modes[c.procedencia.modalidad]} · {c.grado.replaceAll('_',' ')}</span>
        {'comando' in c&&typeof c.comando==='string'&&<code className="block break-all mt-1">{c.comando}</code>}
      </article>)}
      {number===undefined&&<>
        <details><summary>Observables vinculados ({current.iocs.length})</summary>{current.iocs.map(row=><p className="text-sm break-all" key={row.id_observacion}>
          {row.tipo} · {row.valor} · {row.estado_revision} · <Link className="accent underline" to={evidencePath(row.id_sesion,row.id_evento)}>#{row.id_evento}</Link></p>)}</details>
        <details><summary>MITRE ATT&amp;CK ({current.mitre.length})</summary>{current.mitre.map((row,index)=><p className="text-sm" key={index}>
          {row.codigo_tecnica} · {row.tecnica} · {row.estado_revision} · <Link className="accent underline" to={evidencePath(row.id_sesion,row.id_evento)}>#{row.id_evento}</Link></p>)}</details>
        {current.limites.hay_mas&&<p className="muted text-sm">Historial, análisis, IoCs y MITRE muestran hasta 100 registros por sección.</p>}
      </>}
    </section>
  </div>
}
