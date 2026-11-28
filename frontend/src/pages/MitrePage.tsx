import {MitreClassifiers} from '../analysis/MitreClassifiers'
import {useState} from 'react'
import {Link, useSearchParams} from 'react-router-dom'
import {useAuth} from '../auth/context'
import {CountLabels, MitreMatrix, MitreOverview, MitreTechniqueProfile, modalities} from '../analysis/MitreDashboard'
import {actionEvidencePath, isAutomaticMapping, mitreBrowseStates, mitreGradeLabels, sessionEvidencePath} from '../analysis/iocEvidence'
import {MappingObservables, MappingStatus, type MappingEvidence} from '../analysis/IocCorrelations'
import {Header,ErrorBox,usePagedData,Pager,date} from './shared'
import {ReviewControls,type ReviewState} from './ReviewControls'

type MitreRow=Omit<MappingEvidence,'eventos'|'estado_revision'>&{
  id_analisis:string;id_sesion:string;cowrie_session_id:string;modalidad:string;
  fecha_analisis:string|null;fecha_mapeo:string;version_pipeline?:string|null;version_informe?:string|null;
  estado_revision:ReviewState;tipo_accion:string;descripcion_accion:string;revisado_en?:string|null;evidencia?:string|null;
  confianza?:number|null;
}
const MITRE_FILTERS=['q','tactica','sesion','modalidad','estado','plataforma','ip','citas','grado','desde','hasta','orden'] as const
type MitreCounts=Parameters<typeof CountLabels>[0]['counts']
type MitreTechnique=MitreCounts & {codigo_tecnica:string;tecnica:string;tacticas:string[];sesiones:number;
  primera_aparicion:string|null;ultima_aparicion:string|null}
type MitreSession=MitreCounts & {id_sesion:string;cowrie_session_id:string;modalidades:string[];eventos:number;
  ip_origen:string|null;sensor:string;fecha_inicio:string;fecha_fin:string|null;duracion_segundos:number|null;
  acciones:number;estados_analisis:string[]}

function mitrePath(path:string, filters:string, scope:Record<string,string>={}) {
  const query=new URLSearchParams(filters)
  Object.entries(scope).forEach(([key,value])=>query.set(key,value))
  return path+(query.size?'?'+query:'')
}

function MitreFilterForm({filters,onApply}: {filters:string;onApply:(params:URLSearchParams)=>void}) {
  const query=new URLSearchParams(filters)
  const fieldClass='block w-full bg-[#1a2e46] border line rounded-md px-3 py-2 text-sm mt-1'
  return <form aria-label="Filtros MITRE" className="panel p-4 mb-5" onSubmit={event=>{
    event.preventDefault()
    const data=new FormData(event.currentTarget)
    const next=new URLSearchParams()
    for(const key of MITRE_FILTERS){
      const value=String(data.get(key)??'').trim()
      if(value)next.set(key,value)
    }
    onApply(next)
  }}>
    <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3">
      <label className="text-xs">Código o técnica<input name="q" className={fieldClass} defaultValue={query.get('q')??''} maxLength={100}/></label>
      <label className="text-xs">Táctica<input name="tactica" className={fieldClass} defaultValue={query.get('tactica')??''} maxLength={100}/></label>
      <label className="text-xs">Sesión<input name="sesion" className={fieldClass} defaultValue={query.get('sesion')??''} maxLength={100}/></label>
      <label className="text-xs">Modalidad<select name="modalidad" className={fieldClass} defaultValue={query.get('modalidad')??''}>
        <option value="">Todas</option><option value="cowrie_shell">Shell</option><option value="cowrie_proxy">Proxy</option>
        <option value="cowrie_llm">LLM</option><option value="desconocido">Desconocida</option>
      </select></label>
      <label className="text-xs">Estado<select name="estado" className={fieldClass} defaultValue={query.get('estado')??''}>
        <option value="">Todos</option>
        {Object.entries(mitreBrowseStates).map(([key,value])=><option key={key} value={key}>{value}</option>)}
      </select></label>
    </div>
    <details className="mt-3">
      <summary className="cursor-pointer text-sm">Filtros de evidencia, plataforma y fechas</summary>
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-3">
        <label className="text-xs">Plataforma oficial<input name="plataforma" className={fieldClass} defaultValue={query.get('plataforma')??''} placeholder="Linux" maxLength={50}/></label>
        <label className="text-xs">IP de origen<input name="ip" className={fieldClass} defaultValue={query.get('ip')??''} maxLength={64}/></label>
        <label className="text-xs">Citas<select name="citas" className={fieldClass} defaultValue={query.get('citas')??''}>
          <option value="">Todas</option><option value="con">Con citas verificables</option><option value="sin">Sin citas verificables</option>
        </select></label>
        <label className="text-xs">Grado de evidencia<select name="grado" className={fieldClass} defaultValue={query.get('grado')??''}>
          <option value="">Todos</option><option value="intento">Intento</option><option value="resultado_en_honeypot">Resultado observado</option><option value="sin_registro">Sin registro</option>
        </select></label>
        <label className="text-xs">Desde (Ecuador)<input name="desde" type="date" className={fieldClass} defaultValue={query.get('desde')??''}/></label>
        <label className="text-xs">Hasta (Ecuador)<input name="hasta" type="date" className={fieldClass} defaultValue={query.get('hasta')??''}/></label>
        <label className="text-xs">Ordenar por<select name="orden" className={fieldClass} defaultValue={query.get('orden')??''}>
          <option value="">Última aparición</option><option value="primera">Primera aparición</option><option value="codigo">Código</option>
          <option value="nombre">Nombre</option><option value="sesiones">Sesiones</option><option value="mapeos">Mapeos</option>
        </select></label>
      </div>
    </details>
    {query.size>0&&<p className="muted text-xs mt-3">Filtros activos: {[...query.values()].join(' · ')}</p>}
    <div className="flex gap-2 mt-3">
      <button type="submit" className="btn text-xs">Aplicar filtros</button>
      {query.size>0&&<button type="button" className="btn-secondary text-xs" onClick={()=>onApply(new URLSearchParams())}>Limpiar filtros</button>}
    </div>
  </form>
}

function MitreSessionMappings({codigo,sessionId,filters,activeMapping,onSelect}: {codigo:string;sessionId:string;filters:string;activeMapping:string|null;onSelect:(id:string)=>void}) {
  const [page,setPage]=useState(0)
  const {rows,hasNext,loading,error}=usePagedData<MitreRow>(mitrePath('/mitre/mapeos',filters,{codigo,id_sesion:sessionId}),page,8)
  return <section className="border-t line pt-3 mt-3" aria-label="Hallazgos de la sesión seleccionada">
    {error&&<ErrorBox error={error}/>}
    {loading?<p role="status" className="muted text-sm">Cargando hallazgos…</p>:<>
      <ul className="space-y-2 mb-3">
        {rows.map(row=><li key={row.id_mapeo}>
          <button type="button" aria-pressed={activeMapping===row.id_mapeo} className="w-full text-left p-2 rounded border line hover:bg-[#1b3049] aria-pressed:border-teal-400" onClick={()=>onSelect(row.id_mapeo)}>
            <span className="flex flex-wrap justify-between items-baseline gap-2">
              <span className="font-semibold text-sm">{row.tactica}</span><MappingStatus mapping={row}/>
            </span>
            <span className="block muted text-xs mt-1">{date(row.fecha_analisis??row.fecha_mapeo)} · {row.tipo_accion}</span>
          </button>
        </li>)}
      </ul>
      <Pager page={page} pageSize={8} count={rows.length} hasNext={hasNext} onChange={setPage} label="hallazgos de la sesión"/>
    </>}
  </section>
}

function MitreTechniqueSessions({codigo,filters,activeMapping,linkedSession,onSelect}: {codigo:string;filters:string;activeMapping:string|null;linkedSession:string|null;onSelect:(id:string|null)=>void}) {
  const [page,setPage]=useState(0)
  const [active,setActive]=useState<string|null>(linkedSession)
  const [onlyLinked,setOnlyLinked]=useState(!!linkedSession)
  const [order,setOrder]=useState('ultima')
  const path=mitrePath('/mitre/tecnicas/'+encodeURIComponent(codigo)+'/sesiones',filters,
    onlyLinked&&linkedSession?{id_sesion:linkedSession,orden:order}:{orden:order})
  const {rows,hasNext,loading,error}=usePagedData<MitreSession>(path,page,8)
  return <section className="panel p-5 min-w-0">
    <h2 className="font-semibold mb-3">Sesiones asociadas a {codigo}</h2>
    <label className="text-xs flex flex-wrap items-center gap-2 mb-3">Orden de sesiones
      <select className="bg-[#1a2e46] border line rounded px-2 py-1" value={order} onChange={event=>{
        setOrder(event.target.value);setPage(0);setActive(null);onSelect(null)
      }}>
        <option value="ultima">Última aparición</option><option value="primera">Inicio de sesión</option>
        <option value="codigo">Identificador de Cowrie</option><option value="mapeos">Cantidad de mapeos</option>
      </select>
    </label>
    {onlyLinked&&<button className="btn-secondary text-xs mb-3" type="button" onClick={()=>{setOnlyLinked(false);setPage(0)}}>Ver todas las sesiones de la técnica</button>}
    {error&&<ErrorBox error={error}/>}
    {loading?<p role="status" className="muted text-sm">Cargando sesiones asociadas…</p>:<>
      <ul className="space-y-2 mb-3">
        {rows.map(row=><li key={row.id_sesion} className="border line rounded p-3">
          <div className="flex flex-wrap justify-between gap-2 items-baseline">
            <Link className="font-mono accent break-all text-sm hover:underline" to={sessionEvidencePath(row.id_sesion)}>{row.cowrie_session_id}</Link>
            <button type="button" className="btn-secondary text-xs" aria-expanded={active===row.id_sesion} onClick={()=>{
              setActive(active===row.id_sesion?null:row.id_sesion);onSelect(null)
            }}>{active===row.id_sesion?'Ocultar hallazgos':'Ver hallazgos'}</button>
          </div>
          <p className="muted text-xs mt-1">{row.id_sesion} · {row.ip_origen??'IP sin registro'} · {row.sensor}</p>
          <p className="muted text-xs mt-1">{row.modalidades.map(mode=>modalities[mode]??mode).join(' / ')} · {date(row.fecha_inicio)} a {date(row.fecha_fin)}
            {row.duracion_segundos!=null?' · '+Math.round(row.duracion_segundos)+' s':''}</p>
          <p className="muted text-xs mt-1">{row.eventos} eventos · {row.acciones} acciones · {row.mapeos} mapeos · {row.con_citas} con citas · Análisis {row.estados_analisis.join(' / ')}</p>
          <CountLabels counts={row}/>
          {active===row.id_sesion&&<MitreSessionMappings key={row.id_sesion} codigo={codigo} sessionId={row.id_sesion} filters={filters} activeMapping={activeMapping} onSelect={onSelect}/>}
        </li>)}
      </ul>
      <Pager page={page} pageSize={8} count={rows.length} hasNext={hasNext} onChange={next=>{setActive(null);onSelect(null);setPage(next)}} label="sesiones asociadas"/>
    </>}
  </section>
}

function MitreMappingDetail({id,onReviewed,expectedCode,expectedSession}: {
  id:string;onReviewed?:()=>void;expectedCode?:string|null;expectedSession?:string|null
}) {
  const {session}=useAuth()
  const {rows,setRows,loading,error}=usePagedData<MitreRow>(mitrePath('/mitre/mapeos','',{id_mapeo:id}),0,1)
  const mapping=rows.find(row=>(!expectedCode||row.codigo_tecnica===expectedCode)&&(!expectedSession||row.id_sesion===expectedSession))
  const provenance=mapping?.rag_procedencia
  return <aside className="panel p-5 min-w-0" aria-label="Detalle del hallazgo">
    {error&&<ErrorBox error={error}/>}
    {loading?<p role="status" className="muted text-sm">Cargando hallazgo…</p>:mapping?<>
      <h2 className="font-semibold text-lg">{mapping.codigo_tecnica} · {mapping.tecnica}</h2>
      <div className="flex flex-wrap gap-2 items-baseline mt-2">
        <MappingStatus mapping={mapping}/>
        <span className="badge contextual">{mapping.codigo_tactica} {mapping.tactica}</span>
        {mapping.grado_evidencia&&<span className="badge">{mitreGradeLabels[mapping.grado_evidencia]??mapping.grado_evidencia}</span>}
      </div>
      <p className="text-sm mt-3">{[date(mapping.fecha_analisis??mapping.fecha_mapeo),mapping.modalidad].filter(Boolean).join(' · ')}</p>
      <div className="flex flex-wrap gap-3 mt-3 text-xs">
        <Link to={sessionEvidencePath(mapping.id_sesion)} className="accent hover:underline">Sesión {mapping.cowrie_session_id}</Link>
        <Link to={actionEvidencePath(mapping.id_sesion,mapping.id_analisis,mapping.id_accion)} className="accent hover:underline">Abrir análisis y acción</Link>
        <Link to={sessionEvidencePath(mapping.id_sesion)+'?'+new URLSearchParams({analisis:mapping.id_analisis})} className="accent hover:underline">Abrir informe del análisis</Link>
      </div>
      <p className="text-sm mt-3"><strong>{mapping.tipo_accion}</strong> {mapping.descripcion_accion}</p>
      {provenance?.comportamiento_observado&&<p className="text-sm mt-2"><strong>Interpretación del análisis</strong> {provenance.comportamiento_observado}</p>}
      {!isAutomaticMapping(mapping)&&mapping.evidencia&&<details open className="mt-3 text-xs muted">
        <summary className="cursor-pointer">Texto histórico del mapeo</summary>
        <p className="mt-2 break-words">{mapping.evidencia}</p>
      </details>}
      <MappingObservables key={mapping.id_mapeo} id={mapping.id_mapeo} review={mapping.estado_revision} detailed/>
      <details className="border-t line pt-3 mt-4">
        <summary className="cursor-pointer text-sm font-semibold">Procedencia y validación</summary>
        <dl className="grid gap-2 mt-3 text-xs sm:grid-cols-2">
          {[
            ['Análisis',mapping.id_analisis],['Origen',provenance?.modalidad??mapping.modalidad],
            ['Modelo LLM',provenance?.modelo_llm?.modelo],['Catálogo utilizado',provenance?.catalogo?.version],
            ['STIX',provenance?.stix_id],['Método de análisis',provenance?.metodo],
            ['Validador',provenance?.version_validador],['Contrato de evidencia',provenance?.version_contrato],
            ['Versión del pipeline',mapping.version_pipeline],['Versión del informe',mapping.version_informe],
            ['Fecha del análisis',date(mapping.fecha_analisis)],['Revisión',date(mapping.revisado_en)],
          ].map(([label,value])=><div className="break-words" key={label}><dt className="muted">{label}</dt><dd>{value||'Sin registro'}</dd></div>)}
          {mapping.confianza!=null&&<div><dt className="muted">Confianza declarada por el LLM</dt><dd>{mapping.confianza} · Valor sin calibrar</dd></div>}
        </dl>
      </details>
      {mapping.revisado_en&&<p className="muted text-xs mt-3">Revisado {date(mapping.revisado_en)}{mapping.motivo_revision?' · '+mapping.motivo_revision:''}</p>}
      {session?.usuario.rol==='administrador'&&<details className="border-t line pt-3 mt-4">
        <summary className="cursor-pointer text-sm font-semibold">Revisión administrativa</summary>
        <ReviewControls key={mapping.id_mapeo} kind="mitre" id={mapping.id_mapeo} state={mapping.estado_revision} reviewedAt={mapping.revisado_en}
          automatic={isAutomaticMapping(mapping)} onReviewed={state=>{
            setRows(rows=>rows.map(row=>row.id_mapeo===mapping.id_mapeo?{...row,estado_revision:state}:row));onReviewed?.()
          }}/>
      </details>}
    </>:!error&&<p className="muted text-sm">No se encontró el hallazgo.</p>}
  </aside>
}

function MitreExplorer({filters,code,onTechnique,linkedMapping,linkedSession,revision,onReviewed}: {
  filters:string;code:string|null;onTechnique:(code:string)=>void;linkedMapping:string|null;linkedSession:string|null;
  revision:number;onReviewed:()=>void
}) {
  const [page,setPage]=useState(0)
  const [selection,setSelection]=useState<{code:string|null;mapping:string|null}>({code,mapping:linkedMapping})
  const activeMapping=selection.code===code?selection.mapping:null
  const setActiveMapping=(mapping:string|null)=>setSelection({code,mapping})
  const {rows,hasNext,loading,error}=usePagedData<MitreTechnique>(mitrePath('/mitre/tecnicas',filters),page,12,5000,revision)
  return <div id="mitre-explorer" className="mitre-review-layout grid lg:grid-cols-[minmax(0,1fr)_minmax(22rem,1.3fr)] gap-5 items-start">
    <section className="panel p-5 min-w-0">
      <h2 className="font-semibold mb-3">Técnicas con mapeos guardados</h2>
      {error&&<ErrorBox error={error}/>}
      {loading?<p role="status" className="muted text-sm">Cargando técnicas…</p>:
        <ul className="divide-y line mb-3">
          {rows.map(row=><li key={row.codigo_tecnica}>
            <button type="button" aria-pressed={code===row.codigo_tecnica}
              className="mitre-finding w-full text-left px-3 py-3 rounded-md"
              onClick={()=>{onTechnique(row.codigo_tecnica);setSelection({code:row.codigo_tecnica,mapping:null})}}>
              <span className="flex flex-wrap justify-between gap-2 items-baseline">
                <span className="font-semibold"><span className="font-mono accent mr-2">{row.codigo_tecnica}</span>{row.tecnica}</span>
                <span className="badge">{row.sesiones} {row.sesiones===1?'sesión':'sesiones'}</span>
              </span>
              <span className="block muted text-xs mt-1">{row.tacticas.join(' · ')}</span>
              <span className="block muted text-xs mt-1">{row.mapeos} mapeos · {row.con_citas} con citas</span>
              <span className="block muted text-xs mt-1">{date(row.primera_aparicion)} a {date(row.ultima_aparicion)}</span>
              <CountLabels counts={row}/>
            </button>
          </li>)}
        </ul>}
      <Pager page={page} pageSize={12} count={rows.length} hasNext={hasNext} onChange={setPage} label="técnicas MITRE"/>
    </section>
    <div className="space-y-5 min-w-0">
      {code?<><MitreTechniqueProfile path={mitrePath('/mitre/tecnicas/'+encodeURIComponent(code),filters)} onTechnique={onTechnique} revision={revision}/>
        <MitreTechniqueSessions key={code+':'+linkedSession} codigo={code} filters={filters} activeMapping={activeMapping} linkedSession={linkedSession} onSelect={setActiveMapping}/></>:
        <p className="panel p-5 muted text-sm">Selecciona una técnica para ver sus sesiones y hallazgos.</p>}
      {activeMapping&&<MitreMappingDetail key={activeMapping} id={activeMapping} onReviewed={onReviewed}
        expectedCode={code} expectedSession={linkedMapping===activeMapping?linkedSession:null}/>}
    </div>
  </div>
}

export function MitrePage(){
  const [params,setParams]=useSearchParams()
  const [revision,setRevision]=useState(0)
  const direct=params.get('mapeo')
  const filters=new URLSearchParams()
  for(const key of MITRE_FILTERS){
    const value=params.get(key)
    if(value)filters.set(key,value)
  }
  const filterKey=filters.toString()
  const code=params.get('tecnica')
  const selectTechnique=(selected:string)=>setParams({...Object.fromEntries(filters),tecnica:selected},{preventScrollReset:true})
  const inspectTechnique=(selected:string)=>{
    selectTechnique(selected)
    document.getElementById('mitre-explorer')?.scrollIntoView({block:'start'})
  }
  const selectTactic=(tactic:string)=>setParams({...Object.fromEntries(filters),tactica:tactic})
  return <>
    <Header title="MITRE ATT&CK" description="Investiga las sesiones y las evidencias de cada técnica."
      action={direct?<Link className="btn-secondary" to="/mitre">Ver todas las técnicas</Link>:undefined}/>
    {direct&&!code?<MitreMappingDetail key={direct} id={direct}/>:<div className="space-y-4 min-w-0">
      <MitreClassifiers/>
      <MitreFilterForm key={filterKey} filters={filterKey} onApply={setParams}/>
      <MitreOverview path={mitrePath('/mitre/resumen',filterKey)} onTactic={selectTactic} onTechnique={inspectTechnique} revision={revision}/>
      <MitreMatrix path={mitrePath('/mitre/matriz',filterKey)} selected={code} onTactic={selectTactic} onTechnique={inspectTechnique} revision={revision}/>
      <MitreExplorer key={filterKey+':'+(direct??'')} filters={filterKey} code={code} onTechnique={selectTechnique}
        linkedMapping={direct} linkedSession={params.get('sesion_id')} revision={revision} onReviewed={()=>setRevision(value=>value+1)}/>
    </div>}
  </>
}
