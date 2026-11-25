import {useEffect, useState, type ReactNode} from 'react'
import {Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis} from 'recharts'
import {api} from '../auth/client'
import {mitreBrowseStates} from './iocEvidence'

type Counts = {mapeos:number;automaticas:number;confirmadas:number;pendientes:number;descartadas:number;con_citas:number;sin_citas:number}
type Totals = Counts & {tecnicas:number;tacticas:number;sesiones:number;acciones:number;eventos_citados:number;ips:number;
  observables?:number;primera_aparicion:string|null;ultima_aparicion:string|null}
type Activity = Counts & {fecha:string;origen_fecha:'evento_citado'|'inicio_sesion'}
type Analytics = {
  totales:Totals;version_catalogo?:string|null
  tacticas:(Counts & {codigo_tactica:string;tactica:string})[]
  modalidades:(Counts & {modalidad:string})[]
  estados:(Counts & {estado_identificacion:keyof typeof mitreBrowseStates})[]
  evolucion:Activity[]
  recurrentes:{codigo_tecnica:string;tecnica:string;sesiones:number}[]
}
type Official = {codigo_tecnica:string;nombre:string;descripcion:string|null;plataformas:string[];stix_id:string|null;
  version_objeto:string|null;version_attack:string|null;tecnica_padre_id:string|null;jerarquia_fuente:string|null;
  estado_catalogo:string;tacticas:{codigo_tactica:string;nombre:string;activa_en_catalogo:boolean}[];
  subtecnicas:{codigo_tecnica:string;nombre:string;revocada:boolean;deprecada:boolean;jerarquia_fuente:string|null}[]}
type MatrixCell = Counts & {codigo_tactica:string;tactica:string;codigo_tecnica:string;tecnica:string;
  sesiones:number;tecnica_padre_id:string|null;estado_catalogo:string;relacion_vigente:boolean}

export const modalities:Record<string,string> = {
  cowrie_shell:'Cowrie Shell', cowrie_proxy:'Cowrie Proxy', cowrie_llm:'Cowrie LLM', desconocido:'Desconocida',
}
const catalogStates:Record<string,string> = {vigente:'Vigente',revocada:'Revocada',deprecada:'Deprecada',historica:'Histórica'}

export function mitreDate(value?:string|null) {
  return value ? new Date(value).toLocaleString('es-EC',{dateStyle:'short',timeStyle:'short',timeZone:'America/Guayaquil'}) : 'Sin registro'
}

function useMitreData<T>(path:string, revision=0) {
  const [result,setResult]=useState<{path:string;data?:T;error?:string}>()
  const [attempt,retry]=useState(0)
  useEffect(()=>{
    const controller=new AbortController()
    api<T>(path,{signal:controller.signal}).then(data=>{
      if(!controller.signal.aborted)setResult({path,data})
    }).catch(error=>{
      if(!controller.signal.aborted)setResult({path,error:error.message})
    })
    return ()=>controller.abort()
  },[path,revision,attempt])
  const current=result?.path===path?result:undefined
  return {...current,retry:()=>{setResult(undefined);retry(value=>value+1)}}
}

function FetchStatus({error,retry}: {error?:string;retry:()=>void}) {
  return error ? <div className="flex flex-wrap gap-3 items-center" role="alert">
    <p className="text-red-200 text-sm">{error}</p><button type="button" className="btn-secondary text-xs" onClick={retry}>Reintentar</button>
  </div> : <p className="muted text-sm" role="status">Cargando datos MITRE…</p>
}

export function CountLabels({counts}: {counts:Counts}) {
  return <span className="flex flex-wrap gap-1">
    {!!counts.automaticas&&<span className="badge contextual">{counts.automaticas} {counts.automaticas===1?'automática':'automáticas'}</span>}
    {!!counts.confirmadas&&<span className="badge contextual">{counts.confirmadas} {counts.confirmadas===1?'confirmada':'confirmadas'}</span>}
    {!!counts.pendientes&&<span className="badge warn">{counts.pendientes} {counts.pendientes===1?'histórica pendiente':'históricas pendientes'}</span>}
    {!!counts.descartadas&&<span className="badge error">{counts.descartadas} {counts.descartadas===1?'descartada':'descartadas'}</span>}
  </span>
}

export function Stats({items}: {items:[string,ReactNode][]}) {
  return <dl className="grid grid-cols-2 lg:grid-cols-4 gap-3">
    {items.map(([label,value])=><div className="border line rounded-lg px-3 py-3 min-w-0" key={label}>
      <dt className="muted text-xs">{label}</dt><dd className="mt-1 text-lg font-semibold break-words">{value}</dd>
    </div>)}
  </dl>
}

export function Chart({title,rows,unit,onSelect}: {title:string;rows:{name:string;value:number;code?:string}[];unit:string;onSelect?:(code:string)=>void}) {
  return <section className="panel p-4 min-w-0">
    <h3 className="font-semibold">{title}</h3><p className="muted text-xs">{unit}</p>
    {!rows.length?<p className="mt-4 text-sm muted">Sin datos para los filtros activos.</p>:<>
      <div className="h-40 mt-2 overflow-hidden" aria-hidden="true">
        <ResponsiveContainer width="100%" height="100%"><BarChart data={rows}>
          <CartesianGrid stroke="#20344d" vertical={false}/><XAxis dataKey="name" hide/><YAxis allowDecimals={false} width={36} stroke="#9fb4cc"/>
          <Tooltip contentStyle={{background:'#16273f',border:'1px solid #27415c'}} labelStyle={{color:'#eef5fa'}} itemStyle={{color:'#7ee1dc'}}/>
          <Bar dataKey="value" name={unit} fill="#43b7b5" isAnimationActive={false}
            cursor={onSelect?'pointer':undefined} onClick={entry=>{
              const code=entry.payload?.code
              if(typeof code==='string')onSelect?.(code)
            }}/>
        </BarChart></ResponsiveContainer>
      </div>
      <ul className="flex flex-wrap gap-x-3 gap-y-2 text-xs max-h-32 overflow-y-auto break-all">
        {rows.map(row=><li key={row.name}>{onSelect&&row.code?
          <button type="button" className="accent underline text-left" onClick={()=>onSelect(row.code!)}>{row.name} · {row.value}</button>:
          <span>{row.name} · {row.value}</span>}</li>)}
      </ul>
    </>}
  </section>
}

function ActivityChart({rows}: {rows:Activity[]}) {
  const days=new Map<string,{fecha:string;Citados:number;Sesión:number}>()
  for(const row of rows){
    const day=days.get(row.fecha)??{fecha:row.fecha,Citados:0,Sesión:0}
    day[row.origen_fecha==='evento_citado'?'Citados':'Sesión']+=row.mapeos
    days.set(row.fecha,day)
  }
  return <section className="panel p-4 min-w-0">
    <h3 className="font-semibold">Evolución temporal</h3>
    <p className="muted text-xs">Mapeos por día en Ecuador. Se usa el primer evento citado o, si falta, el inicio de la sesión.</p>
    {!days.size?<p className="mt-4 text-sm muted">Sin fechas para los filtros activos.</p>:<>
      <div className="h-40 mt-2 overflow-hidden" aria-hidden="true"><ResponsiveContainer width="100%" height="100%"><BarChart data={[...days.values()]}>
        <XAxis dataKey="fecha" minTickGap={35} stroke="#9fb4cc"/><YAxis allowDecimals={false} width={36} stroke="#9fb4cc"/>
        <Tooltip contentStyle={{background:'#16273f',border:'1px solid #27415c'}} labelStyle={{color:'#eef5fa'}}/>
        <Bar dataKey="Citados" name="Evento citado" fill="#43b7b5" stackId="fecha" isAnimationActive={false}/>
        <Bar dataKey="Sesión" name="Inicio de sesión" fill="#d4a657" stackId="fecha" isAnimationActive={false}/>
      </BarChart></ResponsiveContainer></div>
      <details className="text-xs"><summary className="cursor-pointer">Fechas y conteos</summary>
        <ul className="mt-2 max-h-36 overflow-auto">{[...days.values()].map(day=><li key={day.fecha}>{day.fecha} · {day.Citados} con fecha de cita · {day.Sesión} con fecha de sesión</li>)}</ul>
      </details>
    </>}
  </section>
}

export function MitreOverview({path,onTactic,onTechnique,revision}: {path:string;onTactic:(code:string)=>void;onTechnique:(code:string)=>void;revision:number}) {
  const {data,error,retry}=useMitreData<Analytics>(path,revision)
  if(!data)return <section className="panel p-4"><FetchStatus error={error} retry={retry}/></section>
  const count=data.totales
  return <>
    <section className="panel p-4" aria-label="Indicadores MITRE">
      <div className="flex flex-wrap gap-2 items-baseline justify-between mb-3">
        <h2 className="font-semibold">Actividad registrada</h2>
        <span className="badge">{data.version_catalogo?'ATT&CK Enterprise '+data.version_catalogo:'Catálogo activo no disponible'}</span>
      </div>
      <Stats items={[[ 'Técnicas distintas',count.tecnicas],['Sesiones distintas',count.sesiones],['Mapeos',count.mapeos],['Eventos citados distintos',count.eventos_citados]]}/>
      <details className="text-sm mt-3"><summary className="cursor-pointer">Desglose de indicadores</summary>
        <div className="mt-3"><CountLabels counts={count}/></div>
        <p className="muted mt-2">{count.tacticas} tácticas · {count.con_citas} mapeos con citas · {count.sin_citas} sin citas. Un mapeo automático también puede estar confirmado.</p>
      </details>
    </section>
    <details className="panel p-4" open><summary className="font-semibold cursor-pointer">Distribución y evolución de mapeos</summary>
      <div className="grid gap-3 mt-3 md:grid-cols-2 2xl:grid-cols-3">
        <Chart title="Por táctica" unit="Mapeos" rows={data.tacticas.map(row=>({name:row.tactica,value:row.mapeos,code:row.codigo_tactica}))} onSelect={onTactic}/>
        <Chart title="Técnicas más recurrentes" unit="Sesiones distintas" rows={data.recurrentes.map(row=>({name:row.codigo_tecnica+' · '+row.tecnica,value:row.sesiones,code:row.codigo_tecnica}))} onSelect={onTechnique}/>
        <Chart title="Por modalidad Cowrie" unit="Mapeos" rows={data.modalidades.map(row=>({name:modalities[row.modalidad]??row.modalidad,value:row.mapeos}))}/>
        <Chart title="Estado de clasificación" unit="Mapeos" rows={data.estados.map(row=>({name:mitreBrowseStates[row.estado_identificacion],value:row.mapeos}))}/>
        <Chart title="Disponibilidad de evidencia" unit="Mapeos" rows={count.mapeos?[{name:'Con citas verificables',value:count.con_citas},{name:'Sin citas verificables',value:count.sin_citas}]:[]}/>
        <ActivityChart rows={data.evolucion}/>
      </div>
    </details>
  </>
}

function MatrixTechnique({cell,selected,onSelect}: {cell:MatrixCell;selected:string|null;onSelect:(code:string)=>void}) {
  return <button type="button" aria-pressed={selected===cell.codigo_tecnica} onClick={()=>onSelect(cell.codigo_tecnica)}
    className="block w-full text-left rounded border line p-2 text-xs hover:border-teal-400 aria-pressed:border-teal-400">
    <span className="font-mono accent">{cell.codigo_tecnica}</span> · {cell.tecnica}
    <span className="block mt-1 muted">{cell.mapeos?
      cell.mapeos+(cell.mapeos===1?' mapeo · ':' mapeos · ')+cell.sesiones+(cell.sesiones===1?' sesión':' sesiones'):'Sin mapeos registrados'}
      {(!cell.relacion_vigente||cell.estado_catalogo!=='vigente')&&' · '+(catalogStates[cell.estado_catalogo]==='Vigente'?'Relación histórica':catalogStates[cell.estado_catalogo])}</span>
    <CountLabels counts={cell}/>
  </button>
}

export function MitreMatrix({path,selected,onTechnique,onTactic,revision}: {
  path:string;selected:string|null;onTechnique:(code:string)=>void;onTactic:(code:string)=>void;revision:number
}) {
  const [open,setOpen]=useState(false)
  const [catalog,setCatalog]=useState(false)
  return <details className="panel p-4" onToggle={event=>setOpen(event.currentTarget.open)}>
    <summary className="font-semibold cursor-pointer">Matriz MITRE ATT&CK</summary>
    {open&&<>
      <label className="flex items-center gap-2 mt-3 text-sm"><input type="checkbox" checked={catalog} onChange={event=>setCatalog(event.target.checked)}/> Incluir catálogo vigente sin mapeos</label>
      <p className="muted text-xs mt-2">Cada columna representa una táctica. Los conteos corresponden a la pareja técnica y táctica con los filtros activos. La matriz distingue catálogo y actividad registrada.</p>
      <MatrixBoard path={path+(path.includes('?')?'&':'?')+'catalogo='+catalog} selected={selected} onTechnique={onTechnique} onTactic={onTactic} revision={revision}/>
    </>}
  </details>
}

function MatrixBoard({path,selected,onTechnique,onTactic,revision}: {
  path:string;selected:string|null;onTechnique:(code:string)=>void;onTactic:(code:string)=>void;revision:number
}) {
  const {data,error,retry}=useMitreData<MatrixCell[]>(path,revision)
  if(!data)return <div className="mt-3"><FetchStatus error={error} retry={retry}/></div>
  if(!data.length)return <p className="muted text-sm mt-3">Sin relaciones para los filtros activos.</p>
  const columns=new Map<string,MatrixCell[]>()
  for(const cell of data){
    const group=columns.get(cell.codigo_tactica)
    if(group)group.push(cell)
    else columns.set(cell.codigo_tactica,[cell])
  }
  return <div className="flex gap-3 overflow-x-auto mt-3 pb-3" tabIndex={0} role="region" aria-label="Tácticas de la matriz ATT&CK">
    {[...columns].map(([code,cells])=>{
      const codes=new Set(cells.map(cell=>cell.codigo_tecnica))
      const byParent=new Map<string,MatrixCell[]>()
      const roots=cells.filter(cell=>{
        const parent=cell.tecnica_padre_id
        if(!parent||!codes.has(parent))return true
        const children=byParent.get(parent)
        if(children)children.push(cell)
        else byParent.set(parent,[cell])
        return false
      })
      return <section key={code} className="shrink-0 w-56 grid content-start gap-2">
        <h3><button className="btn-secondary w-full text-left text-sm" type="button" onClick={()=>onTactic(code)}>{cells[0].tactica}</button></h3>
        <div className="space-y-2 max-h-[30rem] overflow-y-auto pr-1">
          {roots.map(cell=>{
            const children=byParent.get(cell.codigo_tecnica)??[]
            return <div key={cell.codigo_tecnica}><MatrixTechnique cell={cell} selected={selected} onSelect={onTechnique}/>
              {children.length>0&&<details className="mt-1 pl-2"><summary className="text-xs muted cursor-pointer">Subtécnicas ({children.length})</summary>
                <div className="space-y-1 mt-1">{children.map(child=><MatrixTechnique key={child.codigo_tecnica} cell={child} selected={selected} onSelect={onTechnique}/>)}</div>
              </details>}
            </div>
          })}
        </div>
      </section>
    })}
  </div>
}

export function MitreTechniqueProfile({path,onTechnique,revision}: {path:string;onTechnique:(code:string)=>void;revision:number}) {
  const {data,error,retry}=useMitreData<Analytics & {catalogo:Official}>(path,revision)
  if(!data)return <section className="panel p-4"><FetchStatus error={error} retry={retry}/></section>
  const {catalogo:official,totales:count}=data
  const match=/^T(\d{4})(?:\.(\d{3}))?$/.exec(official.codigo_tecnica)
  return <section className="panel p-4 space-y-3 min-w-0" aria-label="Perfil de técnica">
    <div><p className="font-mono accent text-sm">{official.codigo_tecnica}</p><h2 className="text-lg font-semibold">{official.nombre}</h2>
      <p className="muted text-xs mt-1">{[catalogStates[official.estado_catalogo],official.version_attack&&'ATT&CK '+official.version_attack].filter(Boolean).join(' · ')}</p>
    </div>
    <details open><summary className="cursor-pointer font-semibold text-sm">Información oficial</summary>
      <p className="text-xs muted mt-2">Plataformas: {official.plataformas?.join(', ')||'Sin registro'}</p>
      <p className="text-xs mt-1 break-all">{official.stix_id??'STIX sin registro'}{official.version_objeto?' · Objeto v'+official.version_objeto:''}</p>
      <p className="text-xs mt-1">{official.tacticas.map(tactic=>tactic.nombre+(tactic.activa_en_catalogo?'':' (histórica)')).join(' · ')||'Sin tácticas registradas'}</p>
      {official.descripcion&&<details className="text-xs mt-2"><summary className="cursor-pointer">Leer descripción oficial</summary><p className="mt-2 whitespace-pre-wrap break-words">{official.descripcion}</p></details>}
      <div className="flex flex-wrap gap-3 text-xs mt-3">
        {match&&<a className="accent underline" target="_blank" rel="noopener noreferrer" href={'https://attack.mitre.org/techniques/T'+match[1]+'/'+(match[2]?match[2]+'/':'')}>Documentación ATT&CK</a>}
        {official.tecnica_padre_id&&<button type="button" className="accent underline" onClick={()=>onTechnique(official.tecnica_padre_id!)}>Principal {official.tecnica_padre_id}{official.jerarquia_fuente==='codigo_revocado'?' (derivada del código histórico)':''}</button>}
      </div>
      {!!official.subtecnicas.length&&<details className="mt-2 text-xs"><summary className="cursor-pointer">Subtécnicas ({official.subtecnicas.length})</summary>
        <ul className="space-y-1 mt-2">{official.subtecnicas.map(child=><li key={child.codigo_tecnica}><button type="button" className="accent underline text-left" onClick={()=>onTechnique(child.codigo_tecnica)}>{child.codigo_tecnica} · {child.nombre}{child.revocada?' · Revocada':child.deprecada?' · Deprecada':''}</button></li>)}</ul>
      </details>}
    </details>
    <Stats items={[[ 'Sesiones',count.sesiones],['Mapeos',count.mapeos],['Acciones',count.acciones],['Eventos citados',count.eventos_citados],['Origen IP distinto',count.ips],['Observables vinculados',count.observables??'Sin registro']]}/>
    <p className="muted text-xs">Primera aparición {mitreDate(count.primera_aparicion)} · Última {mitreDate(count.ultima_aparicion)}</p>
    <CountLabels counts={count}/>
    {!!data.modalidades.length&&<p className="muted text-xs">{data.modalidades.map(row=>(modalities[row.modalidad]??row.modalidad)+' · '+row.mapeos).join(' / ')}</p>}
    {new Set(data.evolucion.map(row=>row.fecha)).size>1&&<ActivityChart rows={data.evolucion}/>}
  </section>
}
