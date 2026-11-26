import {useEffect, useState} from 'react'
import {Link, useSearchParams} from 'react-router-dom'
import {ArrowUpRight, ChevronDown, FileText, History, ListFilter, NotebookPen, ShieldCheck} from 'lucide-react'
import './safeguards.css'
import {api, mutate} from '../auth/client'
import {useAuth} from '../auth/context'
import {mitreDate} from './MitreDashboard'

type Review = {revision:number;estado:string;responsable:string;motivo:string;verificacion:string;revisado_en:string;revisado_por:string}
type Proposal = {id_analisis:string;id_sesion:string;cowrie_session_id:string;codigo:string;estado:string;
  fecha_inicio:string;fecha_analisis:string|null;ficha:{title:string;rows:[string,string][]};historial:Review[];total:number}
const labels:Record<string,string> = {propuesta:'Propuesta',aprobada:'Aprobada',en_curso:'En curso',verificada:'Verificada',descartada:'Descartada'}
const transitions:Record<string,string[]> = {
  propuesta:['aprobada','descartada'], aprobada:['en_curso','descartada'],
  en_curso:['verificada','descartada'], verificada:['en_curso'], descartada:['propuesta'],
}

function ReviewForm({proposal,onSaved}:{proposal:Proposal;onSaved:()=>void}) {
  const {session}=useAuth()
  const [busy,setBusy]=useState(false), [error,setError]=useState('')
  const [state,setState]=useState(transitions[proposal.estado][0])
  async function save(event:React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form=Object.fromEntries(new FormData(event.currentTarget))
    setBusy(true);setError('')
    try {
      await mutate('/analisis/'+proposal.id_analisis+'/salvaguardas/'+proposal.codigo+'/revision',{
        ...form,revision_esperada:proposal.historial.length,
      })
      onSaved()
    } catch(failure) {setError((failure as Error).message)}
    finally {setBusy(false)}
  }
  if(session?.usuario.rol!=='administrador')return null
  return <details className="sg-section">
    <summary><NotebookPen/>Registrar seguimiento<ChevronDown/></summary>
    <form className="sg-form" onSubmit={save}>
      <label>Estado<select name="estado" className="input w-full" value={state} onChange={event=>setState(event.target.value)}>
        {transitions[proposal.estado].map(value=><option key={value} value={value}>{labels[value]}</option>)}
      </select></label>
      <label>Responsable<input name="responsable" className="input w-full" minLength={3} maxLength={200} required
        defaultValue={proposal.historial.at(-1)?.responsable??''}/></label>
      <label>Motivo y actuaciones<textarea className="input w-full" name="motivo" required minLength={10} maxLength={2000}/></label>
      <label>Verificación y evidencia<textarea className="input w-full" name="verificacion"
        required={state==='verificada'} minLength={state==='verificada'?20:undefined} maxLength={3000}/></label>
      {error&&<p role="alert" className="text-red-200">{error}</p>}
      <button className="btn justify-self-start" disabled={busy}>{busy?'Guardando…':'Guardar seguimiento'}</button>
    </form>
  </details>
}

export function SafeguardsPage() {
  const [params,setParams]=useSearchParams()
  const [rows,setRows]=useState<Proposal[]>([])
  const [error,setError]=useState(''), [loading,setLoading]=useState(true), [revision,setRevision]=useState(0)
  const page=Math.max(0,Number(params.get('pagina'))||0)
  const analysis=params.get('analisis'), code=params.get('codigo')
  const state=params.get('estado')??''
  const query=new URLSearchParams({limit:'26',offset:String(page*25)})
  const sessionId=params.get('sesion')
  if(sessionId)query.set('id_sesion',sessionId)
  if(analysis)query.set('id_analisis',analysis)
  if(state)query.set('estado',state)
  const path='/salvaguardas?'+query
  useEffect(()=>{
    const controller=new AbortController()
    setLoading(true);setError('');setRows([])
    api<Proposal[]>(path,{signal:controller.signal}).then(setRows).catch(failure=>{
      if(!controller.signal.aborted)setError(failure.message)
    }).finally(()=>{if(!controller.signal.aborted)setLoading(false)})
    return()=>controller.abort()
  },[path,revision])
  function change(values:Record<string,string>) {
    setParams({...Object.fromEntries(params),...values})
  }
  const visible=rows.slice(0,25)
  return <div className="sg-page space-y-5">
    <header className="border-b line pb-6">
      <h1 className="text-3xl font-bold flex items-center gap-3"><ShieldCheck className="accent"/>Salvaguardas</h1>
      <p className="muted mt-2 text-sm">Propuestas por sesión, responsables y comprobación de eficacia.</p>
    </header>
    <div className="sg-toolbar">
      <label><ListFilter size={16}/>Estado <select value={state} onChange={event=>change({estado:event.target.value,pagina:'0'})}>
        <option value="">Todos</option>{Object.entries(labels).map(([value,label])=><option key={value} value={value}>{label}</option>)}
      </select></label>
      {(analysis||sessionId)&&<Link className="btn-secondary text-xs" to="/salvaguardas">Ver todas las sesiones y análisis</Link>}
    </div>
    {loading&&<p role="status">Cargando salvaguardas…</p>}
    {error&&<div role="alert"><p className="text-red-200">{error}</p><button className="btn-secondary mt-2" onClick={()=>setRevision(value=>value+1)}>Reintentar</button></div>}
    {!loading&&!error&&!visible.length&&<p className="panel p-5 muted">Sin propuestas para esta selección.</p>}
    {visible.map(item=><article key={item.id_analisis+item.codigo} className="panel p-5">
      <div className="sg-heading">
        <span className="sg-code">{item.codigo}</span>
        <span className={'badge '+(item.estado==='propuesta'?'warn':'')}>{labels[item.estado]}</span>
      </div>
      <h2 className="sg-title">{item.ficha.title}</h2>
      <dl className="sg-meta">
        <div><dt>Sesión</dt><dd>{item.cowrie_session_id} · {mitreDate(item.fecha_inicio)}</dd></div>
        <div><dt>Análisis</dt><dd>{item.id_analisis} · {mitreDate(item.fecha_analisis)}</dd></div>
      </dl>
      <div className="sg-links">
        <Link to={'/sesiones/'+item.id_sesion+'?analisis='+item.id_analisis}>Ver análisis y evidencia de origen<ArrowUpRight/></Link>
        {!sessionId&&<Link to={'/salvaguardas?sesion='+item.id_sesion}>Historial de esta sesión<ArrowUpRight/></Link>}
      </div>
      <details className="sg-section" open={analysis!==null&&code===item.codigo}>
        <summary><FileText/>Ficha de propuesta<ChevronDown/></summary>
        <dl className="text-sm mt-3">{item.ficha.rows.map(([label,value])=><div key={label} className="grid sm:grid-cols-[12rem_1fr] gap-2 py-2 border-t line">
          <dt className="muted">{label}</dt><dd className="whitespace-pre-wrap break-words">{value}</dd>
        </div>)}</dl>
      </details>
      <details className="sg-section" open={analysis!==null&&code===item.codigo}>
        <summary><History/>Historial ({item.historial.length})<ChevronDown/></summary>
        {!item.historial.length&&<p className="muted text-sm mt-2">Propuesta generada en este análisis, pendiente de seguimiento.</p>}
        <ol className="mt-3 space-y-3">{item.historial.map(review=><li key={review.revision} className="border-l-2 border-[#427279] pl-4 text-sm">
          <p className="font-semibold">{labels[review.estado]} · {mitreDate(review.revisado_en)}</p>
          <p>Responsable · {review.responsable}</p>
          <p className="whitespace-pre-wrap mt-1">{review.motivo}</p>
          {review.verificacion&&<p className="whitespace-pre-wrap mt-1">{review.verificacion}</p>}
          <p className="muted text-xs mt-2">Registrado por {review.revisado_por}</p>
        </li>)}</ol>
      </details>
      <ReviewForm key={item.id_analisis+item.codigo+item.historial.length} proposal={item} onSaved={()=>setRevision(value=>value+1)}/>
    </article>)}
    {!loading&&!error&&(page>0||rows.length>25)&&<nav className="flex gap-3 justify-end" aria-label="Páginas de salvaguardas">
      <button className="btn-secondary" disabled={page===0} onClick={()=>change({pagina:String(page-1)})}>Anterior</button>
      <span className="muted text-sm self-center">Página {page+1}</span>
      <button className="btn-secondary" disabled={rows.length<=25} onClick={()=>change({pagina:String(page+1)})}>Siguiente</button>
    </nav>}
  </div>
}
