import {useEffect, useState} from 'react'
import {mutate} from '../auth/client'
import {useAuth} from '../auth/context'
import {mappingReviewLabels, reviewLabels} from '../analysis/iocEvidence'

export type ReviewState='pendiente'|'confirmado'|'descartado'|'mixto'
export function ReviewControls({kind,id,state,reviewedAt,canConfirm=true,automatic=false,onReviewed}:{kind:'observacion_ioc'|'mitre',id:string,state:ReviewState,reviewedAt?:string|null,canConfirm?:boolean,automatic?:boolean,onReviewed?:(state:ReviewState)=>void}){
  const {session}=useAuth(),[busy,setBusy]=useState(false),[error,setError]=useState('')
  const [decision,setDecision]=useState<'confirmado'|'descartado'|null>(null)
  const [reason,setReason]=useState('')
  const [current,setCurrent]=useState(state)
  const [version,setVersion]=useState<string|null>(null)
  function choose(value:'confirmado'|'descartado'){setVersion(reviewedAt??null);setDecision(value);setError('')}
  useEffect(()=>setCurrent(state),[state])
  const observable=kind==='observacion_ioc'
  async function review(){
    const motivo=reason.trim()
    if(!decision||motivo.length<10){setError('Escriba un motivo de al menos 10 caracteres.');return}
    setBusy(true);setError('')
    try{await mutate(`/inteligencia/${kind}/${id}/revision`,{estado:decision,motivo,revision_esperada:version},'PATCH');setCurrent(decision);onReviewed?.(decision);setDecision(null);setReason('')}
    catch(e){setError((e as Error).message)}finally{setBusy(false)}
  }
  return <div className="mt-2">
    <span className={'badge '+(current==='pendiente'?'warn':'')} aria-live="polite">
      {observable?reviewLabels[current]:automatic?(current==='pendiente'?'Sin revisión administrativa':current==='confirmado'?'Confirmada en revisión':'Descartada en revisión'):mappingReviewLabels[current]}
    </span>
    {session?.usuario.rol==='administrador'&&<div className="flex flex-wrap gap-2 mt-2">
      {canConfirm&&<button className="btn text-xs" disabled={busy} onClick={()=>choose('confirmado')}>{observable?'Confirmar relevancia':'Confirmar mapeo'}</button>}
      <button className="btn text-xs" disabled={busy} onClick={()=>choose('descartado')}>{observable?'Descartar relevancia':'Descartar mapeo'}</button>
    </div>}
    {decision&&<div className="mt-2">
      <label className="block text-xs muted" htmlFor={`review-${id}`}>Motivo de la revisión</label>
      <textarea id={`review-${id}`} className="w-full bg-[#0d192a] border line rounded p-2 mt-1 text-sm" maxLength={500} value={reason} onChange={e=>setReason(e.target.value)}/>
      <div className="flex gap-2 mt-2">
        <button className="btn text-xs" disabled={busy||reason.trim().length<10} onClick={review}>Guardar revisión</button>
        <button className="btn text-xs" disabled={busy} onClick={()=>{setDecision(null);setReason('');setError('')}}>Cancelar</button>
      </div>
    </div>}
    {error&&<p role="alert" className="text-red-300 text-xs mt-2">{error}</p>}
  </div>
}
