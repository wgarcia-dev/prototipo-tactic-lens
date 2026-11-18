import {useEffect,useRef,useState} from 'react'
import {api} from '../auth/client'

type Candidate={codigo_tecnica:string,nombre:string,definicion:string,observabilidad:string,puntuacion_hibrida:number,tacticas:{codigo_tactica:string,nombre:string}[]}
type Results={catalogo:{version:string},modelo_embeddings:{nombre:string},candidatos:Candidate[],representacion:{acciones:string[]}}

export function RagCandidates({sessionId}:{sessionId?:string}){
  const [result,setResult]=useState<Results|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState('')
  const pending=useRef<AbortController|null>(null)
  useEffect(()=>{setResult(null);setError('');setBusy(false);return()=>pending.current?.abort()},[sessionId])
  async function consult(){
    if(!sessionId||busy)return
    const controller=new AbortController();pending.current=controller;setBusy(true);setError('')
    try{const data=await api<Results>('/sesiones/'+sessionId+'/mitre/candidatos',{method:'POST',signal:controller.signal});if(!controller.signal.aborted)setResult(data)}
    catch(e){if(!controller.signal.aborted)setError((e as Error).message)}
    finally{if(!controller.signal.aborted)setBusy(false)}
  }
  return <section className="panel p-5 mt-5" aria-label="Buscador RAG MITRE">
    <div className="flex flex-wrap gap-3 justify-between items-start"><div><h2 className="font-semibold">Catálogo MITRE · búsqueda híbrida</h2><p className="muted text-xs mt-1">Consulta local de evidencias y definiciones oficiales. No llama a DeepSeek.</p></div><button className="btn-secondary text-xs" disabled={!sessionId||busy} onClick={consult}>{busy?'Recuperando candidatos…':'Consultar candidatos'}</button></div>
    {error&&<p className="text-red-200 text-sm mt-4" role="alert">{error}</p>}
    {result&&<><p className="muted text-xs mt-4">ATT&CK {result.catalogo.version} · {result.candidatos.length} candidatos · relevancia RRF, no probabilidad de ataque. La clasificación requiere análisis manual y revisión humana.</p><ul className="space-y-3 mt-4">{result.candidatos.map(row=><li key={row.codigo_tecnica} className="border-t line pt-3"><div className="flex flex-wrap gap-2 items-center"><strong className="accent text-sm">{row.codigo_tecnica} · {row.nombre}</strong><span className="badge">{row.observabilidad==='intento_evaluable'?'Intento evaluable':'Fuera de cobertura actual'}</span></div><p className="text-xs muted mt-2">{row.tacticas.map(t=>t.codigo_tactica+' '+t.nombre).join(' · ')}</p><p className="text-xs mt-2">{row.definicion.slice(0,350)}{row.definicion.length>350?'…':''}</p><p className="text-xs muted mt-2">Relevancia RRF: {row.puntuacion_hibrida.toFixed(4)}</p></li>)}</ul></>}
  </section>
}
