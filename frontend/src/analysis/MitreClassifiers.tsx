import {useEffect, useState} from 'react'
import {api} from '../auth/client'
import {modalities} from './MitreDashboard'

type Coverage = {version:string;clasificadores:{codigo:string;nombre:string;modalidades:string[];
  minimo_evidencias_distintas:number;limitacion:string;presente_en_catalogo:boolean;version:string;tacticas:string[]}[]}

export function MitreClassifiers() {
  const [data,setData]=useState<Coverage>(), [error,setError]=useState(''), [attempt,setAttempt]=useState(0)
  useEffect(()=>{
    const controller=new AbortController()
    setError('')
    api<Coverage>('/mitre/clasificadores',{signal:controller.signal}).then(setData).catch(failure=>{
      if(!controller.signal.aborted)setError(failure.message)
    })
    return()=>controller.abort()
  },[attempt])
  return <details className="panel p-5">
    <summary className="font-semibold cursor-pointer">Contratos de evidencia MITRE ATT&amp;CK {data&&'('+data.clasificadores.length+')'}</summary>
    <p className="muted text-sm mt-3">El análisis recupera técnicas candidatas del catálogo. Para identificar una técnica automáticamente, la propuesta del modelo debe cumplir su contrato con eventos de la sesión. Si la evidencia es insuficiente, la técnica queda como candidata o el resultado queda sin determinar.</p>
    {error&&<div role="alert"><p>{error}</p><button className="btn-secondary mt-2" onClick={()=>setAttempt(value=>value+1)}>Reintentar</button></div>}
    {!data&&!error&&<p role="status">Cargando cobertura…</p>}
    {data&&<><p className="muted text-xs mt-2">Versión {data.version}</p>
      <ul className="grid md:grid-cols-2 gap-3 mt-4">{data.clasificadores.map(item=><li key={item.codigo} className="border line rounded-lg p-4">
        <p className="font-semibold"><span className="accent">{item.codigo}</span> · {item.nombre}</p>
        <p className="text-xs muted mt-2">{item.modalidades.map(mode=>modalities[mode]).join(' · ')}</p>
        <p className="text-xs mt-2">Mínimo de evidencias distintas · {item.minimo_evidencias_distintas}</p>
        <p className="text-sm mt-2">{item.limitacion}</p>
        {!item.presente_en_catalogo&&<p className="badge warn mt-2">Sin técnica vigente en el catálogo activo</p>}
      </li>)}</ul></>}
  </details>
}
