import {useEffect,useState} from 'react'
import {api,apiBlob} from '../../auth/client'

type Report = {title:string;status:string;snapshot:string;metadata:[string,string][];
  sections:{title:string;paragraphs:string[];columns:string[];rows:string[][]}[]}

export function ResponseReport({path}:{path:string}) {
  const [open,setOpen]=useState(false), [report,setReport]=useState<Report>(), [error,setError]=useState('')
  const [refresh,reload]=useState(0), [downloading,setDownloading]=useState(false)
  useEffect(()=>{
    if(!open)return
    const request=new AbortController()
    setReport(undefined);setError('')
    api<Report>(path+'/informe',{signal:request.signal}).then(result=>{if(!request.signal.aborted)setReport(result)})
      .catch(failure=>{if(!request.signal.aborted)setError(failure.message)})
    return ()=>request.abort()
  },[path,open,refresh])

  async function download(format:'pdf'|'docx') {
    if(!report)return
    setDownloading(true);setError('')
    try {
      const query=new URLSearchParams({formato:format,snapshot:report.snapshot})
      const url=URL.createObjectURL(await apiBlob(path+'/informe?'+query))
      const anchor=document.createElement('a')
      anchor.href=url;anchor.download='TacticLens-respuesta.'+format;anchor.click()
      window.setTimeout(()=>URL.revokeObjectURL(url),30000)
    } catch(failure) {setError((failure as Error).message)}
    finally {setDownloading(false)}
  }
  return <section className="panel p-4 space-y-3">
    <div className="flex justify-between flex-wrap gap-2"><h2 className="font-semibold">Informe de incidente</h2>
      <button className="btn-secondary" aria-expanded={open} onClick={()=>setOpen(!open)}>{open?'Cerrar vista previa':'Ver informe'}</button></div>
    {open&&<>
      {error&&<p role="alert">{error}</p>}
      {!report&&!error&&<p role="status" className="muted">Cargando informe…</p>}
      <div className="flex flex-wrap gap-2">
        <button className="btn-secondary" onClick={()=>reload(value=>value+1)}>Actualizar vista previa</button>
        {report&&<><button className="btn" disabled={downloading} onClick={()=>void download('pdf')}>Descargar PDF</button>
          <button className="btn" disabled={downloading} onClick={()=>void download('docx')}>Descargar DOCX</button></>}
      </div>
      {report&&<article className="border line rounded p-4 space-y-4 break-words">
        <h3 className="text-xl font-semibold">{report.title}</h3><p>{report.status}</p>
        <dl className="grid sm:grid-cols-2 gap-2 text-sm">{report.metadata.map(([key,value])=>
          <div key={key}><dt className="font-semibold">{key}</dt><dd>{value}</dd></div>)}</dl>
        {report.sections.map(section=><section key={section.title} className="space-y-2">
          <h4 className="font-semibold">{section.title}</h4>
          {section.paragraphs.map((value,index)=><p key={index} className="text-sm whitespace-pre-wrap">{value}</p>)}
          {!!section.rows.length&&<div className="overflow-auto max-h-80"><table className="w-full text-sm text-left">
            <thead><tr>{section.columns.map(column=><th className="p-2" scope="col" key={column}>{column}</th>)}</tr></thead>
            <tbody>{section.rows.map((row,index)=><tr className="border-t line" key={index}>
              {row.map((cell,i)=><td className="p-2 whitespace-pre-wrap" key={i}>{cell}</td>)}</tr>)}</tbody>
          </table></div>}
        </section>)}
      </article>}
    </>}
  </section>
}
