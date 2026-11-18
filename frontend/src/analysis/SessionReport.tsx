import {useEffect, useState} from 'react'
import {Download, FileText} from 'lucide-react'
import {api, apiBlob} from '../auth/client'

type Report = {
  title: string
  reference: string
  status: string
  metadata: [string, string][]
  sections: {title: string, paragraphs: string[], columns: string[], rows: string[][]}[]
}

export function SessionReport({id}: {id: string}) {
  const [open, setOpen] = useState(false)
  const [report, setReport] = useState<Report | null>(null)
  const [error, setError] = useState('')
  const [attempt, setAttempt] = useState(0)
  const [downloading, setDownloading] = useState<'pdf' | 'docx' | null>(null)
  const path = '/sesiones/' + id + '/informe'

  useEffect(() => {
    if (!open) return
    const controller = new AbortController()
    api<Report>(path, {signal: controller.signal}).then(setReport).catch(err => {
      if (!controller.signal.aborted) setError(err.message)
    })
    return () => controller.abort()
  }, [open, path, attempt])

  function refresh() {
    setError('')
    setReport(null)
    setAttempt(value => value + 1)
  }

  async function download(format: 'pdf' | 'docx') {
    setDownloading(format)
    setError('')
    try {
      const blob = await apiBlob(path + '?formato=' + format)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = 'TacticLens-' + id + '.' + format
      link.click()
      window.setTimeout(() => URL.revokeObjectURL(url), 30000)
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setDownloading(null)
    }
  }

  return <section className="panel p-5 mb-5" aria-label="Informe de sesión">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h2 className="font-semibold flex items-center gap-2"><FileText size={17} aria-hidden/> Informe de sesión</h2>
        <p className="muted text-xs mt-1">Cronología de Cowrie, observables y mapeos con evidencia.</p>
      </div>
      <button className="btn-secondary" aria-expanded={open} onClick={() => {
        if (!open) refresh()
        setOpen(!open)
      }}>{open ? 'Cerrar vista previa' : 'Ver informe'}</button>
    </div>
    {open && <div className="mt-5 border-t line pt-5">
      {error && <p role="alert" className="text-sm text-red-200 mb-4">{error}</p>}
      {!report && (error
        ? <button className="btn-secondary" onClick={refresh}>Volver a intentar</button>
        : <p role="status" className="muted text-sm">Cargando informe…</p>)}
      {report && <>
        <div className="flex flex-wrap gap-2 mb-5">
          {(['pdf', 'docx'] as const).map(format =>
            <button key={format} className="btn flex items-center gap-2" disabled={!!downloading}
              onClick={() => download(format)}>
              <Download size={15} aria-hidden/>
              {downloading === format ? 'Generando…' : format === 'pdf' ? 'Descargar PDF' : 'Descargar Word'}
            </button>)}
          <button className="btn-secondary" onClick={refresh}>Actualizar vista</button>
        </div>
        <article className="rounded-md bg-[#f8fafc] text-[#172a40] p-4 sm:p-8 break-words">
          <h3 className="text-2xl font-semibold">{report.title}</h3>
          <p className="text-sm text-[#485c70] mt-1">{report.status}</p>
          <dl className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3 border-y border-slate-300 py-4 my-5 text-sm">
            {report.metadata.map(([name, value]) => <div key={name}>
              <dt className="text-xs font-semibold text-[#485c70]">{name}</dt><dd>{value}</dd>
            </div>)}
          </dl>
          {report.sections.map(section => <section className="mt-6" key={section.title}>
            <h4 className="font-semibold mb-2">{section.title}</h4>
            {section.paragraphs.map((value, i) => <p key={i} className="text-sm mb-2 whitespace-pre-wrap">{value}</p>)}
            {section.rows.length > 0 && <details className="mt-2 border border-slate-300 rounded">
              <summary className="cursor-pointer px-3 py-2 text-sm font-medium">Ver registros ({section.rows.length})</summary>
              <div className="overflow-auto max-h-80">
                <table aria-label={section.title} className="w-full text-sm text-left">
                  <thead className="sticky top-0 bg-[#172a40] text-white"><tr>
                    {section.columns.map(col => <th scope="col" key={col} className="px-3 py-2">{col}</th>)}
                  </tr></thead>
                  <tbody>{section.rows.map((row, i) => <tr key={i} className="even:bg-slate-100">
                    {row.map((cell, j) => <td className="px-3 py-2 align-top max-w-sm break-all" key={j}>{cell}</td>)}
                  </tr>)}</tbody>
                </table>
              </div>
            </details>}
          </section>)}
        </article>
      </>}
    </div>}
  </section>
}
