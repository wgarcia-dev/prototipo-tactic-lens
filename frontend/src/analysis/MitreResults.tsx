import {Link} from 'react-router-dom'
import {MappingBasis, MappingStatus, type MappingEvidence} from './IocCorrelations'
import {isAutomaticMapping, mappingEvidencePath, sessionEvidencePath} from './iocEvidence'
import type {AnalysisPayload} from './AnalysisNarrative'

type Result = {
  id_sesion:string
  estado:string
  resultado_estructurado?:AnalysisPayload
}

function ResultsList({mappings,session}: {mappings:MappingEvidence[];session:string}) {
  return <ul className="space-y-3 mt-3">
    {mappings.map(mapping=><li key={mapping.id_mapeo} className="border-l line pl-3 text-sm break-words">
      <div className="flex flex-wrap items-baseline gap-2">
        <Link className="accent font-semibold hover:underline" to={mappingEvidencePath(mapping.id_mapeo,{technique:mapping.codigo_tecnica,session})}>
          {mapping.codigo_tecnica} · {mapping.tecnica}
        </Link>
        <MappingStatus mapping={mapping}/>
      </div>
      <MappingBasis mapping={mapping}/>
    </li>)}
  </ul>
}

export function MitreResults({analysis,mappings}: {analysis:Result;mappings:MappingEvidence[]}) {
  const classification=analysis.resultado_estructurado?.clasificacion_mitre
  const unique=[...new Map(mappings.map(mapping=>[mapping.id_mapeo,mapping])).values()]
  const identified=unique.filter(mapping=>isAutomaticMapping(mapping)&&mapping.estado_revision!=='descartado')
  const archived=unique.filter(mapping=>!isAutomaticMapping(mapping)||mapping.estado_revision==='descartado')
  return <section aria-label="Técnicas MITRE identificadas" className="border-t line pt-4 my-5">
    <div className="flex flex-wrap gap-2 justify-between items-baseline">
      <h3 className="font-semibold">Técnicas MITRE identificadas</h3>
      <Link className="accent text-xs hover:underline" to={sessionEvidencePath(analysis.id_sesion)}>Abrir sesión</Link>
    </div>
    {analysis.estado==='fallido' ? <p role="alert" className="text-sm text-red-200 mt-2">Análisis fallido.</p> :
      analysis.estado==='completado'&&<>
        {identified.length>0 ? <ResultsList mappings={identified} session={analysis.id_sesion}/> :
          <p className="muted text-sm mt-2"><strong>No determinada.</strong>{' '}
            {classification?.motivo || (archived.length ? 'Esta vista conserva mapeos históricos o descartados.' : 'El análisis guardado no contiene técnicas identificadas con evidencia suficiente.')}
            {!!classification?.candidatas_no_validadas && ' Hay candidatas guardadas para diagnóstico.'}
          </p>}
        {archived.length>0&&<details className="mt-3" open={identified.length===0}>
          <summary className="cursor-pointer text-sm">Mapeos históricos y descartados ({archived.length})</summary>
          <ResultsList mappings={archived} session={analysis.id_sesion}/>
        </details>}
      </>}
  </section>
}
