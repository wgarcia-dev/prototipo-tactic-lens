import './session-narrative.css'
import {BookOpen, Compass, GitBranch, Search, ShieldAlert, Fingerprint, ShieldCheck} from 'lucide-react'
import {Link} from 'react-router-dom'
import {enrichmentStatusLabel,eventEvidencePath} from './iocEvidence'
import {IncidentAssessment, type Assessment} from './IncidentAssessment'

type AnalyticalSection = {title:string; paragraphs:string[]; columns:string[]; rows:string[][]};
type Severity = 'S0'|'S1'|'S2'|'S3'|'S4'|'No evaluable';
type WarningMatch={id:string; nombre:string; version?:number; categoria:string; url:string; consultado_en:string};
type EnrichmentStatus={estado:string; consultado_en?:string; url?:string; id?:string; coincidencias?:WarningMatch[]};

export type AnalysisPayload = {
  version_esquema?: number;
  evaluacion_amenaza?: {codigo_severidad:Severity; severidad_preliminar:string; prioridad_investigacion:string|null; confianza_evaluacion:{nivel:string}};

  clasificacion_mitre?: {estado:'identificada_automaticamente'|'no_determinada'; modalidad:string; motivo?:string|null; candidatas_no_validadas?:number};
  evaluacion_incidente?: Assessment;
  rag?:{metodo:string,catalogo?:{version:string},modelo_llm?:{proveedor:string;modelo:string}}
  eventos_analizados?: number;
  version_informe?: number;
  enriquecimiento?: {generado_en:string; fuentes:Record<string,boolean>; observables:{tipo:string; valor:string; alcance_ip?:string|null; eventos:number[]; proveedores:Record<string,EnrichmentStatus|WarningMatch[]>}[]};
  contexto_observado?: {
    eventos: number;
    inicio: string | null;
    fin: string | null;
    duracion_observada_segundos: number;
    comandos: number;
    autenticaciones_exitosas: number;
    autenticaciones_fallidas: number;
  };
  informe?: {
    contexto: string;
    fases: {
      fase: string;
      observado: string;
      interpretacion: string;
      resultado: string;
      orden?:number;
      inicio_fase?:string;
      fin_fase?:string;
      estado_resultado?:string;
      eventos: number[]; eventos_texto?: string[];
    }[];
    hipotesis: {descripcion: string; confianza: number; eventos: number[]; eventos_texto?: string[];
      objetivo_probable?:string|null; objetivo_inmediato?:string; confianza_analitica?:{nivel:string};
      recursos_interes?:string[]}[];
    conclusion: string;
    limitaciones: string[];
    recomendaciones: (string | {salvaguarda:string; activo:string; riesgo:string; objetivo:string; medidas:string; validacion:string})[];
  };
};

type Narrative = {
  id_analisis: string;
  id_sesion: string;
  presentacion_analitica?: AnalyticalSection[];
  salvaguardas?: {title:string; id?:string; rows:[string,string][]}[];
  resumen: string | null;
  mensaje_error: string | null;
  resultado_estructurado?: AnalysisPayload;
};

export function hasCurrentReport(analysis: Narrative) {
  return !!analysis.resultado_estructurado?.informe && (analysis.resultado_estructurado.version_informe ?? 0) >= 6 && !!analysis.resultado_estructurado.version_esquema;
}

const phaseStatus:Record<string,string> = {
  registrado:'Registro acreditado', intento:'Solicitud documentada', resultado_observado:'Resultado observado por el sensor',
  fallido:'Fallo registrado', no_determinable:'Evidencia insuficiente'
};
const phaseTime = (value:string) => new Date(value).toLocaleString('es-EC',{
  timeZone:'America/Guayaquil', dateStyle:'short', timeStyle:'medium'
});

function Evidence({events, session}: {events: string[]; session: string}) {
  return <p className="muted text-xs mt-3 break-words">Evidencia: {events.map(id => <Link className="accent underline mr-2" key={id} to={eventEvidencePath(session,id)}>Evento #{id}</Link>)}</p>;
}

function EvidencedText({value, session}: {value:string; session:string}) {
  return <>{value.split(/(#\d+)/).map((part,index) => /^#\d+$/.test(part)
    ? <Link className="accent underline" key={index} to={eventEvidencePath(session,part.slice(1))}>{part}</Link> : part)}</>;
}

function EvaluationSections({sections, session}: {sections:AnalyticalSection[]; session:string}) {
  return <div className="session-findings">
    {sections.map(section => <details key={section.title}>
      <summary className="cursor-pointer font-semibold">{section.title}</summary>
      <div className="p-2 space-y-2">
        {section.paragraphs.filter(Boolean).map((paragraph,index) => <p key={index}><EvidencedText value={paragraph} session={session}/></p>)}
        {section.rows.length > 0 && <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead><tr>{section.columns.map(column=><th key={column} scope="col" className="p-2">{column}</th>)}</tr></thead>
            <tbody>{section.rows.map((row,index)=><tr key={index} className="border-t line">
              {row.map((cell,i)=><td key={i} className="p-2 align-top break-words whitespace-pre-line"><EvidencedText value={cell}
                session={section.columns[i] === 'Eventos de sesión asociada' ? row[0] : session}/></td>)}
            </tr>)}</tbody>
          </table>
        </div>}
      </div>
    </details>)}
  </div>;
}

export function AnalysisNarrative({analysis}: {analysis: Narrative}) {
  const assessment = analysis.resultado_estructurado?.evaluacion_amenaza;
  const report = analysis.resultado_estructurado?.informe;
  const context = analysis.resultado_estructurado?.contexto_observado;
  const enrichment = analysis.resultado_estructurado?.enriquecimiento;
  const cards:NonNullable<Narrative['salvaguardas']> = analysis.salvaguardas ?? (report?.recomendaciones ?? []).map((item,index)=>{
    const proposal = typeof item === 'string' ? {salvaguarda:item} : item;
    const rows:[string,string][] = [
      ['Código','SG-'+String(index+1).padStart(3,'0')],
      ['Activo','activo' in proposal ? proposal.activo : 'Por identificar'],
      ['Riesgo','riesgo' in proposal ? proposal.riesgo : 'Por caracterizar'],
      ['Riesgo inicial técnico','Sin nivel individual sustentado'],
      ['Salvaguarda',proposal.salvaguarda],
      ['Objetivo','objetivo' in proposal ? proposal.objetivo : 'Por definir'],
      ['Medidas','medidas' in proposal ? proposal.medidas : 'Por concretar'],
      ['Responsable','Por asignar'],['Prioridad','Pendiente de valoración'],
      ['Validación','validacion' in proposal ? proposal.validacion : 'Por definir con el analista'],
      ['Estado','Propuesta, pendiente de aprobación']
    ];
    return {title:proposal.salvaguarda,rows};
  });
  return <div className="session-narrative text-sm leading-6 min-w-0">

    <section>
      <h3 className="font-semibold mb-2">Resumen del comportamiento observado</h3>
      <p className="whitespace-pre-wrap break-words">{analysis.resumen || analysis.mensaje_error}</p>
    </section>


    {assessment && <div className="flex flex-wrap gap-2" aria-label="Valoración técnica preliminar">
      <span className="badge analysis-severity" data-severity={assessment.codigo_severidad}>{assessment.codigo_severidad} · {assessment.severidad_preliminar}</span>
      {assessment.prioridad_investigacion && <span className="badge">Prioridad {assessment.prioridad_investigacion}</span>}
      <span className="badge">Confianza {assessment.confianza_evaluacion.nivel}</span>
    </div>}
    {analysis.presentacion_analitica?.length ? <EvaluationSections sections={analysis.presentacion_analitica} session={analysis.id_sesion}/> : null}
    {report && !assessment && <p className="muted text-xs">Resultado histórico. Conserva la interpretación de su versión original.</p>}

    {report ? <>
      {context && <dl className="grid grid-cols-2 lg:grid-cols-4 gap-x-4 gap-y-3 border-y line py-3 text-xs">
        <div><dt className="muted">Eventos examinados</dt><dd className="font-semibold">{context.eventos}</dd></div>
        <div><dt className="muted">Comandos registrados</dt><dd className="font-semibold">{context.comandos}</dd></div>
        <div><dt className="muted">Autenticaciones en Cowrie</dt><dd>{context.autenticaciones_exitosas} exitosas · {context.autenticaciones_fallidas} fallidas</dd></div>
        <div><dt className="muted">Ventana observada</dt><dd>{context.duracion_observada_segundos.toLocaleString('es-EC', {maximumFractionDigits: 2})} s</dd></div>
      </dl>}
      <div className="session-findings">
      {!analysis.presentacion_analitica?.some(section => section.title === 'Conclusiones del análisis') && <details>
        <summary className="cursor-pointer font-semibold"><BookOpen size={18} aria-hidden/>Conclusión del análisis</summary>
        <p className="whitespace-pre-wrap break-words">{report.conclusion}</p>
      </details>}

      <details className="py-2">
        <summary className="font-semibold cursor-pointer"><Compass size={18} aria-hidden/>Contexto y alcance</summary>
        <p className="muted whitespace-pre-wrap break-words">{report.contexto}</p>
      </details>
      <details className="py-2">
        <summary className="font-semibold cursor-pointer"><GitBranch size={18} aria-hidden/>Reconstrucción del comportamiento ({report.fases.length} fases)</summary>
        <ol className="space-y-1 border-l line ml-2 mt-2">
          {report.fases.map((phase, index) => <li key={index} className="pl-5 min-w-0">
            <details><summary className="font-semibold accent cursor-pointer py-1">{phase.orden ?? index + 1}. {phase.fase}</summary>
            <dl className="mt-2 space-y-2 break-words">
              {phase.estado_resultado && <div><dt className="text-xs font-semibold">Estado de evidencia</dt>
                <dd>{phaseStatus[phase.estado_resultado] ?? phase.estado_resultado}</dd></div>}
              {phase.inicio_fase && phase.fin_fase && <div><dt className="text-xs font-semibold">Ventana en Ecuador</dt>
                <dd><time dateTime={phase.inicio_fase}>{phaseTime(phase.inicio_fase)}</time> a <time dateTime={phase.fin_fase}>{phaseTime(phase.fin_fase)}</time></dd></div>}
              <div><dt className="text-xs font-semibold">Hechos observados</dt><dd className="whitespace-pre-wrap">{phase.observado}</dd></div>
              <div><dt className="text-xs font-semibold">Interpretación técnica</dt><dd className="muted whitespace-pre-wrap">{phase.interpretacion}</dd></div>
              <div><dt className="text-xs font-semibold">Resultado y evidencia disponible</dt><dd className="whitespace-pre-wrap">{phase.resultado}</dd></div>
            </dl>
            <Evidence session={analysis.id_sesion} events={phase.eventos_texto ?? phase.eventos.filter(Number.isSafeInteger).map(String)}/>
            </details>
          </li>)}
        </ol>
      </details>
      {report.hipotesis.length > 0 && <details className="py-2">
        <summary className="font-semibold cursor-pointer"><Search size={18} aria-hidden/>Hipótesis por verificar ({report.hipotesis.length})</summary>
        <p className="muted text-xs mb-3">Revise las evidencias y explicaciones alternativas antes de incorporar estas hipótesis a la decisión del incidente.</p>
        <ul className="space-y-4">{report.hipotesis.map((hypothesis, index) => <li key={index} className="border-l-2 border-[#2d5470] pl-3">
          <p className="whitespace-pre-wrap break-words">{hypothesis.descripcion}</p>
          <details className="text-xs muted mt-1"><summary className="cursor-pointer">Estimación declarada por el modelo</summary>{Math.round(hypothesis.confianza * 100)}% · Valor subjetivo pendiente de validación.</details>
          <Evidence session={analysis.id_sesion} events={hypothesis.eventos_texto ?? hypothesis.eventos.filter(Number.isSafeInteger).map(String)}/>
        </li>)}</ul>
      </details>}
      <details className="py-2">
        <summary className="font-semibold cursor-pointer"><ShieldAlert size={18} aria-hidden/>Limitaciones de la evidencia ({report.limitaciones.length})</summary>
        <ul className="list-disc pl-5 space-y-2 muted break-words">{report.limitaciones.map((item, index) => <li key={index}>{item}</li>)}</ul>
      </details>
      </div>
    </> : <p className="muted text-xs">Este resultado conserva el formato anterior. «Ampliar análisis» solicita un nuevo informe al proveedor y mantiene el resultado previo guardado.</p>}
    <details className="border-t line pt-3" aria-label="Fuentes y evidencias">
      <summary className="cursor-pointer font-semibold"><Fingerprint size={18} aria-hidden/>Fuentes y evidencias</summary>
      <p className="muted text-xs mt-1">Los observables provienen de Cowrie. Las coincidencias externas aportan contexto; las interpretaciones del modelo quedan pendientes de revisión humana.</p>
      {enrichment ? <div className="mt-3 space-y-3">
        {enrichment.observables.map((item,index)=><div key={index} className="border line rounded-lg p-3 break-words">
          <p className="font-mono text-xs">{item.tipo}: {item.valor} {item.alcance_ip&&<span className="muted">({item.alcance_ip})</span>}</p>
          <Evidence session={analysis.id_sesion} events={item.eventos.map(String)}/>
          <ul className="mt-2 text-xs space-y-1">{Object.entries(item.proveedores).flatMap(([name,result])=>{
            const matches=Array.isArray(result)?result:result.coincidencias??[]
            const entries=matches.map(match=><li key={name+match.id}>MISP Warning Lists: <a className="accent underline" href={match.url} target="_blank" rel="noreferrer">{match.nombre}</a> · {match.categoria} · versión {match.version ?? 's/d'} · {new Date(match.consultado_en).toLocaleString('es-EC')}</li>)
            if(Array.isArray(result))return entries
            return [<li key={name}>{name}: {result.estado==='omitido' ? 'IP de alcance local. Verifique su origen en los registros de la red del sensor.' : enrichmentStatusLabel(result.estado)} {result.consultado_en&&`· ${new Date(result.consultado_en).toLocaleString('es-EC')}`} {result.id&&`· ID ${result.id}`} {result.url&&<a className="accent underline ml-2" href={result.url} target="_blank" rel="noreferrer">Fuente</a>}</li>,...entries]
          })}</ul>
        </div>)}
        {!enrichment.observables.length&&<p className="muted text-xs">No se extrajeron observables aptos para enriquecimiento.</p>}
      </div> : <p className="muted text-xs mt-2">Análisis histórico: no se registró enriquecimiento externo.</p>}
    </details>
    <section aria-label="Salvaguardas" className="border-t line pt-3">
      <h3 className="font-semibold"><ShieldCheck size={20} aria-hidden/>Ficha de propuesta de salvaguarda</h3>
      {cards.map((card,index)=><details key={card.rows[0][1]+':'+index} className="mt-2 border line rounded-lg p-3">
        <summary className="cursor-pointer"><strong className="accent">{card.rows[0][1]}</strong> · {card.title}</summary>
        <dl className="mt-3">{card.rows.map(([label,value])=><div key={label} className="grid sm:grid-cols-[12rem_1fr] gap-x-3 border-t line py-1">
          <dt className="font-semibold">{label}</dt><dd><EvidencedText value={value} session={analysis.id_sesion}/></dd></div>)}</dl>
        {card.id&&<Link className="accent underline mt-2 inline-block" to={'/salvaguardas?id='+card.id}>Consultar seguimiento</Link>}
      </details>)}
      {cards.length>0&&<Link className="accent underline text-xs inline-block mt-3" to={'/salvaguardas/propuestas?analisis='+analysis.id_analisis}>Ver revisión e historial de las propuestas</Link>}
      {!cards.length && <p className="muted">Este análisis no contiene propuestas de salvaguarda.</p>}
    </section>
    <IncidentAssessment key={analysis.id_analisis} id={analysis.id_analisis} session={analysis.id_sesion} initial={analysis.resultado_estructurado?.evaluacion_incidente}/>
  </div>;
}
