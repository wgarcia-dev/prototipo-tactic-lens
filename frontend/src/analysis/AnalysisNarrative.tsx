import './session-narrative.css'
import {BookOpen, Compass, GitBranch, Search, ShieldAlert, Fingerprint, ShieldCheck} from 'lucide-react'
import {Link} from 'react-router-dom'
import {eventEvidencePath} from './iocEvidence'
import {IncidentAssessment, type Assessment} from './IncidentAssessment'

export type AnalysisPayload = {
  evaluacion_incidente?: Assessment;
  rag?:{metodo:string,catalogo:{version:string}}
  eventos_analizados?: number;
  version_informe?: number;
  enriquecimiento?: {generado_en:string; fuentes:Record<string,boolean>; observables:{tipo:string; valor:string; alcance_ip?:string|null; eventos:number[]; proveedores:Record<string,{estado:string; consultado_en?:string; url?:string; id?:string; resultado?:string}|{id:string; nombre:string; version?:number; categoria:string; url:string; consultado_en:string}[]>}[]};
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
      eventos: number[]; eventos_texto?: string[];
    }[];
    hipotesis: {descripcion: string; confianza: number; eventos: number[]; eventos_texto?: string[]}[];
    conclusion: string;
    limitaciones: string[];
    recomendaciones: (string | {salvaguarda:string; activo:string; riesgo:string; objetivo:string; medidas:string; validacion:string})[];
  };
};

type Narrative = {
  id_analisis: string;
  id_sesion: string;
  salvaguardas?: {title:string; rows:[string,string][]}[];
  resumen: string | null;
  mensaje_error: string | null;
  resultado_estructurado?: AnalysisPayload;
};

export function hasCurrentReport(analysis: Narrative) {
  return !!analysis.resultado_estructurado?.informe && (analysis.resultado_estructurado.version_informe ?? 0) >= 5;
}

function Evidence({events, session}: {events: string[]; session: string}) {
  return <p className="muted text-xs mt-3 break-words">Evidencia: {events.map(id => <Link className="accent underline mr-2" key={id} to={eventEvidencePath(session,id)}>Evento #{id}</Link>)}</p>;
}

export function AnalysisNarrative({analysis}: {analysis: Narrative}) {
  const report = analysis.resultado_estructurado?.informe;
  const context = analysis.resultado_estructurado?.contexto_observado;
  const enrichment = analysis.resultado_estructurado?.enriquecimiento;
  const cards = analysis.salvaguardas?.length ? analysis.salvaguardas : (report?.recomendaciones ?? []).map((item,index)=>{
    const proposal = typeof item === 'string' ? {salvaguarda:item} : item;
    const rows:[string,string][] = [
      ['Código','SG-'+String(index+1).padStart(3,'0')],
      ['Activo','activo' in proposal ? proposal.activo : 'Por identificar'],
      ['Riesgo','riesgo' in proposal ? proposal.riesgo : 'Por caracterizar'],
      ['Nivel de riesgo inicial','Pendiente de valorar probabilidad e impacto'],
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


    {report ? <>
      {context && <dl className="grid grid-cols-2 lg:grid-cols-4 gap-x-4 gap-y-3 border-y line py-3 text-xs">
        <div><dt className="muted">Eventos examinados</dt><dd className="font-semibold">{context.eventos}</dd></div>
        <div><dt className="muted">Comandos registrados</dt><dd className="font-semibold">{context.comandos}</dd></div>
        <div><dt className="muted">Autenticaciones en Cowrie</dt><dd>{context.autenticaciones_exitosas} exitosas · {context.autenticaciones_fallidas} fallidas</dd></div>
        <div><dt className="muted">Ventana observada</dt><dd>{context.duracion_observada_segundos.toLocaleString('es-EC', {maximumFractionDigits: 2})} s</dd></div>
      </dl>}
      <div className="session-findings">
      <details>
        <summary className="cursor-pointer font-semibold"><BookOpen size={18} aria-hidden/>Conclusión del análisis</summary>
        <p className="whitespace-pre-wrap break-words">{report.conclusion}</p>
      </details>

      <details className="py-2">
        <summary className="font-semibold cursor-pointer"><Compass size={18} aria-hidden/>Contexto y alcance</summary>
        <p className="muted whitespace-pre-wrap break-words">{report.contexto}</p>
      </details>
      <details className="py-2">
        <summary className="font-semibold cursor-pointer"><GitBranch size={18} aria-hidden/>Reconstrucción del comportamiento ({report.fases.length} fases)</summary>
        <ol className="space-y-1 border-l line ml-2 mt-2">
          {report.fases.map((phase, index) => <li key={index} className="pl-5 min-w-0">
            <details><summary className="font-semibold accent cursor-pointer py-1">{index + 1}. {phase.fase}</summary>
            <dl className="mt-2 space-y-2 break-words">
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
          <ul className="mt-2 text-xs space-y-1">{Object.entries(item.proveedores).flatMap(([name,result])=>Array.isArray(result)
            ? result.map(match=><li key={name+match.id}>MISP Warning Lists: <a className="accent underline" href={match.url} target="_blank" rel="noreferrer">{match.nombre}</a> · {match.categoria} · versión {match.version ?? 's/d'} · {new Date(match.consultado_en).toLocaleString('es-EC')}</li>)
            : [<li key={name}>{name}: {result.estado==='omitido' ? (name==='urlhaus' ? 'Se requiere el SHA-256 de un archivo para consultar esta fuente.' : 'IP de alcance local. Verifique su origen en los registros de la red del sensor.') : result.estado} {result.consultado_en&&`· ${new Date(result.consultado_en).toLocaleString('es-EC')}`} {result.id&&`· ID ${result.id}`} {result.url&&<a className="accent underline ml-2" href={result.url} target="_blank" rel="noreferrer">Fuente</a>}</li>])}</ul>
        </div>)}
        {!enrichment.observables.length&&<p className="muted text-xs">No se extrajeron observables aptos para enriquecimiento.</p>}
      </div> : <p className="muted text-xs mt-2">Análisis histórico: no se registró enriquecimiento externo.</p>}
    </details>
    <section aria-label="Salvaguardas" className="border-t line pt-3">
      <h3 className="font-semibold"><ShieldCheck size={20} aria-hidden/>Ficha de propuesta de salvaguarda</h3>
      {cards.map(card=><details key={card.rows[0][1]} className="mt-2 border line rounded-lg p-3">
        <summary className="cursor-pointer"><strong className="accent">{card.rows[0][1]}</strong> · {card.title}</summary>
        <dl className="mt-3">{card.rows.map(([label,value])=><div key={label} className="grid sm:grid-cols-[12rem_1fr] gap-x-3 border-t line py-1">
          <dt className="font-semibold">{label}</dt><dd>{value}</dd></div>)}</dl>
      </details>)}
      {!cards.length && <p className="muted">Este análisis no contiene propuestas de salvaguarda.</p>}
    </section>
    <IncidentAssessment key={analysis.id_analisis} id={analysis.id_analisis} session={analysis.id_sesion} initial={analysis.resultado_estructurado?.evaluacion_incidente}/>
  </div>;
}
