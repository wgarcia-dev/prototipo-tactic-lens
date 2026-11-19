import {Link} from 'react-router-dom'
import {eventEvidencePath} from './iocEvidence'

export type AnalysisPayload = {
  rag?:{metodo:string,catalogo:{version:string}}
  eventos_analizados?: number;
  version_informe?: number;
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
  id_sesion: string;
  salvaguardas?: {title:string; rows:[string,string][]}[];
  resumen: string | null;
  mensaje_error: string | null;
  resultado_estructurado?: AnalysisPayload;
};

export function hasCurrentReport(analysis: Narrative) {
  return !!analysis.resultado_estructurado?.informe && (analysis.resultado_estructurado.version_informe ?? 0) >= 3;
}

function Evidence({events, session}: {events: string[]; session: string}) {
  return <p className="muted text-xs mt-3 break-words">Evidencia: {events.map(id => <Link className="accent underline mr-2" key={id} to={eventEvidencePath(session,id)}>Evento #{id}</Link>)}</p>;
}

export function AnalysisNarrative({analysis}: {analysis: Narrative}) {
  const report = analysis.resultado_estructurado?.informe;
  const context = analysis.resultado_estructurado?.contexto_observado;
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
  return <div className="space-y-5 text-sm leading-6 min-w-0">
    <section>
      <h3 className="font-semibold mb-2">Resumen del comportamiento observado</h3>
      <p className="whitespace-pre-wrap break-words">{analysis.resumen || analysis.mensaje_error}</p>
    </section>
    <section aria-label="Salvaguardas" className="border-t line pt-3">
      <h3 className="font-semibold">Ficha de propuesta de salvaguarda</h3>
      {cards.map((card,index)=><details open={index===0} key={card.rows[0][1]} className="mt-2 border line rounded-lg p-3">
        <summary className="cursor-pointer"><strong className="accent">{card.rows[0][1]}</strong> · {card.title}</summary>
        <dl className="mt-3">{card.rows.map(([label,value])=><div key={label} className="grid sm:grid-cols-[12rem_1fr] gap-x-3 border-t line py-1">
          <dt className="font-semibold">{label}</dt><dd>{value}</dd></div>)}</dl>
      </details>)}
      {!cards.length && <p className="muted">Este análisis no contiene propuestas de salvaguarda.</p>}
    </section>
    {report ? <>
      {context && <dl className="grid grid-cols-2 gap-x-4 gap-y-3 border-y line py-3 text-xs">
        <div><dt className="muted">Eventos examinados</dt><dd className="font-semibold">{context.eventos}</dd></div>
        <div><dt className="muted">Comandos registrados</dt><dd className="font-semibold">{context.comandos}</dd></div>
        <div><dt className="muted">Autenticaciones en Cowrie</dt><dd>{context.autenticaciones_exitosas} exitosas · {context.autenticaciones_fallidas} fallidas</dd></div>
        <div><dt className="muted">Ventana observada</dt><dd>{context.duracion_observada_segundos.toLocaleString('es-EC', {maximumFractionDigits: 2})} s</dd></div>
      </dl>}
      <section>
        <h3 className="font-semibold mb-1">Conclusión del análisis</h3>
        <p className="whitespace-pre-wrap break-words">{report.conclusion}</p>
      </section>
      <div className="divide-y border-y line">
      <details className="py-2">
        <summary className="font-semibold cursor-pointer">Contexto y alcance</summary>
        <p className="muted whitespace-pre-wrap break-words">{report.contexto}</p>
      </details>
      <details className="py-2">
        <summary className="font-semibold cursor-pointer">Reconstrucción del comportamiento ({report.fases.length} fases)</summary>
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
        <summary className="font-semibold cursor-pointer">Hipótesis del modelo ({report.hipotesis.length})</summary>
        <p className="muted text-xs mb-3">Inferencias del modelo que requieren revisión; la confianza no es una probabilidad calibrada.</p>
        <ul className="space-y-4">{report.hipotesis.map((hypothesis, index) => <li key={index} className="border-l-2 border-[#2d5470] pl-3">
          <p className="whitespace-pre-wrap break-words">{hypothesis.descripcion}</p>
          <p className="text-xs muted mt-1">Confianza estimada: {Math.round(hypothesis.confianza * 100)}%</p>
          <Evidence session={analysis.id_sesion} events={hypothesis.eventos_texto ?? hypothesis.eventos.filter(Number.isSafeInteger).map(String)}/>
        </li>)}</ul>
      </details>}
      <details className="py-2">
        <summary className="font-semibold cursor-pointer">Limitaciones de la evidencia ({report.limitaciones.length})</summary>
        <ul className="list-disc pl-5 space-y-2 muted break-words">{report.limitaciones.map((item, index) => <li key={index}>{item}</li>)}</ul>
      </details>
      </div>
    </> : <p className="muted text-xs">Este resultado conserva el formato anterior. «Ampliar análisis» solicita un nuevo informe al proveedor y mantiene el resultado previo guardado.</p>}
  </div>;
}
