export type AnalysisPayload = {
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
      eventos: number[];
    }[];
    hipotesis: {descripcion: string; confianza: number; eventos: number[]}[];
    conclusion: string;
    limitaciones: string[];
    recomendaciones: string[];
  };
};

type Narrative = {
  resumen: string | null;
  mensaje_error: string | null;
  resultado_estructurado?: AnalysisPayload;
};

export function hasDetailedReport(analysis: Narrative) {
  return !!analysis.resultado_estructurado?.informe;
}

function Evidence({events}: {events: number[]}) {
  return <p className="muted text-xs mt-3 break-words">Evidencia: {events.map(id => `#${id}`).join(', ')}</p>;
}

export function AnalysisNarrative({analysis}: {analysis: Narrative}) {
  const report = analysis.resultado_estructurado?.informe;
  const context = analysis.resultado_estructurado?.contexto_observado;
  return <div className="space-y-5 text-sm leading-6 min-w-0">
    <section>
      <h3 className="font-semibold mb-2">Resumen del comportamiento observado</h3>
      <p className="whitespace-pre-wrap break-words">{analysis.resumen || analysis.mensaje_error}</p>
    </section>
    {report ? <>
      {context && <dl className="grid grid-cols-2 gap-x-4 gap-y-3 border-y line py-3 text-xs">
        <div><dt className="muted">Eventos examinados</dt><dd className="font-semibold">{context.eventos}</dd></div>
        <div><dt className="muted">Comandos registrados</dt><dd className="font-semibold">{context.comandos}</dd></div>
        <div><dt className="muted">Autenticaciones en Cowrie</dt><dd>{context.autenticaciones_exitosas} exitosas · {context.autenticaciones_fallidas} fallidas</dd></div>
        <div><dt className="muted">Ventana observada</dt><dd>{context.duracion_observada_segundos.toLocaleString('es-EC', {maximumFractionDigits: 2})} s</dd></div>
      </dl>}
      <section>
        <h3 className="font-semibold mb-2">Contexto y alcance</h3>
        <p className="muted whitespace-pre-wrap break-words">{report.contexto}</p>
      </section>
      <section>
        <h3 className="font-semibold mb-4">Reconstrucción del comportamiento</h3>
        <ol className="space-y-5 border-l border-[#2d5470] ml-2">
          {report.fases.map((phase, index) => <li key={index} className="pl-5 min-w-0">
            <h4 className="font-semibold accent">{index + 1}. {phase.fase}</h4>
            <dl className="mt-2 space-y-2 break-words">
              <div><dt className="text-xs font-semibold">Hechos observados</dt><dd className="whitespace-pre-wrap">{phase.observado}</dd></div>
              <div><dt className="text-xs font-semibold">Interpretación técnica</dt><dd className="muted whitespace-pre-wrap">{phase.interpretacion}</dd></div>
              <div><dt className="text-xs font-semibold">Resultado y evidencia disponible</dt><dd className="whitespace-pre-wrap">{phase.resultado}</dd></div>
            </dl>
            <Evidence events={phase.eventos}/>
          </li>)}
        </ol>
      </section>
      {report.hipotesis.length > 0 && <section>
        <h3 className="font-semibold mb-2">Objetivos probables · hipótesis</h3>
        <p className="muted text-xs mb-3">Inferencias del modelo que requieren revisión; la confianza no es una probabilidad calibrada.</p>
        <ul className="space-y-4">{report.hipotesis.map((hypothesis, index) => <li key={index} className="border-l-2 border-[#2d5470] pl-3">
          <p className="whitespace-pre-wrap break-words">{hypothesis.descripcion}</p>
          <p className="text-xs muted mt-1">Confianza estimada: {Math.round(hypothesis.confianza * 100)}%</p>
          <Evidence events={hypothesis.eventos}/>
        </li>)}</ul>
      </section>}
      <section className="border-t line pt-4">
        <h3 className="font-semibold mb-2">Conclusión del análisis</h3>
        <p className="whitespace-pre-wrap break-words">{report.conclusion}</p>
      </section>
      <section>
        <h3 className="font-semibold mb-2">Limitaciones de la evidencia</h3>
        <ul className="list-disc pl-5 space-y-2 muted break-words">{report.limitaciones.map((item, index) => <li key={index}>{item}</li>)}</ul>
      </section>
      {report.recomendaciones.length > 0 && <details className="border-t line pt-3">
        <summary className="cursor-pointer font-semibold">Comprobaciones recomendadas</summary>
        <ul className="list-disc pl-5 mt-3 space-y-2 muted break-words">{report.recomendaciones.map((item, index) => <li key={index}>{item}</li>)}</ul>
      </details>}
    </> : <p className="muted text-xs">Este resultado conserva el formato anterior. «Ampliar análisis» solicita un nuevo informe al proveedor y mantiene el resultado previo guardado.</p>}
  </div>;
}
