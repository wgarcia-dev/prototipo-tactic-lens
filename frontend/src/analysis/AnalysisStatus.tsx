export type AnalysisValidity = {
  cobertura_eventos: 'completa' | 'incompleta'
  metodologia: 'vigente' | 'desactualizada' | 'no_verificable'
  evidencia_verificable: boolean
}

export type AttemptStatus = 'sin_analizar' | 'en_proceso' | 'completado' | 'fallido' | 'vencido'

const attempts: Record<AttemptStatus, string> = {
  sin_analizar: 'Sin analizar', en_proceso: 'En proceso', completado: 'Completado',
  fallido: 'Fallido', vencido: 'Vencido',
}

const methodology = {
  vigente: 'Metodología vigente', desactualizada: 'Metodología desactualizada',
  no_verificable: 'Metodología no verificable',
}

export function AnalysisStatus({attempt, validity}: {attempt?: AttemptStatus; validity?: AnalysisValidity | null}) {
  return <span className="inline-flex flex-wrap gap-1" aria-label="Estado de análisis">
    {attempt && <span className={'badge ' + (attempt === 'fallido' || attempt === 'vencido' ? 'error' : attempt === 'en_proceso' ? 'warn' : '')}>
      {attempts[attempt]}
    </span>}
    {validity && <>
      <span className={'badge ' + (validity.cobertura_eventos === 'incompleta' ? 'warn' : '')}>
        Cobertura {validity.cobertura_eventos}{!validity.evidencia_verificable && ' · solo conteo histórico'}
      </span>
      <span className={'badge ' + (validity.metodologia === 'vigente' ? '' : 'warn')}>{methodology[validity.metodologia]}</span>
    </>}
  </span>
}
