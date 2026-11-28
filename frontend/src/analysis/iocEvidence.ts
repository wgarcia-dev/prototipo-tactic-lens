export const reviewLabels = {
  pendiente: 'Pendiente',
  confirmado: 'Relevancia confirmada',
  descartado: 'Descartado',
  mixto: 'Revisión mixta',
  historico: 'Histórico por verificar',
} as const

export type IocReviewState = keyof typeof reviewLabels

export const behaviorLabels: Record<string, string> = {
  conexion_origen: 'Conexión de origen',
  origen_sesion: 'Origen de la sesión',
  host_mencionado: 'Host mencionado en un comando',
  url_mencionada: 'URL mencionada en un comando',
  intento_descarga: 'Intento de descarga',
  descarga_registrada: 'Descarga registrada por Cowrie',
  descarga_fallida: 'Descarga fallida',
  archivo_subido: 'Archivo subido a Cowrie',
  archivo_capturado: 'Archivo capturado por Cowrie',
}

export const evidenceLabels: Record<string, string> = {
  referencia: 'Referencia',
  intento: 'Intento',
  resultado_registrado: 'Resultado registrado',
  fallo_registrado: 'Fallo registrado',
}

export const scopeLabels: Record<string, string> = {
  global: 'IP de alcance global',
  privada: 'IP privada',
  loopback: 'IP de loopback',
  enlace_local: 'IP de enlace local',
  documentacion: 'IP de documentación',
  no_enrutable: 'IP no enrutable',
  no_especificada: 'IP no especificada',
  multicast: 'IP multicast',
  reservada: 'IP reservada',
}

export function sessionEvidencePath(sessionId: string) {
  return '/sesiones/' + encodeURIComponent(sessionId)
}

export const relationLabels = {
  directa: 'Relación directa',
  contextual: 'Relación contextual',
  candidata: 'Candidata a revisión',
  insuficiente: 'Evidencia insuficiente',
} as const

export type RelationState = keyof typeof relationLabels

export const mappingReviewLabels: Record<string, string> = {
  pendiente: 'Mapeo pendiente',
  confirmado: 'Mapeo confirmado',
  descartado: 'Mapeo descartado',
}

export const mitreGradeLabels: Record<string, string> = {
  intento: 'Intento',
  resultado_en_honeypot: 'Resultado observado en el honeypot',
}

export const mitreBrowseStates = {
  automatica:'Identificada automáticamente',
  confirmada:'Confirmada administrativamente',
  historica_pendiente:'Histórico · pendiente de revisión',
  historica_confirmada:'Histórico · confirmado',
  descartada:'Descartada en revisión',
} as const

export type MitreBrowseState=keyof typeof mitreBrowseStates

export function isAutomaticMapping(mapping:{rag_procedencia?:{clasificacion?:string}}) {
  return mapping.rag_procedencia?.clasificacion === 'identificada_automaticamente'
}

export function mappingClassificationLabel(mapping: {estado_revision:string; rag_procedencia?:{clasificacion?:string}}) {
  if (!isAutomaticMapping(mapping)) return ({pendiente:'Histórico · pendiente de revisión',
    confirmado:'Histórico · confirmado',descartado:'Histórico · descartado'} as Record<string,string>)[mapping.estado_revision]??'Mapeo histórico'
  if (mapping.estado_revision === 'descartado') return 'Descartada por revisión'
  return 'Identificada automáticamente'
}

export function reportEventIds(value:string) {
  return /^#\d+(, #\d+)*$/.test(value) ? value.split(', ').map(ref=>ref.slice(1)) : []
}

export function eventEvidencePath(sessionId: string, eventId: string) {
  return sessionEvidencePath(sessionId) + '?' + new URLSearchParams({evento: eventId})
}

export function observableEvidencePath(id: string, eventId: string) {
  return '/iocs?' + new URLSearchParams({ioc: id, evento: eventId})
}

export function actionEvidencePath(sessionId: string, analysisId: string, actionId: string) {
  return sessionEvidencePath(sessionId) + '?' + new URLSearchParams({analisis: analysisId, accion: actionId})
}

export function mappingEvidencePath(id: string, context?:{technique:string;session:string}) {
  const query=new URLSearchParams({mapeo:id})
  if(context){
    query.set('tecnica',context.technique)
    query.set('sesion_id',context.session)
  }
  return '/mitre?' + query
}
const enrichmentStates: Record<string,string> = {
  coincidencia:'Coincidencia encontrada', sin_resultados:'Sin coincidencias',
  no_disponible:'Servicio no disponible', timeout:'Tiempo de espera agotado',
  cuota:'Cuota agotada', respuesta_incompatible:'Respuesta incompatible',
  error_autenticacion:'Error de autenticación', omitido:'Consulta omitida', error:'Error de consulta',
}

export function enrichmentStatusLabel(state?:string) {
  return state ? enrichmentStates[state] ?? state : 'Sin resultado'
}
