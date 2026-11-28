export const phases = {investigacion:'Investigación', contencion:'Contención', erradicacion:'Erradicación',
  recuperacion:'Recuperación', mitigacion:'Mitigación', verificacion:'Verificación'} as const
export const priorities={baja:'Baja',media:'Media',alta:'Alta',inmediata:'Inmediata'} as const
export const origins={manual:'Manual',llm:'IA',historica:'Histórica'} as const
export const actionStates = {propuesta:'Propuesta', aprobada:'Aprobada', rechazada:'Rechazada',
  en_curso:'En curso', ejecutada:'Ejecutada', verificada:'Verificada', cancelada:'Cancelada'} as const
export const planStates = {sin_respuesta:'Sin respuesta', en_respuesta:'En respuesta',
  resuelto:'Resuelto', cerrado:'Cerrado', cancelado:'Cancelado'} as const
export const operations = {aprobar:'Aprobar', rechazar:'Rechazar', asignar:'Asignar responsable',
  iniciar:'Iniciar', avanzar:'Registrar avance', ejecutar:'Documentar ejecución', verificar:'Verificar',
  devolver:'Devolver a aprobadas', cancelar:'Cancelar'} as const
export const lanes = {por_decidir:'Por decidir', aprobadas:'Aprobadas', en_curso:'En curso',
  por_verificar:'Por verificar', finalizadas:'Finalizadas'} as const
export type Phase = keyof typeof phases
export type ActionState = keyof typeof actionStates
export type Lane = keyof typeof lanes
export type Operation = keyof typeof operations
export const columns = Object.keys(lanes) as Lane[]
export const laneStates:Record<Lane,ActionState[]> = {
  por_decidir:['propuesta'], aprobadas:['aprobada'], en_curso:['en_curso'],
  por_verificar:['ejecutada'], finalizadas:['verificada','rechazada','cancelada'],
}
export const laneOf = (state:ActionState) => columns.find(lane=>laneStates[lane].includes(state))!
export const pathFor = (id:string) => '/incidentes/'+id+'/respuesta'
export const dateTime = (value:string) => new Date(value).toLocaleString('es-EC',{timeZone:'America/Guayaquil'})
export type Citation = {id_evento:string;id_sesion:string;id_analisis:string|null;grado:string}
export type Evaluation = {decision:string;titulo:string;resumen:string;severidad:string|null;evidencias:Citation[]}
export type Plan = {
  id_incidente:string;id_respuesta:string|null;estado:keyof typeof planStates;elegible:boolean;desactualizada:boolean;
  revision_respuesta:number|null;revision_plan:number|null;revision_evaluacion_actual:number;evaluacion:Evaluation;
  objetivo?:string;alcance?:string;criterio_cierre?:string;id_responsable?:string|null;
  borrador?:{objetivo:string;alcance:string;criterio_cierre:string;eventos:string[]}|null;
  fases_no_aplicables?:Partial<Record<Phase,string>>;resolucion?:Record<string,string|null>|null;
  automatizacion_disponible?:boolean;origen?:keyof typeof origins;detalle_plan?:Record<string,string>;
  progreso?:{total?:number;estados?:Partial<Record<ActionState,number>>;vencidas?:number;porcentaje_finalizado?:number;
    segundos_desde_identificacion?:number|null;listo_resolver?:boolean;listo_cerrar?:boolean};
}
export type Evidence = {id_evidencia:string;id_evento:string|null;id_sesion:string|null;tipo:string;referencia:string|null}
export type Action = {
  id_accion:string;id_incidente:string;incidente_titulo:string;fase:Phase;estado:ActionState;medida:string;objetivo:string;
  justificacion:string;criterio_verificacion:string;id_responsable:string|null;responsable:string|null;vence_en:string|null;
  revision_accion:number;revision_validada:number;revision_evaluacion_actual:number;
  estado_respuesta:keyof typeof planStates;desactualizada:boolean;evidencia?:Evidence[];hay_mas_evidencia?:boolean;
  codigo_incidente?:string;codigo_accion?:string;prioridad?:keyof typeof priorities;origen_plan?:keyof typeof origins;
  vencida?:boolean;procedencia?:{descripcion?:string;resultado_esperado?:string;mitre?:string[];dependencias?:string[]};
}
export type History = {id_cambio:string;id_accion:string|null;operacion:string;motivo:string;actor:string;
  creado_en:string;revision_evaluacion:number;detalle:Record<string,unknown>}
export type Person = {id_usuario:string;nombre_usuario:string;carga?:number;en_curso?:number}
export type Page<T> = {items:T[];cursor:string|null}
export type Config = {wip_activo:boolean;limite_wip:number;revision_config:number;
  automatizacion_disponible?:boolean;generacion_habilitada?:boolean}
export type Lot = {id_lote:string;estado:string;error_codigo:string|null;resultado:{acciones:string[];abstencion:string|null}|null}
export type Antecedent = {id_analisis:string;posicion:number;id_salvaguarda:string|null;
  importable:boolean;recomendacion:{salvaguarda?:string;objetivo?:string}}

export function available(action:Action, admin:boolean, actor?:string):Operation[] {
  if(action.estado_respuesta!=='en_respuesta'||laneOf(action.estado)==='finalizadas')return []
  const canExecute=admin||!!actor&&action.id_responsable===actor
  if(action.desactualizada||action.revision_validada!==action.revision_evaluacion_actual)
    return [...(action.estado==='en_curso'&&canExecute?['avanzar','ejecutar'] as const:[]),...(admin?['cancelar'] as const:[])]
  if(action.estado==='propuesta')return admin?['aprobar','rechazar','asignar','cancelar']:[]
  if(action.estado==='aprobada')return [...(canExecute&&action.id_responsable?['iniciar'] as const:[]),
    ...(admin?['asignar','cancelar'] as const:[])]
  if(action.estado==='en_curso')return [...(canExecute?['avanzar','ejecutar'] as const:[]),
    ...(admin?['asignar','cancelar'] as const:[])]
  return admin?['verificar','devolver','cancelar']:[]
}

export function moves(action:Action, admin:boolean, actor?:string):Partial<Record<Lane,Operation>> {
  const authorized=available(action,admin,actor)
  const candidates:Partial<Record<Lane,Operation>> = {aprobadas:action.estado==='ejecutada'?'devolver':'aprobar',
    en_curso:'iniciar',por_verificar:'ejecutar',finalizadas:'verificar'}
  return Object.fromEntries(Object.entries(candidates).filter(([,operation])=>authorized.includes(operation)))
}
