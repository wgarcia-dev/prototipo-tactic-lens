export const decisions = {incidente_confirmado:'Incidente confirmado', actividad_sospechosa:'Actividad sospechosa',
  actividad_autorizada:'Actividad autorizada', evidencia_insuficiente:'Evidencia insuficiente'} as const
export const modes = {cowrie_shell:'Shell',cowrie_proxy:'Proxy',cowrie_llm:'LLM',desconocido:'Desconocido'} as const
export const severities=['S0','S1','S2','S3','S4'] as const
export const priorities={baja:'Baja',media:'Media',alta:'Alta',inmediata:'Inmediata',por_determinar:'Por determinar'} as const
export type Decision=keyof typeof decisions
export type Mode=keyof typeof modes
export type Priority=keyof typeof priorities
export type Summary={id_incidente:string;revision_actual:number;titulo:string;resumen:string;clasificacion:string;
  decision:Decision;severidad:string|null;prioridad:Priority;actualizado_en:string;modalidades:Mode[]}
export type Page={items:Summary[];cursor:string|null}
export type Citation={id_evento:string;id_sesion:string;id_analisis:string|null;grado:string;
  procedencia:{modalidad:Mode;sensor:string|null;estado:string}}
export type Evaluation={id_incidente:string;titulo:string;resumen:string;clasificacion:string;decision:Decision;
  severidad:string|null;prioridad:Priority;revision_evaluacion:number;revision_actual:number;validado_por?:string;
  evaluado_en:string;evidencia_sha256:string;evidencia_verificable:boolean;evidencias:Citation[];
  alcance:{sesiones:string[];recursos_confirmados:string[]};
  detalle:{motivo?:string;impacto_confirmado?:string|null;corroboracion?:string|null;origen:string;
    analisis?:{id_analisis:string;id_sesion:string;modalidad_al_analizar:Mode;
      severidad:string|null;impacto_tecnico:Record<string,unknown>}[];
    evidencias_incluidas:number;evidencias_disponibles:number};
  correlaciones:{id_sesion:string;metodo:string;eventos?:string[];sha256?:string;limitacion?:string}[]}
export type Incident=Evaluation & {
  eventos:(Citation&{tipo_evento:string;comando:string|null;fecha_hora:string})[];
  iocs:{id_observacion:string;id_evento:string;id_sesion:string;valor:string;tipo:string;estado_revision:string}[];
  mitre:{id_evento:string;id_sesion:string;codigo_tecnica:string;tecnica:string;estado_revision:string}[];
  sesiones:{id_sesion:string;cowrie_session_id:string;fecha_inicio:string}[];
  analisis:{id_analisis:string;id_sesion:string;revision_ingreso:number}[];
  historial:{revision_evaluacion:number;decision:Decision;severidad:string|null;evaluado_en:string;actor:string|null}[];
  limites:{hay_mas:boolean};
}
export const responseEligible=(evaluation:Pick<Evaluation,'decision'|'evidencia_verificable'|'revision_actual'|'revision_evaluacion'>) =>
  evaluation.decision==='incidente_confirmado'&&evaluation.evidencia_verificable&&evaluation.revision_actual===evaluation.revision_evaluacion
export const evidencePath=(session:string,event:string)=>'/sesiones/'+session+'?evento='+encodeURIComponent(event)
export const dateTime=(date:string)=>new Date(date).toLocaleString('es-EC',{timeZone:'America/Guayaquil'})
