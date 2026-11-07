import {useState} from "react";
import {Link} from "react-router-dom";
import {AuthFrame,Field,Form,Status,Submit,formData,useTask} from "./components";
import {useAuth} from "./context";
import {mutate} from "./client";
import {useSupportContact} from "./SupportContact";
import {adminDate,useAdminRows} from "./adminShared";

type SentSupport={id_soporte:string;asunto:string;categoria:string;creado_en:string;estado_envio:string;resultado:string|null};
const statusLabel=(value:string)=>({aceptado:"Aceptado por el servicio de correo",pendiente:"Pendiente de remisión",en_proceso:"Procesando remisión",fallido:"Fallo de remisión",incierto:"Aceptación sin confirmar",cancelado:"Remisión cancelada"}[value]||value);

function OwnSupport({revision}:{revision:number}){
  const data=useAdminRows<SentSupport>("/auth/soporte/mis-solicitudes",revision);
  return <section className="mt-6 border-t line pt-5"><h3 className="font-semibold text-sm mb-2">Mis consultas recientes</h3><p className="auth-help">Estos estados corresponden al envío del correo. No indican que el equipo lo haya leído o resuelto.</p><Status error={data.error}/>{data.loading?<p role="status">Cargando consultas…</p>:<ul className="space-y-3">{data.rows.map(row=><li className="text-sm border-b line pb-3" key={row.id_soporte}><strong>{row.asunto}</strong><p className="muted text-xs">{adminDate(row.creado_en)} · {statusLabel(row.estado_envio)}</p><p className="muted text-xs break-all">Referencia: {row.id_soporte}</p></li>)}</ul>}</section>;
}

export function SupportPage(){
  const {session}=useAuth(),{contact,error}=useSupportContact(),task=useTask();
  const [description,setDescription]=useState(""),[reference,setReference]=useState(""),[revision,setRevision]=useState(0);
  const user=session?.usuario;
  return <AuthFrame step="AYUDA Y SOPORTE" title="¿Necesita ayuda con TacticLens?" description="Describa su consulta. El equipo de soporte responderá manualmente al correo que indique.">
    <Status error={error}/><Status {...task}/>
    {contact?.support_email&&<p className="auth-message">Canal oficial: <a className="accent underline" href={`mailto:${contact.support_email}`}>{contact.support_email}</a></p>}
    <p className="auth-help">No incluya contraseñas, claves API, códigos de verificación ni secretos de su autenticador. Una consulta de soporte no autoriza cambios de cuenta ni permite omitir Google Authenticator.</p>
    {reference?<div className="auth-message" role="status"><p>Consulta registrada para remisión a soporte.</p><p className="break-all text-xs mt-2">Referencia: {reference}</p><p className="auth-help mt-3">Conserve esta referencia. Las respuestas se gestionan por correo.</p><button className="btn-secondary mt-3" onClick={()=>{setReference("");task.clear();}}>Crear otra consulta</button></div>:<Form busy={task.busy} onSubmit={e=>{const data=formData(e.currentTarget);void task.run(async()=>{
      const result=await mutate<{id_solicitud:string;mensaje:string}>("/auth/soporte",{nombre:data.nombre,correo:data.correo,asunto:data.asunto,categoria:data.categoria,descripcion:description});
      setReference(result.id_solicitud);task.setNotice(result.mensaje);setRevision(r=>r+1);setDescription("");
    });}}>
      <Field label="Nombre" name="nombre" defaultValue={user?`${user.nombres} ${user.apellidos}`:""} required minLength={2} maxLength={120} autoComplete="name"/>
      <Field label="Correo de respuesta" name="correo" type="email" defaultValue={user?.correo||""} required maxLength={254} autoComplete="email"/>
      <Field label="Asunto" name="asunto" required minLength={5} maxLength={140}/>
      <label className="auth-field">Categoría<select name="categoria" required><option value="acceso">Problemas de acceso</option><option value="mfa">Google Authenticator</option><option value="recuperacion">Recuperación de cuenta</option><option value="funcional">Problemas de la plataforma</option><option value="general">Consulta general</option></select></label>
      <label className="auth-field">Descripción<textarea name="descripcion" value={description} onChange={e=>setDescription(e.target.value)} required minLength={20} maxLength={3000} rows={5}/><small className="auth-help">{description.length}/3000 caracteres. Explique qué intentaba hacer y qué mensaje apareció, sin credenciales.</small></label>
      <label className="auth-checkbox"><input type="checkbox" required/>Confirmo que no incluí contraseñas ni códigos y autorizo el envío de esta consulta al equipo de soporte.</label>
      <Submit busy={task.busy} disabled={!contact?.support_enabled}>Enviar consulta a soporte</Submit>
    </Form>}
    {session?.etapa==="completa"&&<OwnSupport revision={revision}/>}
    <div className="auth-links"><Link to={session?.etapa==="completa"?"/":"/login"}>Volver a TacticLens</Link><Link to="/recuperar">Solicitar recuperación de contraseña</Link></div>
  </AuthFrame>;
}
