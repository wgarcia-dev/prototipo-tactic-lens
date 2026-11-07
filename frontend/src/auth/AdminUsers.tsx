import {useEffect, useState} from "react";
import {Link} from "react-router-dom";
import {mutate} from "./client";
import {useAuth} from "./context";
import {Form, AuthenticatorField, ReauthFields, Status, Submit, reauthData, useTask} from "./components";
import {AdminSessions, AdminRecovery, AdminHistory} from "./AdminSupervision";
import {AdminConfirmation, AdminPager, adminDate, connectionLabel, useAdminRows} from "./adminShared";

type Account={id_usuario:string;nombres:string;apellidos:string;nombre_usuario:string;correo:string;rol:string;activo:boolean;autorizacion:string;estado_cuenta:string;creado_en:string;ultimo_acceso_en:string|null;ultima_actividad:string|null;conexion:string;sesiones_activas:number;correo_verificado_en:string|null;mfa_confirmado_en:string|null;motivo_restriccion:string|null;motivo_rechazo:string|null;password_cambio_obligatorio:boolean};

export function AdminUsers(){
  const {session}=useAuth();
  if(session?.usuario.rol!=="administrador")return <section className="panel auth-section"><h1>Acceso restringido</h1><p>Esta sección requiere un administrador de seguridad.</p><Link to="/">Volver al panel</Link></section>;
  return <AdminWorkspace/>;
}

function AdminWorkspace(){
  const [tab,setTab]=useState("usuarios"),[focusUser,setFocusUser]=useState("");
  return <>
    <header className="auth-page-header"><p className="auth-kicker">ADMINISTRACIÓN DE SEGURIDAD</p><h1>Administración de usuarios</h1><p className="muted">Cuentas, actividad, sesiones y recuperaciones supervisadas.</p></header>
    <nav className="flex flex-wrap gap-2 mb-5" aria-label="Secciones de administración">{[["usuarios","Usuarios"],["sesiones","Usuarios conectados"],["recuperaciones","Solicitudes de recuperación"],["historial","Historial administrativo"]].map(([key,label])=><button type="button" key={key} className={tab===key?"btn":"btn-secondary"} aria-pressed={tab===key} onClick={()=>{setTab(key);setFocusUser("");}}>{label}</button>)}</nav>
    {focusUser&&<p className="auth-help mb-4">Mostrando la cuenta seleccionada. <button className="accent underline" onClick={()=>setFocusUser("")}>Mostrar todas</button></p>}
    {tab==="usuarios"&&<UserAccounts onSessions={id=>{setFocusUser(id);setTab("sesiones");}} onHistory={id=>{setFocusUser(id);setTab("historial");}}/>}
    {tab==="sesiones"&&<AdminSessions userId={focusUser}/>}
    {tab==="recuperaciones"&&<AdminRecovery/>}
    {tab==="historial"&&<AdminHistory userId={focusUser}/>}
  </>;
}

function UserAccounts({onSessions,onHistory}:{onSessions:(id:string)=>void;onHistory:(id:string)=>void}){
  const [page,setPage]=useState(0),[state,setState]=useState(""),[role,setRole]=useState(""),[order,setOrder]=useState("registro"),[direction,setDirection]=useState("desc"),[search,setSearch]=useState(""),[query,setQuery]=useState(""),[revision,setRevision]=useState(0);
  const [selected,setSelected]=useState<Account|null>(null),[action,setAction]=useState("guardar");
  const {session}=useAuth(),task=useTask(),reset=useTask();
  useEffect(()=>{const timer=window.setTimeout(()=>{setQuery(search);setPage(0);},300);return()=>window.clearTimeout(timer);},[search]);
  const data=useAdminRows<Account>(`/auth/admin/usuarios?limit=26&offset=${page*25}&q=${encodeURIComponent(query)}&orden=${order}&direccion=${direction}${state?`&estado=${state}`:""}${role?`&rol=${role}`:""}`,revision);
  useEffect(()=>{setSelected(previous=>data.rows.find(u=>u.id_usuario===previous?.id_usuario)||null);},[data.rows]);
  useEffect(()=>setAction(selected?.autorizacion==="aprobado"?"guardar":"aprobar"),[selected?.id_usuario,selected?.autorizacion]);
  function filter(setter:(value:string)=>void,value:string){setter(value);setPage(0);setSelected(null);}
  const own=selected?.id_usuario===session?.usuario.id_usuario;
  return <>
    <section className="panel auth-section mb-5"><div className="auth-section-heading"><h2>Cuentas de la organización</h2><button className="btn-secondary" onClick={()=>setRevision(r=>r+1)}>Actualizar</button></div>
      <div className="grid sm:grid-cols-2 xl:grid-cols-5 gap-3 mb-4">
        <label className="auth-field">Buscar<input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Nombre, correo o usuario" maxLength={120}/></label>
        <label className="auth-field">Estado<select value={state} onChange={e=>filter(setState,e.target.value)}>{["","pendiente","activo","rechazado","suspendido","bloqueado"].map(v=><option key={v} value={v}>{v||"Todos los estados"}</option>)}</select></label>
        <label className="auth-field">Rol<select value={role} onChange={e=>filter(setRole,e.target.value)}><option value="">Todos los roles</option><option value="administrador">Administrador de seguridad</option><option value="analista">Analista de seguridad</option></select></label>
        <label className="auth-field">Ordenar por<select value={order} onChange={e=>filter(setOrder,e.target.value)}><option value="registro">Fecha de registro</option><option value="nombre">Nombre</option><option value="ultimo_acceso">Último acceso</option><option value="actividad">Última actividad</option></select></label>
        <label className="auth-field">Dirección<select value={direction} onChange={e=>filter(setDirection,e.target.value)}><option value="desc">Descendente</option><option value="asc">Ascendente</option></select></label>
      </div><Status error={data.error}/><Status {...task}/>
      {data.loading?<p role="status">Cargando cuentas…</p>:<div className="auth-table-scroll"><table className="w-full text-sm"><thead><tr><th>Usuario / rol</th><th>Estado</th><th>Registro / último acceso</th><th>Actividad / sesiones</th><th>Acciones</th></tr></thead><tbody>{data.rows.map(u=><tr key={u.id_usuario}><td><strong>{u.nombres} {u.apellidos}</strong><p className="muted text-xs">{u.correo}</p><p className="muted text-xs">{u.rol==="administrador"?"Administrador de seguridad":"Analista de seguridad"}</p></td><td><span className="badge">{u.estado_cuenta}</span><p className="muted text-xs">Correo: {u.correo_verificado_en?"verificado":"pendiente"}</p><p className="muted text-xs">MFA: {u.mfa_confirmado_en?"configurado":"pendiente"}</p></td><td>{adminDate(u.creado_en)}<p className="muted text-xs">Acceso: {adminDate(u.ultimo_acceso_en)}</p></td><td>{connectionLabel(u.conexion)}<p className="muted text-xs">{adminDate(u.ultima_actividad)}</p><p className="muted text-xs">{u.sesiones_activas} sesiones vigentes</p></td><td><div className="flex flex-wrap gap-2"><button className="btn-secondary" disabled={task.busy} onClick={()=>{setSelected(u);task.clear();reset.clear();}}>Gestionar</button><button className="btn-secondary" onClick={()=>onSessions(u.id_usuario)}>Sesiones</button><button className="btn-secondary" onClick={()=>onHistory(u.id_usuario)}>Historial</button></div></td></tr>)}</tbody></table>{!data.rows.length&&<p className="muted">No hay usuarios para estos filtros.</p>}</div>}
      <AdminPager page={page} hasNext={data.hasNext} loading={data.loading} onChange={setPage}/>
    </section>
    {selected&&<section className="panel auth-section"><h2>Gestionar cuenta de {selected.nombres} {selected.apellidos}</h2><p className="muted mb-4">{selected.correo} · {selected.estado_cuenta}</p>
      {selected.motivo_restriccion&&<p className="auth-message">Motivo de restricción: {selected.motivo_restriccion}</p>}
      {selected.motivo_rechazo&&<p className="auth-message">Motivo de rechazo: {selected.motivo_rechazo}</p>}
      {own?<p className="auth-message">Otro administrador debe gestionar su rol y estado. Su contraseña y sesiones propias se gestionan desde Seguridad de mi cuenta.</p>:<>
        <Form key={selected.id_usuario+selected.estado_cuenta} busy={task.busy} onSubmit={e=>{const data=reauthData(e.currentTarget);void task.run(async()=>{
          const result=await mutate<{mensaje:string;notificacion_enviada:boolean}>(`/auth/admin/usuarios/${selected.id_usuario}`,{password:data.password,codigo:data.codigo,recuperacion:data.recuperacion,rol:data.rol||selected.rol,
            activo:action==="aprobar"||action==="reactivar"?true:action==="suspender"||action==="bloquear"||action==="rechazar"?false:selected.activo,
            aprobar:action==="aprobar",rechazar:action==="rechazar",accion:["suspender","bloquear","reactivar"].includes(action)?action:null,
            motivo_rechazo:action==="rechazar"?data.motivo:null,motivo:data.motivo||null},"PATCH");
          setSelected(null);setRevision(r=>r+1);task.setNotice(result.mensaje+(result.notificacion_enviada?" Notificación enviada al servicio de correo.":" No se pudo entregar la notificación; revise el servicio de correo y las solicitudes pendientes."));
        });}}>
          <label className="auth-field">Acción<select value={action} onChange={e=>setAction(e.target.value)}>{selected.autorizacion!=="aprobado"?<><option value="aprobar">Aprobar registro</option>{selected.autorizacion==="pendiente"&&<option value="rechazar">Rechazar registro</option>}</>:<><option value="guardar">Actualizar rol</option>{selected.activo?<><option value="suspender">Suspender cuenta</option><option value="bloquear">Bloquear cuenta</option></>:<option value="reactivar">Reactivar cuenta</option>}{!selected.activo&&selected.estado_cuenta!=="bloqueado"&&<option value="bloquear">Bloquear cuenta</option>}</>}</select></label>
          <label className="auth-field">Rol<select name="rol" defaultValue={selected.rol} disabled={!["guardar","aprobar"].includes(action)}><option value="analista">Analista de seguridad</option><option value="administrador">Administrador de seguridad</option></select></label>
          {["rechazar","suspender","bloquear","reactivar"].includes(action)&&<label className="auth-field">Motivo<textarea name="motivo" required minLength={10} maxLength={300} placeholder="Explique la decisión sin contraseñas, códigos ni documentos personales."/></label>}
          {action==="aprobar"&&selected.autorizacion==="pendiente"?<AuthenticatorField/>:<ReauthFields passwordLabel="Tu contraseña de administrador"/>}
          <AdminConfirmation/><Submit busy={task.busy} disabled={action==="aprobar"&&!selected.correo_verificado_en}>Confirmar acción</Submit><button type="button" className="btn-secondary" onClick={()=>setSelected(null)}>Cancelar</button>
        </Form>
        <details className="mt-5"><summary className="cursor-pointer font-semibold">Restablecimiento administrativo de Google Authenticator</summary><p className="auth-help">Solo después de verificar la identidad por un canal independiente y documentar la referencia. La recuperación de contraseña nunca desactiva MFA.</p><Status {...reset}/><Form busy={reset.busy} onSubmit={e=>{const data=reauthData(e.currentTarget);void reset.run(async()=>{await mutate(`/auth/admin/usuarios/${selected.id_usuario}/mfa/restablecer`,{password:data.password,codigo:data.codigo,recuperacion:data.recuperacion,referencia_verificacion:data.referencia_verificacion});setRevision(r=>r+1);reset.setNotice("MFA restablecido y sesiones revocadas. El titular debe vincular un autenticador nuevo.");});}}><label className="auth-field">Referencia de verificación de identidad<input name="referencia_verificacion" required minLength={20} maxLength={160}/></label><ReauthFields passwordLabel="Tu contraseña de administrador"/><AdminConfirmation/><Submit busy={reset.busy}>Restablecer MFA</Submit></Form></details>
      </>}
    </section>}
  </>;
}
