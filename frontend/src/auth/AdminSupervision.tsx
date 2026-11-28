import {useEffect, useState} from "react";
import {mutate} from "./client";
import {Form, ReauthFields, Status, Submit, reauthData, useTask} from "./components";
import {AdminConfirmation, AdminPager, adminDate, connectionLabel, useAdminRows} from "./adminShared";

type ManagedSession={id_sesion:string;id_usuario:string;usuario:string;correo:string;inicio:string|null;ultima_actividad:string;vence_en:string;estado:string;actividad:string;dispositivo:string|null};
type Recovery={id_solicitud:string;id_usuario:string;nombres:string;apellidos:string;correo:string;origen:string;estado:string;creado_en:string;resuelto_en:string|null;administrador:string|null;notificacion_estado:string;enlace_vence_en:string|null;motivo_decision:string|null};
type Audit={id_auditoria:string;tipo:string;fecha_evento:string;administrador:string|null;usuario:string|null;metadatos:{reason?:string;resultado?:string;rol?:string}};

export function AdminSessions({userId=""}:{userId?:string}){
  const [page,setPage]=useState(0),[state,setState]=useState("vigente"),[revision,setRevision]=useState(0);
  const [selected,setSelected]=useState<ManagedSession|null>(null),[all,setAll]=useState(false);
  const task=useTask();
  const data=useAdminRows<ManagedSession>(`/auth/admin/sesiones?limit=26&offset=${page*25}${state?`&estado=${state}`:""}${userId?`&usuario=${userId}`:""}`,revision,true);
  useEffect(()=>{setSelected(null);setPage(0);},[userId]);
  return <section className="panel auth-section">
    <h2>Usuarios conectados y sesiones</h2>
    <p className="muted text-sm mb-4">«Actividad reciente» requiere interacción en la aplicación. Una sesión vigente por sí sola no significa que la persona esté conectada.</p>
    <label className="auth-field">Estado de sesión<select value={state} onChange={e=>{setState(e.target.value);setPage(0);setSelected(null);}}><option value="vigente">Vigentes</option><option value="">Todas</option><option value="expirada">Expiradas</option><option value="revocada">Revocadas</option><option value="incompleta">Autenticación incompleta</option></select></label>
    <Status error={data.error}/><Status {...task}/>
    {data.loading?<p role="status">Cargando sesiones…</p>:<div className="auth-table-scroll"><table className="w-full text-sm"><thead><tr><th>Usuario</th><th>Inicio / última actividad</th><th>Estado y dispositivo</th><th>Acción</th></tr></thead><tbody>
      {data.rows.map(s=><tr key={s.id_sesion}><td>{s.usuario}<p className="muted text-xs">{s.correo}</p></td><td>{adminDate(s.inicio)}<p className="muted text-xs">Actividad: {adminDate(s.ultima_actividad)}</p></td><td><span className="badge">{s.estado}</span><p>{connectionLabel(s.actividad)}</p><p className="muted text-xs">{s.dispositivo||"No disponible"}</p></td><td><button className="btn-secondary" disabled={!!s.estado.match(/revocada|expirada/)||task.busy} onClick={()=>{setSelected(s);setAll(false);task.clear();}}>Gestionar</button></td></tr>)}
    </tbody></table>{!data.rows.length&&<p className="muted">No hay sesiones para este filtro.</p>}</div>}
    <AdminPager page={page} hasNext={data.hasNext} loading={data.loading} onChange={setPage}/>
    {selected&&<Form key={selected.id_sesion} busy={task.busy} onSubmit={e=>{const form=e.currentTarget,data=reauthData(form);void task.run(async()=>{
      await mutate(all?`/auth/admin/usuarios/${selected.id_usuario}/sesiones/revocar`:`/auth/admin/sesiones/${selected.id_sesion}/revocar`,{password:data.password,codigo:data.codigo,recuperacion:data.recuperacion,motivo:data.motivo});
      setSelected(null);setRevision(r=>r+1);task.setNotice("Revocación aplicada en el servidor.");
    });}}><h3>Revocar acceso de {selected.usuario}</h3><label className="auth-checkbox"><input type="checkbox" checked={all} onChange={e=>setAll(e.target.checked)}/>Cerrar todas las sesiones de esta cuenta</label><label className="auth-field">Motivo<textarea name="motivo" required minLength={10} maxLength={300}/></label><ReauthFields passwordLabel="Tu contraseña de administrador"/><AdminConfirmation/><Submit busy={task.busy}>Revocar sesiones</Submit><button type="button" className="btn-secondary" onClick={()=>setSelected(null)}>Cancelar</button></Form>}
  </section>;
}

export function AdminRecovery(){
  const [page,setPage]=useState(0),[filter,setFilter]=useState("pendiente"),[revision,setRevision]=useState(0),[selected,setSelected]=useState<Recovery|null>(null);
  const task=useTask(),data=useAdminRows<Recovery>(`/auth/admin/recuperaciones?limit=26&offset=${page*25}${filter?`&estado=${filter}`:""}`,revision);
  return <section className="panel auth-section"><div className="auth-section-heading"><h2>Solicitudes de recuperación</h2><button className="btn-secondary" onClick={()=>setRevision(r=>r+1)}>Actualizar</button></div>
    <p className="muted text-sm mb-4">Aprobar envía un enlace personal al correo verificado. Nunca se muestran contraseñas ni tokens. Un fallo de envío deja la solicitud pendiente.</p>
    <label className="auth-field">Estado<select value={filter} onChange={e=>{setFilter(e.target.value);setPage(0);setSelected(null);}}>{["pendiente","aprobada","rechazada","expirada","completada","cancelada",""].map(v=><option key={v} value={v}>{v||"Todas"}</option>)}</select></label>
    <Status error={data.error}/><Status {...task}/>
    {data.loading?<p role="status">Cargando solicitudes…</p>:<div className="auth-table-scroll"><table className="w-full text-sm"><thead><tr><th>Solicitud / cuenta</th><th>Estado</th><th>Resolución</th><th>Acción</th></tr></thead><tbody>{data.rows.map(r=><tr key={r.id_solicitud}><td>{r.nombres} {r.apellidos}<p className="muted text-xs">{r.correo}</p><p className="muted text-xs break-all">{r.id_solicitud}</p><p>{adminDate(r.creado_en)} · {r.origen==="alta"?"Primera contraseña":"Recuperación"}</p></td><td><span className="badge">{r.estado}</span><p className="muted text-xs">Notificación: {r.notificacion_estado}</p>{r.enlace_vence_en&&<p className="muted text-xs">Enlace vence: {adminDate(r.enlace_vence_en)}</p>}</td><td>{r.administrador||"Sin resolver"}<p className="muted text-xs">{adminDate(r.resuelto_en)}</p><p className="muted text-xs">{r.motivo_decision}</p></td><td>{r.estado==="pendiente"&&<button className="btn-secondary" disabled={task.busy} onClick={()=>{setSelected(r);task.clear();}}>Revisar</button>}</td></tr>)}</tbody></table>{!data.rows.length&&<p className="muted">No hay solicitudes para este filtro.</p>}</div>}
    <AdminPager page={page} hasNext={data.hasNext} loading={data.loading} onChange={setPage}/>
    {selected&&<Form key={selected.id_solicitud} busy={task.busy} onSubmit={e=>{const data=reauthData(e.currentTarget);void task.run(async()=>{
      const result=await mutate<{notificacion_estado:string}>(`/auth/admin/recuperaciones/${selected.id_solicitud}/resolver`,{password:data.password,codigo:data.codigo,recuperacion:data.recuperacion,motivo:data.motivo,decision:data.decision});
      setSelected(null);setRevision(r=>r+1);task.setNotice(result.notificacion_estado==="pendiente"?"Decisión registrada. La notificación quedó en cola.":"Decisión registrada.");
    });}}><h3>Resolver solicitud de {selected.correo}</h3><label className="auth-field">Decisión<select name="decision" required><option value="aprobar">Aprobar y enviar enlace</option><option value="rechazar">Rechazar solicitud</option></select></label><label className="auth-field">Motivo de la decisión<textarea name="motivo" required minLength={10} maxLength={300}/></label><ReauthFields passwordLabel="Tu contraseña de administrador"/><AdminConfirmation/><Submit busy={task.busy}>Confirmar decisión</Submit><button type="button" className="btn-secondary" onClick={()=>setSelected(null)}>Cancelar</button></Form>}
  </section>;
}

export function AdminHistory({userId=""}:{userId?:string}){
  const [page,setPage]=useState(0),[type,setType]=useState(""),[revision,setRevision]=useState(0);
  const data=useAdminRows<Audit>(`/auth/admin/auditoria?limit=26&offset=${page*25}${userId?`&usuario=${userId}`:""}${type?`&tipo=${encodeURIComponent(type)}`:""}`,revision);
  useEffect(()=>setPage(0),[userId]);
  return <section className="panel auth-section"><div className="auth-section-heading"><h2>Historial administrativo y de seguridad</h2><button className="btn-secondary" onClick={()=>setRevision(r=>r+1)}>Actualizar</button></div><label className="auth-field">Tipo de evento<select value={type} onChange={e=>{setType(e.target.value);setPage(0);}}>{["","cuenta_autorizada","cuenta_rechazada","cuenta_suspendida","cuenta_bloqueada","cuenta_reactivada","rol_cambiado","sesion_revocada_administrativamente","sesiones_revocadas_administrativamente","recuperacion_solicitada","recuperacion_aprobada","recuperacion_rechazada","recuperacion_envio_fallido","password_restablecida","password_cambiada"].map(v=><option key={v} value={v}>{v.replaceAll("_"," ")||"Todos los eventos"}</option>)}</select></label><Status error={data.error}/>
    {data.loading?<p role="status">Cargando historial…</p>:<div className="auth-table-scroll"><table className="w-full text-sm"><thead><tr><th>Fecha / operación</th><th>Responsable / usuario</th><th>Resultado y motivo</th></tr></thead><tbody>{data.rows.map(a=><tr key={a.id_auditoria}><td>{adminDate(a.fecha_evento)}<p>{a.tipo.replaceAll("_"," ")}</p></td><td>{a.administrador||"Solicitud pública / sistema"}<p className="muted">Afectado: {a.usuario||"Sin cuenta identificada"}</p></td><td>{a.metadatos.resultado||"Registrado"}<p className="muted">{a.metadatos.reason}</p>{a.metadatos.rol&&<p>Rol: {a.metadatos.rol}</p>}</td></tr>)}</tbody></table>{!data.rows.length&&<p className="muted">Sin eventos para este filtro.</p>}</div>}
    <AdminPager page={page} hasNext={data.hasNext} loading={data.loading} onChange={setPage}/></section>;
}
