import {useEffect, useMemo, useState} from "react";
import {api} from "./client";

export const adminDate = (value?: string | null) => value ? new Date(value).toLocaleString("es-EC", {dateStyle:"short",timeStyle:"short"}) : "Sin registro";
export const connectionLabel = (value: string) => ({recientemente_activo:"Actividad reciente",inactivo:"Inactivo con sesión vigente",desconectado:"Desconectado"}[value] || value);

export function useAdminRows<T>(path: string, revision: number, poll = false) {
  const [rows,setRows]=useState<T[]>([]), [loading,setLoading]=useState(true), [error,setError]=useState("");
  useEffect(()=>{
    let active=true;
    setLoading(true);
    async function load(){
      try{const result=await api<T[]>(path); if(active){setRows(result);setError("");}}
      catch(e){if(active)setError((e as Error).message);}
      finally{if(active)setLoading(false);}
    }
    void load();
    const timer=poll?window.setInterval(()=>void load(),15000):undefined;
    return()=>{active=false;window.clearInterval(timer);};
  },[path,revision,poll]);
  const visible=useMemo(()=>rows.slice(0,25),[rows]);
  return {rows:visible,hasNext:rows.length>25,loading,error};
}

export function AdminPager({page,hasNext,loading,onChange}:{page:number;hasNext:boolean;loading:boolean;onChange:(page:number)=>void}){
  return <nav className="pager" aria-label="Paginación de administración"><span className="muted text-xs">Página {page+1}</span><div className="flex gap-2">
    <button type="button" className="btn-secondary" disabled={loading||page===0} onClick={()=>onChange(page-1)}>Anterior</button>
    <button type="button" className="btn-secondary" disabled={loading||!hasNext} onClick={()=>onChange(page+1)}>Siguiente</button>
  </div></nav>;
}

export function AdminConfirmation(){return <label className="auth-checkbox"><input name="confirmacion_admin" type="checkbox" required/>Confirmo la operación sobre la cuenta seleccionada.</label>;}
