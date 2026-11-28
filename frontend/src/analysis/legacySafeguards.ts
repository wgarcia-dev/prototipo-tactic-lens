import {useEffect,useState} from 'react'
import {api} from '../auth/client'

type ArchiveStatus={archivo_activo:boolean;archivo_solicitado:boolean;
  tareas_por_conciliar:number|null;revisiones_por_conciliar:number|null}

export function useLegacySafeguards(){
  const [status,setStatus]=useState<ArchiveStatus>()
  useEffect(()=>{
    const controller=new AbortController()
    api<ArchiveStatus>('/salvaguardas/archivo',{signal:controller.signal})
      .then(data=>{if(!controller.signal.aborted)setStatus(data)}).catch(()=>{})
    return ()=>controller.abort()
  },[])
  return status
}
