import {useEffect, useRef, useState} from 'react'
import {api} from '../auth/client'

export async function runSessionAnalysis<A extends {id_analisis:string;id_sesion:string}, S extends {id_sesion:string}>(
  sessionId:string, upgradeReport:boolean, signal:AbortSignal,
) {
  const path = '/sesiones/' + encodeURIComponent(sessionId)
  const parameters = '?actualizar_rag=true' + (upgradeReport ? '&actualizar_informe=true' : '')
  let result
  try {
    result = await api<{id_analisis:string;reutilizado?:boolean}>(path+'/analizar'+parameters,{method:'POST',signal})
  } catch (error) {
    throw new Error('Análisis fallido. '+(error as Error).message,{cause:error})
  }
  try {
    const [analysis, session] = await Promise.all([
      api<A>('/analisis/'+encodeURIComponent(result.id_analisis),{signal}), api<S>(path,{signal}),
    ])
    if (analysis.id_analisis!==result.id_analisis || analysis.id_sesion!==sessionId || session.id_sesion!==sessionId) {
      throw new Error('El resultado recibido corresponde a otra sesión o análisis.')
    }
    return {analysis, session, reused:result.reutilizado===true}
  } catch (error) {
    throw new Error('No se pudo cargar el análisis guardado. '+(error as Error).message,{cause:error})
  }
}

export function useSessionAnalysisRun<A extends {id_analisis:string;id_sesion:string}, S extends {id_sesion:string}>(
  sessionId:string|undefined, apply:(analysis:A,session:S)=>void,
) {
  const pending=useRef<AbortController|null>(null)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')

  useEffect(()=>{
    setBusy(false);setError('');setNotice('')
    return ()=>{pending.current?.abort();pending.current=null}
  },[sessionId])

  async function run(upgradeReport:boolean) {
    if (!sessionId || pending.current) return
    const controller=new AbortController()
    pending.current=controller
    setBusy(true);setError('');setNotice('')
    try {
      const result=await runSessionAnalysis<A,S>(sessionId,upgradeReport,controller.signal)
      if (controller.signal.aborted) return
      apply(result.analysis,result.session)
      setNotice(result.reused?'Resultado reutilizado de PostgreSQL.':'Análisis completado y guardado.')
    } catch (failure) {
      if (!controller.signal.aborted) setError((failure as Error).message)
    } finally {
      if (pending.current===controller) {pending.current=null;setBusy(false)}
    }
  }
  return {run,busy,error,notice,clearNotice:()=>setNotice('')}
}
