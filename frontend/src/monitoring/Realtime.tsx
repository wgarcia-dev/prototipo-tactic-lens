import {createContext,useContext,useEffect,useRef,useState,type DependencyList,type ReactNode} from 'react'
import {affectedDomains,startMonitor,type MonitorDomain,type Notice} from './socket'
import {usePolling} from './usePolling'

const configuredReconcile=Number(import.meta.env?.VITE_MONITOR_RECONCILE_MS??30000)
const reconcile=Number.isFinite(configuredReconcile)?Math.min(300000,Math.max(5000,configuredReconcile)):30000
const Context=createContext({connected:false,revision:0,notice:null as Notice|null})

export function RealtimeProvider({children}:{children:ReactNode}){
  const [state,setState]=useState({connected:false,revision:0,notice:null as Notice|null})
  useEffect(()=>{
    let dispose:(()=>void)|undefined
    // StrictMode probes effects before the real mount. Defer its socket handshake.
    const timer=window.setTimeout(()=>{dispose=startMonitor({
      connect:()=>new WebSocket(`${location.protocol==='https:'?'wss:':'ws:'}//${location.host}/api/monitor/ws`,'tacticlens.monitor.v1'),
      now:()=>Date.now(),random:()=>Math.random(),
      schedule:(fn,ms)=>window.setTimeout(fn,ms),cancel:id=>window.clearTimeout(id as number),
      visible:()=>document.visibilityState==='visible',
      subscribe:fn=>{document.addEventListener('visibilitychange',fn);return()=>document.removeEventListener('visibilitychange',fn)},
    },(connected,notice)=>{
      setState(previous=>({connected,revision:previous.revision+(notice?1:0),notice:notice?.eventos?.length?notice:previous.notice}))
      if(notice)window.dispatchEvent(new CustomEvent('tacticlens:monitor-invalidate',{detail:affectedDomains(notice)}))
    },()=>window.dispatchEvent(new Event('tacticlens:session-expired')))},0)
    return()=>{window.clearTimeout(timer);dispose?.()}
  },[])
  return <Context.Provider value={state}>{children}</Context.Provider>
}

export const useRealtime=()=>useContext(Context)

/** Domain invalidations share the serialized scheduler with periodic reconciliation. */
export function useMonitorQuery(refresh:(signal:AbortSignal)=>Promise<void>,delay=5000,
  dependencies:DependencyList=[],domains?:readonly MonitorDomain[]){
  const {connected}=useRealtime()
  const active=useRef(connected);active.current=connected
  usePolling(refresh,domains?()=>active.current?reconcile:Math.min(reconcile,15000):delay,dependencies,domains)
}
