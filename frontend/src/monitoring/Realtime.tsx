import {createContext,useContext,useEffect,useRef,useState,type DependencyList,type ReactNode} from 'react'
import {startMonitor,type Notice} from './socket'
import {usePolling} from './usePolling'
import {invalidationTask} from './invalidation'

const Context=createContext({connected:false,revision:0,notice:null as Notice|null})
export function RealtimeProvider({children}:{children:ReactNode}){
  const [state,setState]=useState({connected:false,revision:0,notice:null as Notice|null})
  useEffect(()=>startMonitor({
    connect:()=>new WebSocket(`${location.protocol==='https:'?'wss:':'ws:'}//${location.host}/api/monitor/ws`,'tacticlens.monitor.v1'),
    now:()=>Date.now(),random:()=>Math.random(),
    schedule:(fn,ms)=>window.setTimeout(fn,ms),cancel:id=>window.clearTimeout(id as number),
    visible:()=>document.visibilityState==='visible',
    subscribe:fn=>{document.addEventListener('visibilitychange',fn);return()=>document.removeEventListener('visibilitychange',fn)},
  },(connected,notice)=>setState(previous=>({connected,revision:previous.revision+(notice?1:0),notice:notice??previous.notice})),
  ()=>window.dispatchEvent(new Event('tacticlens:session-expired'))),[])
  return <Context.Provider value={state}>{children}</Context.Provider>
}
export const useRealtime=()=>useContext(Context)

/** Immediate fetch on invalidation, serialized and coalesced during a slow request.
 * Only a disconnected WebSocket enables the slower 15-second fallback.
 */
export function useMonitorQuery(refresh:(signal:AbortSignal)=>Promise<void>,delay=1000,dependencies:DependencyList=[]){
  const live=useRealtime(), realtime=delay===1000
  const current=useRef(refresh);current.current=refresh
  const state=useRef(live);state.current=live
  const task=useRef<ReturnType<typeof invalidationTask>|null>(null)
  if(!task.current)task.current=invalidationTask(signal=>current.current(signal),()=>state.current)
  useEffect(()=>{task.current!.reset()},dependencies)
  // Existing non-monitoring screens retain their original cadence.
  usePolling(async signal=>{
    if(!realtime){await current.current(signal);return}
    await task.current!.run(signal)
  },realtime?15000:delay,[...dependencies],realtime)
  // Wake the active scheduler via a custom event without creating a second fetch.
  useEffect(()=>{if(realtime)window.dispatchEvent(new Event('tacticlens:monitor-invalidate'))},[live.revision,realtime])
}
