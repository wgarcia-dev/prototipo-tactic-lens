import {useEffect, useRef, type DependencyList} from 'react'
import {startPolling, type PollTask} from './polling'
import {watchesDomain,type MonitorDomain} from './socket'

export function usePolling(refresh: PollTask, delay: number | (()=>number) = 1000, dependencies: DependencyList = [], domains?:readonly MonitorDomain[]) {
  const callback = useRef(refresh)
  callback.current = refresh
  const period = useRef(delay); period.current = delay
  const watched = useRef(domains); watched.current = domains
  const invalidation = domains !== undefined
  useEffect(() => startPolling(signal => callback.current(signal), () => typeof period.current==='function'?period.current():period.current, {
    now: () => performance.now(),
    visible: () => document.visibilityState === 'visible',
    schedule: (run, wait) => window.setTimeout(run, wait),
    cancel: handle => window.clearTimeout(handle as number),
    subscribe: run => {
      const notify = (event:Event) => {
        const changed = (event as CustomEvent<readonly MonitorDomain[]>).detail
        if (watched.current && watchesDomain(watched.current,changed)) run()
      }
      document.addEventListener('visibilitychange', run)
      if(invalidation)window.addEventListener('tacticlens:monitor-invalidate', notify)
      return () => {document.removeEventListener('visibilitychange', run);if(invalidation)window.removeEventListener('tacticlens:monitor-invalidate', notify)}
    },
  }), [invalidation, ...dependencies])
}
