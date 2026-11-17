import {useEffect, useRef, type DependencyList} from 'react'
import {startPolling, type PollTask} from './polling'

export function usePolling(refresh: PollTask, delay = 1000, dependencies: DependencyList = [], invalidate = false) {
  const callback = useRef(refresh)
  callback.current = refresh
  useEffect(() => startPolling(signal => callback.current(signal), delay, {
    now: () => performance.now(),
    visible: () => document.visibilityState === 'visible',
    schedule: (run, wait) => window.setTimeout(run, wait),
    cancel: handle => window.clearTimeout(handle as number),
    subscribe: run => {
      document.addEventListener('visibilitychange', run)
      if(invalidate)window.addEventListener('tacticlens:monitor-invalidate', run)
      return () => {document.removeEventListener('visibilitychange', run);if(invalidate)window.removeEventListener('tacticlens:monitor-invalidate', run)}
    },
  }), [delay, invalidate, ...dependencies])
}
