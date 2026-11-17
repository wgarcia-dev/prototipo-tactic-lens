export type PollTask = (signal: AbortSignal) => Promise<void>

export type PollEnvironment = {
  now: () => number
  visible: () => boolean
  schedule: (run: () => void, delay: number) => unknown
  cancel: (handle: unknown) => void
  subscribe: (run: () => void) => () => void
}

export function startPolling(task: PollTask, interval: number, env: PollEnvironment) {
  let stopped = false, running = false, failures = 0, wake = false
  let timer: unknown
  let controller: AbortController | undefined
  const cancelTimer = () => { if (timer !== undefined) env.cancel(timer); timer = undefined }
  async function run() {
    cancelTimer()
    if (stopped || running || !env.visible()) return
    running = true
    const started = env.now()
    controller = new AbortController()
    try { await task(controller.signal); failures = 0 }
    catch { if (!controller.signal.aborted) failures++ }
    finally {
      running = false
      controller = undefined
      if (!stopped && env.visible()) {
        const period = Math.min(interval * 2 ** Math.min(failures, 4), 15000)
        timer = env.schedule(() => { void run() }, wake?50:Math.max(50, period - (env.now() - started)))
        wake=false
      }
    }
  }
  const unsubscribe = env.subscribe(() => {
    cancelTimer()
    if (!env.visible()) controller?.abort()
    else if(running)wake=true
    else void run()
  })
  void run()
  return () => { stopped = true; cancelTimer(); controller?.abort(); unsubscribe() }
}

export function sameSnapshot<T>(previous: T, next: T): T {
  return JSON.stringify(previous) === JSON.stringify(next) ? previous : next
}
