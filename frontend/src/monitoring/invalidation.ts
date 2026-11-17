type State = {connected:boolean,revision:number}

/** Serialize this task with startPolling; connected idle cycles never query HTTP. */
export function invalidationTask(load:(signal:AbortSignal)=>Promise<void>,state:()=>State){
  let completed=-1
  return {
    reset(){completed=-1},
    async run(signal:AbortSignal){
      if(state().connected&&completed===state().revision)return
      do {
        const version=state().revision
        await load(signal)
        if(signal.aborted)return
        completed=version
      }while(state().connected&&completed!==state().revision)
    },
  }
}
