export const monitorDomains = ['sesiones','analisis','iocs','mitre','salvaguardas','panel'] as const
export type MonitorDomain = typeof monitorDomains[number]
export type Notice = {tipo:string, epoca?:string, revision?:number, dominios?:MonitorDomain[], recibido_api?:string, confirmado_api?:string, eventos?:number[]}

export function affectedDomains(notice: Notice): readonly MonitorDomain[] {
  if (notice.tipo === 'listo' || notice.dominios === undefined) return monitorDomains
  return monitorDomains.filter(domain => notice.dominios?.includes(domain))
}

export function watchesDomain(watched:readonly MonitorDomain[], changed:readonly MonitorDomain[]) {
  return watched.some(domain => changed.includes(domain))
}
type Socket = Pick<WebSocket,'send'|'close'> & {
  readyState?:number
  onopen: ((event: Event) => void)|null
  onmessage: ((event: MessageEvent) => void)|null
  onclose: ((event: CloseEvent) => void)|null
  onerror: ((event: Event) => void)|null
}
export type SocketEnvironment = {
  connect:()=>Socket, now:()=>number, random:()=>number,
  schedule:(fn:()=>void,ms:number)=>unknown, cancel:(id:unknown)=>void,
  visible:()=>boolean, subscribe:(fn:()=>void)=>()=>void,
}

export function startMonitor(env:SocketEnvironment, update:(connected:boolean,notice?:Notice)=>void, expired:()=>void) {
  let stopped=false, denied=false, socket:Socket|undefined, timer:unknown, watchdog:unknown, failures=0, seen=0
  const cancel=()=>{env.cancel(timer);env.cancel(watchdog)}
  const retire=()=>{
    const old=socket;socket=undefined
    if(!old)return
    old.onclose=null;old.onmessage=null;old.onerror=null;old.onopen=null
    // Let an in-flight upgrade complete before sending a normal close frame.
    // Aborting CONNECTING sockets produces ECONNABORTED in the Windows proxy.
    if(old.readyState===0)old.onopen=()=>{old.onopen=null;old.close()}
    else old.close()
  }
  function open(){
    if(stopped||denied||!env.visible()||socket)return
    try {
      const current=env.connect();socket=current;seen=env.now()
      const check=()=>{
        if(socket!==current)return
        if(env.now()-seen>45000){current.close();return}
        watchdog=env.schedule(check,15000)
      }
      watchdog=env.schedule(check,15000)
      current.onmessage=event=>{
        if(socket!==current)return
        try {
          if(typeof event.data!=='string'||event.data.length>65536){current.close();return}
          const notice=JSON.parse(event.data) as Notice
          seen=env.now()
          if(notice.tipo==='ping'){current.send('pong');return}
          if(notice.tipo==='listo'){failures=0;update(true,notice)}
          else if(notice.tipo==='cambio')update(true,notice)
        }catch{current.close()}
      }
      current.onclose=event=>{
        if(socket!==current)return
        socket=undefined;env.cancel(watchdog);update(false)
        if(event.code===4401){denied=true;expired();return}
        if(!stopped&&env.visible())timer=env.schedule(open,Math.min(30000,1000*2**Math.min(failures++,5))*(0.8+env.random()*0.4))
      }
      current.onerror=()=>current.close()
    }catch{update(false);timer=env.schedule(open,5000)}
  }
  const unsubscribe=env.subscribe(()=>{cancel();if(!env.visible()){retire();update(false)}else open()})
  open()
  return ()=>{stopped=true;cancel();unsubscribe();retire()}
}
