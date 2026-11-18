import {test} from 'node:test'
import assert from 'node:assert/strict'
import {startMonitor} from './socket.ts'

function fixture(){
  let at=0,visible=true,listener,seq=0
  const timers=new Map(),sockets=[],updates=[]
  const env={connect:()=>{const socket={send:value=>socket.sent.push(value),sent:[],closed:0,close:()=>socket.closed++};sockets.push(socket);return socket},
    now:()=>at,random:()=>0.5,schedule:(fn,ms)=>{const id=++seq;timers.set(id,{fn,at:at+ms});return id},cancel:id=>timers.delete(id),
    visible:()=>visible,subscribe:fn=>{listener=fn;return()=>{listener=null}}}
  let expired=0
  const stop=startMonitor(env,(...args)=>updates.push(args),()=>expired++)
  return {sockets,updates,stop,timers,expired:()=>expired,
    message:body=>sockets.at(-1).onmessage({data:JSON.stringify(body)}),
    visibility:v=>{visible=v;listener()},
    advance(ms){at+=ms;for(const [id,timer] of [...timers])if(timer.at<=at){timers.delete(id);timer.fn()}}}
}
test('ready and committed invalidations notify, heartbeat does not refetch',()=>{
  const f=fixture();f.message({tipo:'listo'});f.message({tipo:'cambio',revision:2});f.message({tipo:'ping'})
  assert.equal(f.updates.length,2);assert.deepEqual(f.sockets[0].sent,['pong']);f.stop()
})
test('reconnect resynchronizes, stale callbacks and hidden tabs cannot update',()=>{
  const f=fixture(),old=f.sockets[0];old.onclose({code:1006});f.advance(1000)
  assert.equal(f.sockets.length,2);f.message({tipo:'listo',revision:7});assert.equal(f.updates.at(-1)[1].revision,7)
  f.visibility(false);assert.equal(f.sockets[1].onmessage,null);f.visibility(true);assert.equal(f.sockets.length,3)
  f.stop();assert.equal(f.timers.size,0)
})
test('revoked session never reconnects and emits session expiration',()=>{
  const f=fixture();f.sockets[0].onclose({code:4401});f.advance(60000)
  assert.equal(f.expired(),1);assert.equal(f.sockets.length,1);f.stop()
})
test('watchdog closes a silent connection; invalid JSON is rejected',()=>{
  const f=fixture();f.advance(46000);assert.equal(f.sockets[0].closed,1)
  f.sockets[0].onmessage({data:'{invalid'});assert.equal(f.sockets[0].closed,2);f.stop()
})
