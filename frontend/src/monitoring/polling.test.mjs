import {test} from 'node:test'
import assert from 'node:assert/strict'
import {setImmediate} from 'node:timers/promises'
import {startPolling, sameSnapshot} from './polling.ts'

const settle = () => setImmediate()
function clock() {
  let now = 0, visible = true, sequence = 0
  const timers = new Map(), listeners = new Set()
  return {
    env: {
      now: () => now, visible: () => visible,
      schedule: (run, delay) => { const id=++sequence;timers.set(id,{run,at:now+delay});return id },
      cancel: id => timers.delete(id),
      subscribe: run => { listeners.add(run);return () => listeners.delete(run) },
    },
    async advance(ms) {
      const end=now+ms
      while(true) {
        const next=[...timers.entries()].filter(([,job])=>job.at<=end).sort((a,b)=>a[1].at-b[1].at)[0]
        if(!next)break
        now=next[1].at;timers.delete(next[0]);next[1].run();await settle()
      }
      now=end;await settle()
    },
    visibility(value) { visible=value;for(const run of listeners)run() },
    pending: () => timers.size,
    listeners: () => listeners.size,
  }
}

test('consulta inmediata y ciclos sanos cada 1000 ms',async()=>{
  const c=clock();let calls=0
  const stop=startPolling(async()=>{calls++},1000,c.env)
  await settle();await c.advance(999);assert.equal(calls,1)
  await c.advance(1);assert.equal(calls,2)
  await c.advance(1000);assert.equal(calls,3);stop()
})

test('una respuesta lenta no genera consultas simultaneas, tampoco al recuperar visibilidad',async()=>{
  const c=clock();let calls=0,resolve
  const stop=startPolling(()=>{calls++;return new Promise(done=>{resolve=done})},1000,c.env)
  await c.advance(5000);assert.equal(calls,1)
  c.visibility(false);c.visibility(true);assert.equal(calls,1)
  resolve();await settle();await c.advance(49);assert.equal(calls,1)
  await c.advance(1);assert.equal(calls,2)
  stop();resolve();await settle();assert.equal(c.pending(),0)
})

test('pestana oculta pausa consultas y al regresar consulta inmediatamente',async()=>{
  const c=clock();let calls=0
  const stop=startPolling(async()=>{calls++},1000,c.env)
  await settle();c.visibility(false);await c.advance(10000);assert.equal(calls,1)
  c.visibility(true);await settle();assert.equal(calls,2);stop()
})

test('desmontar cancela la solicitud y no reprograma respuestas tardias',async()=>{
  const c=clock();let signal,resolve
  const stop=startPolling(value=>{signal=value;return new Promise(done=>{resolve=done})},1000,c.env)
  stop();assert.equal(signal.aborted,true);resolve();await settle()
  assert.equal(c.pending(),0);assert.equal(c.listeners(),0)
})

test('fallos aplican espera progresiva y la recuperacion vuelve a un segundo',async()=>{
  const c=clock();let calls=0
  const stop=startPolling(async()=>{if(++calls===1)throw new Error('offline')},1000,c.env)
  await settle();await c.advance(1999);assert.equal(calls,1)
  await c.advance(1);assert.equal(calls,2)
  await c.advance(1000);assert.equal(calls,3);stop()
})

test('datos sin cambios conservan identidad para no reiniciar componentes visuales',()=>{
  const old=[{id:1,value:4}]
  assert.equal(sameSnapshot(old,[{id:1,value:4}]),old)
  assert.notEqual(sameSnapshot(old,[{id:1,value:5}]),old)
})
