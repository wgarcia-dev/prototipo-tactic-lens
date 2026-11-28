import {test} from 'node:test'
import assert from 'node:assert/strict'
import {affectedDomains,monitorDomains,watchesDomain} from './socket.ts'
import {startPolling} from './polling.ts'

test('only queries for committed domains are invalidated',()=>{
  const changed=affectedDomains({tipo:'cambio',dominios:['mitre','salvaguardas','unknown']})
  assert.deepEqual(changed,['mitre','salvaguardas'])
  assert.equal(watchesDomain(['sesiones','analisis'],changed),false)
  assert.equal(watchesDomain(['mitre'],changed),true)
  assert.equal(watchesDomain(['salvaguardas'],changed),true)
})

test('reconnect or an older worker covering legacy messages reconciles every screen',()=>{
  assert.deepEqual(affectedDomains({tipo:'listo'}),monitorDomains)
  assert.deepEqual(affectedDomains({tipo:'cambio',eventos:[1]}),monitorDomains)
})

test('connected reconciliation uses its configured interval and coalesces during a request',async()=>{
  let pending,notify,finish,calls=0
  const tick=()=>new Promise(resolve=>setImmediate(resolve))
  const stop=startPolling(async()=>{
    if(++calls===1)await new Promise(resolve=>{finish=resolve})
  },()=>30000,{
    now:()=>0,visible:()=>true,
    schedule:(fn,delay)=>{pending={fn,delay};return 1},
    cancel:()=>{pending=undefined},subscribe:on=>{notify=on;return()=>{}}
  })
  notify();notify()
  assert.equal(calls,1)
  finish()
  await tick()
  assert.equal(pending.delay,50)
  pending.fn()
  await tick()
  assert.equal(calls,2)
  assert.equal(pending.delay,30000)
  pending.fn()
  await tick()
  assert.equal(calls,3)
  stop()
})
