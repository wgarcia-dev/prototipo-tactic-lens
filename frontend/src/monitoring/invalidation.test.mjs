import {test} from 'node:test'
import assert from 'node:assert/strict'
import {invalidationTask} from './invalidation.ts'

test('connected idle cycles make no HTTP requests; filter changes and reconnect resync',async()=>{
  const state={connected:true,revision:1};let count=0
  const task=invalidationTask(async()=>{count++},()=>state),signal=new AbortController().signal
  await task.run(signal);await task.run(signal);await task.run(signal);assert.equal(count,1)
  task.reset();await task.run(signal);assert.equal(count,2)
  state.revision++;await task.run(signal);assert.equal(count,3)
  state.connected=false;await task.run(signal);await task.run(signal);assert.equal(count,5)
})
test('invalidation during a slow response is not lost and never overlaps loads',async()=>{
  const state={connected:true,revision:1};let finish,calls=0,running=0,maximum=0
  const task=invalidationTask(async()=>{running++;maximum=Math.max(maximum,running);if(++calls===1)await new Promise(resolve=>{finish=resolve});running--},()=>state)
  const result=task.run(new AbortController().signal);state.revision=2;finish();await result
  assert.equal(calls,2);assert.equal(maximum,1)
})
test('failed fetch never consumes the pending invalidation',async()=>{
  let calls=0;const task=invalidationTask(async()=>{if(++calls===1)throw new Error('offline')},()=>({connected:true,revision:1}))
  const signal=new AbortController().signal
  await assert.rejects(task.run(signal));await task.run(signal);assert.equal(calls,2)
})
