import assert from 'node:assert/strict'
import {test} from 'node:test'
import {available,moves,laneOf,pathFor} from './model.ts'

const action={estado_respuesta:'en_respuesta',estado:'propuesta',id_responsable:'fixture',
  revision_validada:1,revision_evaluacion_actual:1,desactualizada:false}

test('only an administrator approves or verifies and only the assignee starts a task',()=>{
  assert.deepEqual(available(action,false,'fixture'),[])
  assert.deepEqual(moves(action,true),{aprobadas:'aprobar'})
  const approved={...action,estado:'aprobada'}
  assert.deepEqual(moves(approved,false,'otro'),{})
  assert.deepEqual(moves(approved,false,'fixture'),{en_curso:'iniciar'})
  const executed={...action,estado:'ejecutada'}
  assert.deepEqual(moves(executed,true),{aprobadas:'devolver',finalizadas:'verificar'})
  assert.deepEqual(moves(executed,false,'fixture'),{})
})

test('stale evaluations permit documenting existing work without authorizing new work',()=>{
  const stale={...action,estado:'en_curso',revision_evaluacion_actual:2,desactualizada:true}
  assert.deepEqual(available(stale,false,'fixture'),['avanzar','ejecutar'])
  assert.deepEqual(moves({...stale,estado:'aprobada'},true),{})
  assert.deepEqual(available({...stale,estado_respuesta:'cerrado'},true),[])
})

test('terminal action states share a lane and incident routes are stable',()=>{
  for(const state of ['rechazada','verificada','cancelada'])assert.equal(laneOf(state),'finalizadas')
  assert.equal(pathFor('fixture'),'/incidentes/fixture/respuesta')
})
