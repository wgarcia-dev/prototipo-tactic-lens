import assert from 'node:assert/strict'
import test from 'node:test'
import {evidencePath,responseEligible} from './evaluationModel.ts'

test('only a confirmed and verifiable current evaluation opens the response',()=>{
  const current={decision:'incidente_confirmado',evidencia_verificable:true,revision_actual:2,revision_evaluacion:2}
  assert.equal(responseEligible(current),true)
  assert.equal(responseEligible({...current,evidencia_verificable:false}),false)
  assert.equal(responseEligible({...current,revision_evaluacion:1}),false)
  assert.equal(responseEligible({...current,decision:'actividad_sospechosa'}),false)
})

test('event links preserve exact PostgreSQL bigint identifiers',()=>{
  assert.equal(evidencePath('fixture','9007199254740993'),'/sesiones/fixture?evento=9007199254740993')
})
