import assert from 'node:assert/strict'
import test from 'node:test'
import {
  actionEvidencePath, behaviorLabels, eventEvidencePath, evidenceLabels, mappingEvidencePath,
  mappingReviewLabels, observableEvidencePath, relationLabels, reviewLabels, scopeLabels, sessionEvidencePath,
} from './iocEvidence.ts'

test('Cowrie outcomes distinguish a reference, an attempt, a recorded download and a failure', () => {
  assert.deepEqual([
    evidenceLabels.referencia, evidenceLabels.intento,
    evidenceLabels.resultado_registrado, evidenceLabels.fallo_registrado,
  ], ['Referencia', 'Intento', 'Resultado registrado', 'Fallo registrado'])
  assert.equal(behaviorLabels.descarga_registrada, 'Descarga registrada por Cowrie')
  assert.equal(behaviorLabels.descarga_fallida, 'Descarga fallida')
})

test('review and IP scope labels communicate relevance and historical coverage', () => {
  assert.equal(reviewLabels.confirmado, 'Relevancia confirmada')
  assert.equal(reviewLabels.pendiente, 'Pendiente')
  assert.equal(reviewLabels.historico, 'Histórico por verificar')
  assert.equal(scopeLabels.privada, 'IP privada')
})

test('the evidence link routes to an internal session even for a malformed session identifier', () => {
  assert.equal(sessionEvidencePath('f7f851a4-b134-456d-a800-000000000001'),
    '/sesiones/f7f851a4-b134-456d-a800-000000000001')
  assert.equal(sessionEvidencePath('//host.local/id?value'), '/sesiones/%2F%2Fhost.local%2Fid%3Fvalue')
})

test('the review of a mapping stays separate from the strength of a relationship', () => {
  assert.deepEqual(Object.values(relationLabels), [
    'Relación directa', 'Relación contextual', 'Candidata a revisión', 'Evidencia insuficiente',
  ])
  assert.deepEqual(Object.values(mappingReviewLabels), [
    'Mapeo pendiente', 'Mapeo confirmado', 'Mapeo descartado',
  ])
})

test('evidence links carry the precise event, saved analysis, action and mapping', () => {
  const largeEvent = '6111111111111111117'
  assert.equal(eventEvidencePath('session', largeEvent), '/sesiones/session?evento='+largeEvent)
  assert.equal(observableEvidencePath('id/ioc', largeEvent), '/iocs?ioc=id%2Fioc&evento='+largeEvent)
  assert.equal(actionEvidencePath('session', 'old', 'action'), '/sesiones/session?analisis=old&accion=action')
  assert.equal(mappingEvidencePath('id/mapping'), '/mitre?mapeo=id%2Fmapping')
})
