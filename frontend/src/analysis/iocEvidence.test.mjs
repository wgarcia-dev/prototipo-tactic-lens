import assert from 'node:assert/strict'
import {createRequire} from 'node:module'
import {fileURLToPath} from 'node:url'
import test from 'node:test'
import {build} from 'esbuild'
import {createElement} from 'react'
import {renderToStaticMarkup} from 'react-dom/server'
import {MemoryRouter} from 'react-router-dom'
import {
  actionEvidencePath, behaviorLabels, eventEvidencePath, evidenceLabels, mappingEvidencePath,
  mappingClassificationLabel, mappingReviewLabels, mitreGradeLabels, observableEvidencePath, relationLabels, reportEventIds, reviewLabels, scopeLabels, sessionEvidencePath,
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
test('automatic MITRE mappings are identified independently of historical and manual review states', () => {
  const rag_procedencia = {clasificacion:'identificada_automaticamente'}
  assert.equal(mappingClassificationLabel({estado_revision:'pendiente',rag_procedencia}), 'Identificada automáticamente')
  assert.equal(mappingClassificationLabel({estado_revision:'pendiente'}), 'Histórico · pendiente de revisión')
  assert.equal(mappingClassificationLabel({estado_revision:'descartado',rag_procedencia}), 'Descartada por revisión')
  assert.equal(mitreGradeLabels.resultado_en_honeypot, 'Resultado observado en el honeypot')
  assert.deepEqual(reportEventIds('#9234567890123456, #12'), ['9234567890123456','12'])
  assert.deepEqual(reportEventIds('Sin citas verificables'), [])
})

test('React renders automatic classification, tactic, evidence grade and the exact event link', async () => {
  const {outputFiles} = await build({entryPoints:[fileURLToPath(new URL('./IocCorrelations.tsx',import.meta.url))],
    bundle:true, write:false, format:'cjs', platform:'node', packages:'external', jsx:'automatic'})
  const compiled = {exports:{}}
  new Function('module','exports','require',outputFiles[0].text)(compiled,compiled.exports,createRequire(import.meta.url))
  const {MappingStatus, MappingBasis} = compiled.exports
  const mapping = {estado_revision:'pendiente', codigo_tactica:'TA0011', tactica:'Command and Control',
    grado_evidencia:'intento', justificacion:'Orden de descarga observada',
    rag_procedencia:{clasificacion:'identificada_automaticamente',modalidad:'cowrie_shell'},
    eventos:[{id_evento:'9234567890123456',id_sesion:'fixture',tipo_evento:'cowrie.command.input',fecha_hora:'2026-11-23T00:00:00Z'}]}
  const html=renderToStaticMarkup(createElement(MemoryRouter,null,
    createElement(MappingStatus,{mapping}),createElement(MappingBasis,{mapping})))
  assert.match(html,/Identificada automáticamente/)
  assert.match(html,/TA0011 · Command and Control · Intento · cowrie_shell/)
  assert.match(html,/href="\/sesiones\/fixture\?evento=9234567890123456"/)
  assert.doesNotMatch(html,/Mapeo pendiente/)
})
