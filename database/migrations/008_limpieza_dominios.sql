-- Remove filename false positives created during the initial observable backfill.
DELETE FROM honeypot.observacion_ioc o USING honeypot.ioc i, honeypot.tipo_ioc t
 WHERE o.id_ioc=i.id_ioc AND i.id_tipo_ioc=t.id_tipo_ioc
   AND t.nombre='Dominio' AND o.estado_revision='pendiente'
   AND o.evidencia='Dominio escrito en un comando'
   AND lower(reverse(split_part(reverse(i.valor), '.', 1))) IN
       ('txt','py','service','json','jsonl','log','sh','bash','conf','cfg','ini','yaml','yml','xml','csv','db','sql','md','exe','dll','so','zip','tar','gz');
DELETE FROM honeypot.ioc i USING honeypot.tipo_ioc t
 WHERE i.id_tipo_ioc=t.id_tipo_ioc AND t.nombre='Dominio'
 AND lower(reverse(split_part(reverse(i.valor), '.', 1))) IN
       ('txt','py','service','json','jsonl','log','sh','bash','conf','cfg','ini','yaml','yml','xml','csv','db','sql','md','exe','dll','so','zip','tar','gz')
 AND NOT EXISTS
 (SELECT 1 FROM honeypot.observacion_ioc o WHERE o.id_ioc=i.id_ioc)
 AND NOT EXISTS (SELECT 1 FROM honeypot.deteccion_ioc d WHERE d.id_ioc=i.id_ioc);
