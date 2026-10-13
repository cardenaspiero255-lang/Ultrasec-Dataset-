# UltraSec V7 — expediente de calidad técnica pública (muestra)

## Alcance estricto

Este informe se refiere **solo a una muestra de referencia pública y abstracta**, no al dataset privado, ni a exploits ejecutables, ni a 500 mecanismos causales independientes. La muestra contiene 24 pares / 48 grafos declarativos en 6 CWE y tres etiquetas de lenguaje de implementación (Python, JavaScript y Go); esos grafos se ejecutan exclusivamente en un simulador Python. **No son 48 implementaciones Python/JavaScript/Go en producción.**

## Siete controles técnicos y qué prueban

1. **UltraSec Core**: 24 pares completos con hashes y etiquetas causales consistentes; CWE disjuntas entre train, validation y test. Unicidad verificada sobre las 48 estructuras de referencia, no sobre el millón.
2. **Dataset Build**: recomputación determinista del archivo de referencia y SHA-256 comparado con manifiesto.
3. **Unit Test Coverage**: tests y cobertura de ramas medidos en CI sobre el **validador público**. La puerta falla por debajo de 85 % de cobertura total; no corresponde a porcentaje de vulnerabilidades auditadas.
4. **Mutation Lab**: 48 mutaciones introducidas expresamente en contratos de etiqueta/protección y detectadas por el evaluador causal. No son mutaciones de miles de proyectos reales.
5. **Adversarial Gauntlet**: 101 casos de corrupción semántica/metadatos/etiquetas/grafos detectados o rechazados.
6. **Self-Review Gate**: inspección AST del validador y política de seguridad del workflow (token de solo lectura, SHA completo para checkout, jobs fijos, sin secretos).
7. **Reliability — 100**: reconstrucción y validación repetidas cien veces y comparadas mediante huella estable.

Los siete checks de **documentación pública** anteriores se conservan separados y no sustituyen los nuevos.

## Evidencia comercial permitida

Se puede afirmar que GitHub Actions ejecutó estas pruebas **solamente** después de observar los siete jobs completados con `success` en el commit actual. Citar la ejecución y los hashes. Ningún resultado certifica el corpus privado ni un precio de venta.

## Puertas de acreditación pendientes

- Integrar ejecuciones reales sobre el corpus propietario en almacenamiento/control de acceso privado, sin revelar los ejemplos ni las respuestas.
- Medir recall, precisión, falsos positivos y negativos frente a SAST externos ejecutados de verdad (Semgrep y CodeQL sobre código relevante, no sobre el verificador documental).
- Independencia causal contrastada y splits por proyecto y mecanismo, pruebas funcionales reales de mitigaciones, revisión humana ciega y auditoría externa firmada.
- Procedencia, derechos de redistribución, términos comerciales y evaluación con compradores; no inferir automáticamente una valoración a partir de CI verde.

**Certificación externa:** PENDIENTE. **Precio acreditado:** NO VERIFICADO.