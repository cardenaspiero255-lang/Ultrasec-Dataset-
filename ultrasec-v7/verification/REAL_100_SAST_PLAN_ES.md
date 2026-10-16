# Auditoría de CodeQL, Semgrep y Slither en 100 casos reales (plan ejecutable)

**No se ha ejecutado este estudio sobre 100 casos reales en el PR.** El repositorio público carece de estos casos y de licencias para redistribuirlos. Los escáneres de CI públicos analizan solo el validador público, por lo que esos checks **NO** son los resultados del corpus privado.

## Admisión y reproducibilidad

Antes de ejecutar: dos revisores humanos firman el gold o el adjudicador fija la verdad; validar repositorio y commits fuente/parche, derechos de uso, versión de toolchains y proyecto held-out. Ejecutar en VM/runner privado sin egress no aprobado y con controles de acceso al holdout. Conservar digest de cada fuente, contenedor, reglas, salida SARIF/JSON, stderr y código de retorno; almacenar evidencias y logs en directorio privado.

## Herramientas y aplicabilidad

| Tool | Lenguajes y tarea | Comando orientativo de ejecución local | Motivo de no detección a documentar |
|---|---|---|---|
| CodeQL | C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Rust, Swift según pack/versión compatible; no asumir otras lenguas | codeql database create DATABASE --language=LANG --source-root=OWNER_SOURCE ; codeql database analyze DATABASE QUERY_SUITE --format=sarifv2.1.0 --output=PRIVATE_OUTPUT.sarif | Query inexistente, build incompleto, base de datos fallida, flujo no modelado |
| Semgrep OSS | Lenguajes cubiertos por parser/reglas instaladas; no equivale a taint analysis exhaustivo | semgrep scan --config CONFIG_PINNED --json --output PRIVATE_OUTPUT.json OWNER_SOURCE | Regla CWE ausente, patrón fuera de alcance, parser falla, propagación compleja |
| Slither | **Solo Solidity/Vyper**, requiere compilador/toolchain compatible | slither OWNER_SOLIDITY_PROJECT --json PRIVATE_OUTPUT.json | No aplica a C/Go/Java/Rust/Python, sin detector, no compila, fallo de análisis |

Consultas, reglas, imágenes de ejecución, bases de datos y compiladores deben fijarse por versión y hash. La compatibilidad real se verifica con el comando y su exit code, no con una tabla. Para Rust y lenguajes recientes verificar el CodeQL CLI y pack fijados. No ejecutar un scanner no aplicable para crear un TN ficticio.

## Registro por hallazgo y CWE

El escáner debe producir una fila por herramienta y caso, con case_id opaco, versión, hash de reglaset, CWE evaluado, si se ejecutó, si hubo regla aplicable, detected=true/false, causa de cobertura (rule_applied, no_rule, not_applicable, unsupported_language, tool_failed), hash de SARIF/JSON y mapeo documentado regla→CWE.

Después de ejecutar, el propietario convierte evidencias a la entrada de adversarial_sast.summarize_sast. El script calcula TP, TN, FP, FN, precisión, recall y tasa FP agrupados por CWE. La procedencia de la evidencia, la autenticidad de la ejecución, los parciales por CWE y las correcciones de fallo necesitan una auditoría externa; el script por sí solo **no ejecuta los escáneres**.

## Reglas de no autoengaño

- Aceptar un FN cuando la herramienta no detecta una vulnerabilidad verificable; explicar si se debió a no_rule o limitación de data-flow.
- Distinguir fallo de ejecución de un falso negativo; no descartar silenciosamente fallos de build ni usar denominadores favorables.
- Nunca inferir que la ausencia de reglas es señal de alto grado de dificultad ni mérito de UltraSec.
- Recall por CWE <20% es resultado negativo (o evidencia insuficiente si la muestra no es apta); no convertirlo en logro ni en promesa de superioridad.
- Reportar verdaderos negativos en los casos no vulnerables del mismo holdout, intervalos de incertidumbre, número de casos y proyectos independientes, además de micro y macro promedios.
- No comparar directamente métricas entre lenguajes/distribuciones distintas de DiverseVul y PrimeVul. Debe repetirse sobre un holdout común, con gold revisado y sin fuga.

**Estado esperado del PR #7:** CI puede demostrar que el calculador falla de manera conservadora ante no_rule, no_aplicable y missing_result, pero las métricas reales de CodeQL/Slither/Semgrep sobre 100 casos siguen NOT_RUN hasta que existan casos externos elegibles.

## Fase previa: selección de CVE candidatas (investigación del 16-10-2026)

Fuentes públicas identificadas:
- MoreFixes v4 (20-06-2026): https://zenodo.org/records/20776007 — aproximadamente 43.357 CVE y 47.616 commits de corrección referenciados; descargables como dump SQL de 3,5 GB y parches de 3,0 GB. El **propio productor** avisa que las licencias de los repositorios de origen varían: NO hay una autorización general de reventa.
- CVEfixes v1.0.8 (hasta 23-07-2024): https://github.com/secureIT-project/CVEfixes y https://zenodo.org/records/13118970 — fuente complementaria, no fuente de derechos comerciales.
- Tareas, exclusiones y estado de evidencias: https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/issues/9

### Importar referencias *sin* publicar el dataset
1. En un entorno **local y privado**, obtener de una fuente confiable una exportación JSONL de referencias CVE→repositorio/commits. No cargar código privado, gold, credenciales o llaves al PR.
2. Cada fila debe tener `cve_id`, `cwe_id`, `repo_url` (URL HTTPS de GitHub con owner y repo), `source_commit` y `fix_commit` (SHA completos de 40 caracteres), `source_dataset` (`MoreFixes v4` o `CVEfixes v1.0.8`). Para MoreFixes se exige además `score` numérico ≥65 conforme a la recomendación del proyecto original; esta puntuación es una **heurística**, no prueba causal.
3. Ejecutar en privado `python3 ultrasec-v7/tools/real_case_candidate_triage.py PRIVATE_CANDIDATES.jsonl`. El programa selecciona hasta 100 proyectos distintos y da prioridad a 12 CWE; solo emite conteos sanitizados, nunca vulnerabilidades ni licencias inventadas. El PASS significa **metadatos candidatos completos, no casos admitidos**.
4. Verificar **cada una** de las referencias con advisory/CVE, SHA origen y parche, reproducción segura, árbol de dependencias, licencia y permisos del titular. Rechazar falsos fix commits, CVE aliases, versiones incorrectas, forks duplicados y proyectos con filtración hacia train.
5. Solo entonces crear el archivo privado de 100 casos para `premium_evidence.admission_report`. Los campos de verificación autodeclarados de esta API también necesitan evidencia independiente real y custodia sellada.
6. Ejecutar scanner real **solo sobre código autorizado**, con salida privada por CWE y herramienta, versiones y reglas fijadas; validar firmas y roles de revisores independientes mediante un proceso separado.

**Estado al 16-10-2026:** fuentes investigadas, 0/100 casos externamente admitidos en este PR, 0/2 firmas independientes, 0 escaneos reales sobre esa cohorte, redistribución/reventa NO VERIFICADA. No confundir esto con 16 jobs verdes del verificador público ni con certificación comercial.
