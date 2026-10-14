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
