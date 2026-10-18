# UltraSec V7 — preflight privado para evaluación SAST sin revisión humana obligatoria

Fecha: 2026-10-18. Alcance: comprobación local de **metadatos del propietario**, no datos gold públicos ni análisis de código. Aplazamiento de dos revisores humanos confirmado; **no** implica suplirlos con IA.

## Qué quedó integrado

Script: `ultrasec-v7/tools/private_holdout_preflight.py`. Ejecuta validaciones de consistencia en un JSONL de referencia. Los tests sintéticos en `ultrasec-v7/tests/test_private_holdout_preflight.py` cubren fuga entre splits por origen, CVE, mecanismos, commits y SHA-256 de contenidos; rechazan reglas post-hoc y oráculos sin testigo técnico. Requiere, por defecto, >=100 casos, >=12 CWE con positivos y negativos por cada CWE evaluado en **test**.

### Ejecución local, sin publicar corpus

```bash
python3 ultrasec-v7/tools/private_holdout_preflight.py \
  --input /ruta/privada/holdout_metadata.jsonl \
  --minimum-cases 100 --minimum-cwes 12
```

**NO** agregar el JSONL de entrada al repositorio, los logs de Actions, issues, comentarios de PR ni artefactos públicos. Usar un directorio privado con permisos restringidos. Los tests de CI sólo usan registros **sintéticos**, nunca el corpus del propietario. El CLI imprime conteos y nombres genéricos de errores, no IDs, CVE, hashes ni código.

## Esquema por fila JSONL

- `case_id`: ID local opaco sin espacios.
- `cve_id`, `cwe_id`: referencia original y familia; no implica que el advisory no tenga errores.
- `project_fingerprint`, `mechanism_fingerprint`: SHA-256 calculados con un procedimiento canónico estable y controlado; cada fila debe usarlos de manera consistente para detectar alias entre train/test.
- `source_commit`, `fix_commit`: SHAs Git completos del mismo origen, sujetos a comprobación de ancestros fuera de este script.
- `source_sha256`, `fix_sha256`: hashes reales de bytes fuente. El verificador **no comprueba** que correspondan a esos commits.
- `split`: `train`, `validation` o `test`. No aceptar `UNASSIGNED`.
- `vulnerable`: booleano derivado de un oráculo causal, no de la predicción del detector.
- `oracle_type`: `ORIGINAL_RED_GREEN_TEST` o `INDEPENDENT_STATIC_CONTRACT`; `oracle_run_sha256` debe corresponder al log/test original verificable por separado.
- `rule_pre_registered`: booleano `true` únicamente cuando la regla y su versión quedaron fijadas **antes** de usar ese caso de test para afinar el detector. Una regla escrita tras estudiar el parche Moonlight debe marcarse `false`.
- `scanner_output_sha256`: SHA-256 de la salida original de escáner; el programa no reproduce ni verifica ese escaneo.

## Alcance estricto

Un `metadata_preflight_pass=true` significa **únicamente** que las afirmaciones suministradas tienen estructura coherente y no presentan los solapamientos exactos detectables por las claves entregadas. No confirma que la procedencia, las etiquetas, los hashes, la separación semántica, los derechos de redistribución, la preinscripción temporal o las predicciones sean auténticos. Necesitan comprobaciones sobre árboles Git, logs originales, normas SAST y un sellado externo al evaluador.

**Estado real actual:** no se proporcionó el inventario privado; `HOLDOUT_PRIVATE=NOT_VERIFIED`; `GOLD=0`; benchmark real de 100 casos `NOT_RUN`; certificación `NOT_CERTIFIED`. La fase de dos revisores externos sigue `DEFERRED`.

## Detección local complementaria de clones estructurales Python

Cuando el propietario tenga los archivos fuente privados, ejecutar **solo localmente** el nuevo `private_python_ast_screen.py` con un JSONL separado de cinco campos: `case_id`, `split` (train/validation/test), `language: python`, `vulnerable_source`, `fixed_source`. No ejecutar el código de los ejemplos; se analiza con `ast.parse` y se computan firmas SHA-256 sobre AST normalizados (identificadores y literales anonimizados).

```bash
python3 ultrasec-v7/tools/private_python_ast_screen.py \
  --input /ruta/privada/pares_python_para_auditoria.jsonl
```

**Un choque entre train y test o dentro del test requiere revisión manual del mecanismo** y el programa devuelve error. La ausencia de colisiones no acredita independencia causal; otras lenguas (JavaScript, PHP, C) requieren analizadores propios y análisis de flujo de datos. Los resultados impresos son solo conteos/errores agregados: no compartir el JSONL privado, sus hashes o código en Actions, issues ni PR.

