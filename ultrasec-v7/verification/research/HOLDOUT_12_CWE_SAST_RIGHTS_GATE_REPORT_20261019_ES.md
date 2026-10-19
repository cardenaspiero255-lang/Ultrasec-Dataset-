# UltraSec Dataset V7 — informe de ejecución de los gates 3, 4 y 5

**Corte:** 19-10-2026. **ALCANCE TÉCNICO, NO CERTIFICACIÓN.** `GOLD=0`; no se recibió un TRAIN completo ni un HOLDOUT auténtico, y **no se ejecutó benchmark SAST ciego sobre casos privados**. Doble revisión humana expresamente aplazada: no se declara satisfecha ni se introduce como requisito para estos ensayos técnicos.

## 3. TRAIN / TEST — dos fallos reales encontrados y corregidos

El comparador privado `tools/private_training_disjointness.py` ya tenía exclusiones por CVE, proyecto, mecanismo, commits, contenido y el inventario de **63 públicos + 37 referencias históricas privadas**. Este ciclo descubrió que los umbrales `>=100` filas TRAIN / `>=100` filas TEST podían incluir duplicados internos no detectados.

- **TDD RED**: [GitHub Actions #39291626574](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39291626574), commit `d578cc6240ca530e7d6622e0a8b3860f85228472`. Se observaron cinco fallos reales al duplicar IDs de TRAIN, pares completos de commits y hashes originales dentro de TRAIN/TEST, o reutilizar en TEST una versión como parche de otro caso.
- **GREEN**: commit `89625ef2d8192c03319c75210b40b59f529dd383`. Rechaza `duplicate_train_case_id`, `duplicate_train_original_pair`, `duplicate_train_content_pair`, `duplicate_test_original_pair`, `duplicate_test_content_pair` y `shared_test_content_requires_grouping`.
- El valor `metadata_separation_pass` sigue siendo solo **ausencia de colisiones declaradas**, no prueba de procedencia, exclusión de clones semánticos con huellas distintas, calidad de los oráculos ni revisión independiente de etiquetas.
- El comando privado continúa exigiendo `--train`, `--holdout`, `--prior-research` con los 37 históricos y emite únicamente agregados. Los 37 originales **no se incorporaron a GitHub**.

**Falta:** mínimo real de 100 registros válidos TRAIN y 100 TEST (en este protocolo), distribución de 12 CWE con ambos signos, autores/proyectos/familias sin contaminación, originales/SHAs cotejados con upstream, ejecución causal y controles negativos, auditoría de clones semánticos en material propietario. La evidencia estructural no sustituye la autenticidad de la referencia.

## 4. SAST — estadística por CWE y un checkpoint temporal real

- El checkout público aún incorpora solo **dos reglas Semgrep Python CWE-94**, no 12 familias. [Checkpoint temporal original](SAST_FIRST_RULESET_PUBLIC_CHRONOLOGY_ANCHOR_20261019_ES.md): [run #39263262972](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39263262972) desde SHA `2d92103943ba8f0ce6575c70992f37e6545130f8`, artefacto ID `12190799287` creado `2026-10-19T13:50:20Z`. ZIP SHA-256 `346021e09ab5f8a1bb3265bb669580ca9c1770dbeb3477843ddc3ce861b65b2b`, coincide con GitHub. Rulepack digest `1c4ea1fdfcf1955e28adf758e8c08421ab8cd279cfa058a378cb0bef84ab2eb3`. Esto **no** prueba la cronología de un holdout todavía inexistente.
- Nuevo `tools/sast_cwe_scorecard.py` realiza únicamente **aritmética agregada** para los futuros resultados con IDs opacos: matriz `TP/FP/TN/FN` por CWE y total, precisión/recall/F1/tasa FP micro y macro. Rechaza menos de 100 filas, menos de 12 CWE, ausencia de clases positiva/negativa dentro de una CWE, IDs repetidos o predicciones faltantes/sobrantes.
- Para no puntuar *12 CWE arbitrarias* más fáciles, la herramienta exige cubrir las **12 categorías objetivo ya fijadas** en `tools/premium_evidence.py` (`_PINNED_MITRE_CWES`): **CWE-22, CWE-78, CWE-79, CWE-89, CWE-94, CWE-120, CWE-125, CWE-352, CWE-416, CWE-434, CWE-787, CWE-862**.
- **Incluso con 120 ejemplos sintéticos perfectamente puntuados, el reporte conserva `blind_benchmark_accredited=false`, `publishable_result=false` y `certification=NOT_CERTIFIED`**. No existe recibo independiente de origen/holdout, verificación semántica ni sello externo posterior al ruleset completo. Slither no se exige sobre lenguajes no-Solidity/Vyper.
- Los programas `enterprise_scorecard.py` y `adversarial_sast.py` siguen siendo cálculo y validación de registros declarados, **no ejecutores autenticados de escáneres**. No presentar salidas sintéticas como rendimiento de los detectores.

**Falta:** congelar herramientas y reglas realmente aplicables para las **12 CWE** (incluidos packs/hash de CodeQL y Slither sólo si hay Solidity), obtener firma/ancla temporal del custodio TEST no visto **posterior al congelamiento de las reglas pertinentes**, ejecutar herramientas reales en origen privado sin acceso de tuning al holdout y almacenar entradas/salidas SHA/logs de cada herramienta. Solo entonces pueden divulgarse estadísticas con validación independiente.

## 5. Derechos de comercialización — verificador por bytes, sin autoautorización

- SKU **alternativo** `metadata_only`: nuevo `tools/verify_metadata_delivery_scope.py` coteja los **cinco archivos** declarados en `DELIVERY_SCOPE_PUBLIC_METADATA_DRAFT.json` con sus Git **blob IDs originales** usando `git hash-object --stdin`; rechaza rutas fuera del alcance, symlinks, duplicados, fuente binaria y cualquier alegación de derechos concedidos. `file_bytes_match_pins=true` solo significa que coinciden con los bytes esperados de esos cinco archivos, **no** que se haya examinado cada posible cita de tercero ni su permiso comercial.
- **TDD de integridad**: se añadió una prueba sintética de identidad Git nativa. Un análisis SAST público observó `hashlib.sha1` en el cálculo del Git blob ID, uso legítimo para interoperabilidad pero cuya implementación directa hacía fallar `p/security-audit`; el cambio `9b64b5312e4cb2d727eb4f1f1c4d197e6314a98e` utiliza `git hash-object` con argumentos estáticos, sin shell. [CI GREEN pública de Semgrep y CodeQL #39292955043](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39292955043).
- SKU **prioritario del propietario** `minimal_reproducible_source_pairs`: sigue `BLOCKED`, pues su lista exacta por archivo, titulares, LICENSE/NOTICE y permiso de entrega de upstream **no** está cerrada. El alternativo de metadatos no certifica automáticamente el producto premium de pares.
- Couchbase `goutils@v0.3.0`: cuatro archivos Go realmente compilados de la corrección Gitea remiten a `BSL-Couchbase.txt`. Texto original: `Licensed Work: Couchbase Server Version 8.0`, cambio publicado 2029-03-01. **Ámbito de aplicación a los archivos goutils y redistribución comercial pendientes de aclaración por escrito**. No deducir Apache-2.0 actual de la licencia del SDK Go, que es otro componente.
- [Expediente de aclaración Couchbase y matriz de cuatro archivos](COUCHBASE_BSL_FILE_SCOPE_CLEARANCE_PACKET_20261019_ES.md) contiene las preguntas concretas y la vía de contacto [oficial](https://www.couchbase.com/contact/). **No se ha presentado una consulta en nombre del propietario ni recibido autorización legal**.
- Inventario adicional de obligaciones `GITEA_16_ORIGINAL_LICENSE_EXCEPTIONS_20261019_ES.md`: 16 excepciones originales (MPL, BSD, MIT, BSL y dominio público) identificadas, pero no liberadas. Cada archivo/NOTICE de un SKU real debe estar autorizado conforme a su modalidad.

## Secuencia siguiente y no negociables

1. Completar TRAIN auténtico y cronología de procedencia, sin subirlo al PR. Conservar la exclusión de las **100 referencias ya vistas** (63 públicas + 37 históricas privadas) y de sus alias/clones.
2. Elegir futuras cohortes realmente no estudiadas y ejecutar oráculos fuente/parche/controles benignos de cada caso; **no** utilizar los anteriores como benchmark ciego.
3. Auditar similitud semántica y cadena de custodia; registrar recibo de partición fuera del Git público, con clases y CWE objetivos.
4. Congelar el **conjunto completo** de reglas antes del holdout, sellar temporalmente ambos eventos en soportes verificables, ejecutar Semgrep/CodeQL/Slither solo según aplicabilidad y **después** calcular los agregados con `sast_cwe_scorecard`.
5. Solicitar aclaración oficial de Couchbase por los cuatro archivos exactos; preparar inventario definitivo del SKU `minimal_reproducible_source_pairs`. Dejar cualquier material original no resuelto fuera de la oferta y no afirmar autorización implícita.
6. Revalidar el HEAD exacto de PR #7 y #10 y sus gates antes de decidir fusión. Mantener ambos `DRAFT` mientras los gates materiales permanezcan sin acreditar.

**Estado:** `NOT_CERTIFIED`, `GOLD=0`, `TRAIN_COMPLETE=NOT_VERIFIED`, `HOLDOUT_PRIVATE=UNASSIGNED`, `SEMANTIC_CLONE_REVIEW=PENDING`, `FULL_12_CWE_RULESET=NOT_FROZEN`, `BLIND_SAST_BENCHMARK=NOT_RUN`, `COMMERCIAL_RIGHTS=NOT_VERIFIED`, `BSL_SCOPE=UNRESOLVED`; doble revisión humana `DEFERRED`.
