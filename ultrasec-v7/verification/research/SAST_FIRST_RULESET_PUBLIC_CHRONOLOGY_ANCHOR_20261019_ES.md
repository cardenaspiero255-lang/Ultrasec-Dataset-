# UltraSec V7 — primera ancla pública temporal de reglas SAST

**Evidencia histórica comprobada el 19-10-2026 mediante GitHub Actions y descarga del artefacto original.**

| Elemento | Valor verificado |
| --- | --- |
| Workflow público | [UltraSec V7 Future-Unseen SAST Ruleset Byte Lock, run 39263262972](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39263262972) |
| SHA de checkout/HEAD durante la ejecución | `2d92103943ba8f0ce6575c70992f37e6545130f8` |
| Inicio informado por GitHub Actions | `2026-10-19T13:48:11Z` |
| Ejecución completada | `2026-10-19T13:50:24Z` |
| Artefacto `future-unseen-sast-byte-lock-public` | ID `12190799287`, creado `2026-10-19T13:50:20Z`, no expirado al consultar |
| SHA-256 del ZIP original descargado | `346021e09ab5f8a1bb3265bb669580ca9c1770dbeb3477843ddc3ce861b65b2b` |
| SHA-256 del recibo `future-sast-byte-lock.json` | `59e5bfb9c71bcc76e1c830698a60f7d2dfa6ad485b7ef7e46d6b9295cbfb262c` |
| SHA-256 del YAML Semgrep local | `6f3d784e3fa683b25336899fb5424b9f22ba34712147b7163714b25e9af65f00` |
| Digest semántico del ruleset | `1c4ea1fdfcf1955e28adf758e8c08421ab8cd279cfa058a378cb0bef84ab2eb3` |
| Versión de herramienta fijada en este checkpoint | Semgrep OSS `1.180.0` |
| CWE cubiertas | **CWE-94, Python, dos reglas de patrón**; NO se cubren 12 CWE |

**Comprobaciones efectivas:** el SHA-256 del ZIP descargado coincide exactamente con el digest comunicado por GitHub Actions; la prueba de integridad ZIP no detectó errores; contiene únicamente `future-sast-byte-lock.json` y `future-rules-public-sha256.txt`. El recibo afirma `blind_benchmark_ready=false`, `external_chronology_verified=false`, `gold_admitted=0`, `certification=NOT_CERTIFIED`. Se comprobaron los SHA-256 interiores y se conservaron las URLs originales. No se descargó ni publicó código del holdout.

**Alcance probatorio:** esto constituye un **punto de referencia público de la existencia del primer ruleset antes de una eventual futura selección**. No demuestra que se seleccionó un holdout independiente después, ni que las 12 CWE requeridas tengan rulesets fijados, ni que las herramientas CodeQL/Slither se hayan ejecutado sobre el mismo conjunto. La existencia previa de código y un timestamp de GitHub tampoco garantiza que nadie viera o ajustara las reglas a un candidato con anterioridad. Hay que demostrar cronológicamente la selección/custodia separada del TEST real y una huella verificable de cada repositorio y oráculo.

**Puertas pendientes para un benchmark publicable:** (1) historial íntegro TRAIN y 37 candidatos privados históricos comparados con 63 públicos; (2) TEST realmente no visto con evidencia reproducible original, negativos auténticos, proyectos y mecanismos distintos, auditoría de clones semánticos; (3) firma o ancla temporal independiente del inventario privado y su secuencia frente a los rulesets **completos** de las 12 CWE; (4) hash y versión de cada scanner, reglas/packs, toolchain, código upstream, logs/salida y estado de ejecución; (5) matriz TP/FP/TN/FN y métricas por CWE, sin convertir fallos de compilación ni herramientas no aplicables en falsos negativos o verdaderos negativos.

**Estado:** `FIRST_RULESET_PUBLIC_ANCHORED`, `FULL_12_CWE_RULEPACK_FROZEN=false`, `HOLDOUT_PRIVATE=UNASSIGNED`, `EXTERNAL_CHRONOLOGY_OF_HOLDOUT=NOT_VERIFIED`, `BLIND_BENCHMARK=NOT_RUN`, `GOLD=0`, `NOT_CERTIFIED`.
