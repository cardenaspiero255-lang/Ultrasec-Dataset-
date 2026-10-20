# UltraSec V7 — bloqueos de candidatos futuros, oráculos originales y licencias (2026-10-19)

> **No certificado:** `GOLD=0`, `HOLDOUT_PRIVATE=UNASSIGNED`, `BLIND_SAST_BENCHMARK=NOT_RUN`, `RIGHTS_NOT_VERIFIED`, `NOT_CERTIFIED`. La doble revisión humana permanece **aplazada**. Este informe no publica código ajeno ni corpus privado.

## 1. Integridad del origen para el futuro holdout

El filtro privado `ultrasec-v7/tools/future_holdout_exposure.py` no debe tratar un CVE **ya conocido** como nuevo porque cambie el proyecto/identificador de caso. Se añadieron regresiones y una exclusión fail-closed para la lista completa de `CVE_CANDIDATES_63_PUBLIC_METADATA.md`: exactamente **63 identificadores distintos** (conteo reproducido desde el Markdown original) y se rechaza el fichero si desaparece o cambia su estructura. Ejemplos de prueba: `CVE-2022-1519`, `CVE-2021-25932`, `CVE-2026-73140`, `CVE-2020-36280`.

También se excluyen explícitamente por CVE y por fingerprint canónico del proyecto cinco repositorios inspeccionados en esta sesión: MISP/cti-transmute, GladysAssistant/Gladys, MervinPraison/PraisonAI, icip-cas/PPTAgent y huggingface/sentence-transformers. La inclusión en esa lista **no acredita** la vulnerabilidad ni el parche; significa que ya no son futuros casos no vistos. No se importó ni puntuó ningún archivo del holdout.

**Insuficiencia pendiente:** los **37 casos históricos adicionales** reportados previamente no disponen aquí de un inventario privado completo, rastreable y deduplicado por mecanismo/proyecto, de modo que NO puede afirmarse independencia real respecto al entrenamiento. `known_research_inventory_completeness_verified=false` continúa siendo correcto. La ausencia de solapamiento por CVE o proyecto no demuestra ausencia de clones semánticos.

## 2. Causalidad original: MISP/cti-transmute — candidato de desarrollo, no test ciego

- CVE: [CVE-2026-73140](https://nvd.nist.gov/vuln/detail/CVE-2026-73140); fuente upstream original [commit](https://github.com/MISP/cti-transmute/commit/5dbd19b39a61eab793586731f1a80d8c38907c42).
- Antes `06d408e3496fdfc31da22d7b2b427434c67eae94`, después `5dbd19b39a61eab793586731f1a80d8c38907c42`.
- [GitHub Actions #39270535199](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39270535199): dos jobs originales correctos. Se extrae mediante AST la **función real `build_evaluation_report`** de cada SHA. El comentario privado de autor distinto aparece para lector externo antes y se filtra después, incluso para anónimo; propietario, autor y administrador conservan acceso al contenido que les corresponde; los comentarios públicos no se bloquean y los no evaluativos siguen excluidos.
- Alcance: `ORIGINAL_FUNCTION_ISOLATED_NOT_FULL_APPLICATION`, con stubs deterministas en vez de despliegue Flask/DB real. Logs/oráculos y SHAs de archivos en el artefacto, fuente externa **no redistribuida**.
- Derechos: repositorio con texto AGPL-3.0; derechos por archivo/aviso/entregable no adjudicados; no certifica comercialización.

## 3. Triage de enlaces nuevos

- [CVE-2026-61433 / PraisonAI](https://github.com/advisories/GHSA-79fv-7hq9-w7xg): la referencia de parche [`1620b49f36945d8cc8ee5635b906c960df5097a0`](https://github.com/MervinPraison/PraisonAI/commit/1620b49f36945d8cc8ee5635b906c960df5097a0) apunta a un commit que elimina `agent_scheduler.py.bak` y `integration/_legacy_handlers.py`, **sin modificar el generador de API señalado en el aviso**. Estado: `PATCH_REFERENCE_MISMATCH_REJECTED` para ese SHA, no afirmar que el CVE sea inexistente; buscar parche causal genuino y verificar versiones antes de cualquier candidato positivo.
- [CVE-2026-42079 / PPTAgent](https://github.com/advisories/GHSA-89g2-xw5c-v95p): commit upstream `418491a9a1c02d9d93194b5973bb58df35cf9d00` sí modifica `pptagent/apis.py`, cambiando el entorno de `eval()` para retirar `__builtins__`, con otros cambios de rutas de trabajo. La categoría del aviso es **CWE-95**, fuera del núcleo de 12 CWE actual; además no se ejecutaron oráculos nativos ni se validaron derechos. No adjudicar como un nuevo caso CWE-94 simplemente por similitud textual.
- [CVE-2026-68770 / sentence-transformers](https://github.com/advisories/GHSA-jhr6-gm9c-rqjv): `ae1acc3fb2aa2004577b297eb4a915ce7a03316a` introduce advertencia/deprecación de carga local, no el rechazo estricto que se implementa posteriormente en `626eb602b088878a8173bcab69225f68411b99e1` para v6; revisar cronología/afectación oficial con tests originales antes de hablar de versión cerrada. `SOURCE_PATCH_SEQUENCE_NEEDS_CAUSAL_REVIEW`.

Estos son **descubrimientos y rechazos de investigación**, no un holdout independiente sellado. Un candidato futuro elegible debe estar fuera de TODOS los grupos/IDs del entrenamiento y de los casos vistos, incorporar negativo genuino y oráculo original ejecutado, y congelar caso/reglas antes de abrir la salida del escáner.

## 4. Licencia Couchbase BSL: bloqueo ejecutable por archivos originales

Fuente upstream inmutable [goutils@v0.3.0](https://github.com/couchbase/goutils/tree/v0.3.0). Import closure del servicio Gitea a los SHA originales: versión vulnerable no importa goutils; versión corregida importa **dos paquetes, cuatro archivos Go**. Las cabeceras de los cuatro remiten a `licenses/BSL-Couchbase.txt` y una futura transición Apache-2.0. Los 4 hashes originales están fijados en `ultrasec-v7/tools/couchbase_bsl_distribution_gate.py`.

| Archivo original importado en Gitea fix | SHA-256 del contenido original observado |
| --- | --- |
| `logging/logger.go` | `49077aba6fbe5241fa6a93f7d00d94df4add65b1ec7d247995391e0034cba270` |
| `logging/logger_golog.go` | `d32725e23d15ec9af4cffb8d8a299eb76cbf50ba2cb51b9c47fd69a2dec8ac27` |
| `scramsha/scramsha.go` | `8a43d5236b3212b1e6bfb63cbce3faf9f6e16d2bf4583d046e5edf7ec64ec00f` |
| `scramsha/scramsha_http.go` | `20bdfdf5ef281fcafb79fe528823ec627d90afd7fba06b3636053dccee67c684` |

También se fijaron hashes de tres documentos originales (`LICENSE.txt`, `licenses/BSL-Couchbase.txt`, `licenses/APL2.txt`) que el workflow recupera de la caché Go original. [Run #39271161892](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39271161892): 2/2 jobs exitosos, **7/7 tests del gate**, bloqueo confirmado con `commercial_distribution_allowed=false`.

**Por qué sigue bloqueado:** los encabezados mencionan BSL-Couchbase, pero el texto formal dice `Licensed Work: Couchbase Server Version 8.0`; cambio observado 1 de marzo de 2029. La correspondencia de *Licensed Work* con `goutils@v0.3.0` requiere interpretación formal del titular o consejo jurídico aplicable. No asumir licencia Apache hoy. Solicitar una aclaración sobre los cuatro archivos exactos, el derecho a redistribuir fuente/bytecode/módulos compilados y las obligaciones de avisos/NOTICE para el SKU real. Mantener `standalone_compiled_bundle=BLOCKED`; no subir a GitHub ZIP con código/Go modules de terceros.

## 5. Decisión operativa

- **No hay candidatos GOLD nuevos** por estas pruebas; MISP/Gladys ya estaban en el inventario de investigación.
- **No ejecutar SAST puntuable todavía**: sin holdout privado comprobado y reglas multilenguaje congeladas antes de su evaluación.
- PR #7 y #10 deben seguir en Draft hasta resolver los gates materiales; comprobar HEAD/CI vigente después de todos los commits antes de decidir una fusión.
- Doble revisión humana: **aplazada** por el propietario, no sustituida por una certificación automática.
