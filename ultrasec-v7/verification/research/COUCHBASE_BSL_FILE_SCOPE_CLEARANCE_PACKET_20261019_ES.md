# UltraSec V7 — expediente para consulta de derechos Couchbase/goutils@v0.3.0

**Corte:** 19 de octubre de 2026. **Dictamen jurídico: pendiente.** Solo investigación de evidencias y preparación de consulta al titular; ningún permiso comercial concedido. Esta nota se basa en los archivos originales de la etiqueta `v0.3.0` y en los recibos de `go list -deps` obtenidos de los commits Gitea fijados.

## Alcance realmente compilado

- Componente: `github.com/couchbase/goutils@v0.3.0`.
- Gitea vulnerable `7fdfb8d642201b388014f29889ef28e35b8c1872`: en el cierre de importaciones de `./services/release` **no aparece este módulo**.
- Gitea corregido `e4ef995f2a162e3aca3f3a0b536afae067975d71`: aparecen dos paquetes, correspondientes a cuatro archivos compilados, no todo el repositorio Couchbase.
- Evidencia original reproducida: [Go import-closure #39271161892](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39271161892); [puerta BSL bloqueante](../../tools/couchbase_bsl_distribution_gate.py), con referencias SHA originales y estado permanente `commercial_distribution_allowed=false`.

| Archivo original incluido en el import-closure | SHA-256 del contenido original registrado | Texto del encabezado original |
| --- | --- | --- |
| [logging/logger.go](https://github.com/couchbase/goutils/blob/v0.3.0/logging/logger.go) | `49077aba6fbe5241fa6a93f7d00d94df4add65b1ec7d247995391e0034cba270` | Remite a `licenses/BSL-Couchbase.txt`, posteriormente Apache-2.0 |
| [logging/logger_golog.go](https://github.com/couchbase/goutils/blob/v0.3.0/logging/logger_golog.go) | `d32725e23d15ec9af4cffb8d8a299eb76cbf50ba2cb51b9c47fd69a2dec8ac27` | Misma remisión por archivo |
| [scramsha/scramsha.go](https://github.com/couchbase/goutils/blob/v0.3.0/scramsha/scramsha.go) | `8a43d5236b3212b1e6bfb63cbce3faf9f6e16d2bf4583d046e5edf7ec64ec00f` | Misma remisión por archivo |
| [scramsha/scramsha_http.go](https://github.com/couchbase/goutils/blob/v0.3.0/scramsha/scramsha_http.go) | `20bdfdf5ef281fcafb79fe528823ec627d90afd7fba06b3636053dccee67c684` | Misma remisión por archivo |

**Documentos originales distintos:** [LICENSE.txt](https://github.com/couchbase/goutils/blob/v0.3.0/LICENSE.txt), [licenses/BSL-Couchbase.txt](https://github.com/couchbase/goutils/blob/v0.3.0/licenses/BSL-Couchbase.txt) y [licenses/APL2.txt](https://github.com/couchbase/goutils/blob/v0.3.0/licenses/APL2.txt). El README de licencia raíz requiere comprobar cada encabezado individual, por lo que ninguna etiqueta única de módulo es autorización automática.

## Interpretación pendiente, sin hipótesis convertida en permiso

El BSL original indica `Licensor: Couchbase, Inc.`, `Licensed Work: Couchbase Server Version 8.0`, `Change Date: March 1, 2029`, `Change License: Apache License, Version 2.0`. Las cabeceras de los cuatro archivos del módulo `goutils` remiten explícitamente a ese documento. **La mención Couchbase Server 8.0 no prueba ni excluye por sí sola que los cuatro archivos Go de `goutils@v0.3.0` estén cubiertos por la licencia BSL con sus condiciones comerciales.** Debe solicitarse aclaración sobre este alcance.

El texto BSL vigente restringe ciertas distribuciones comerciales del `Licensed Work` o productos que lo incluyan y tiene condiciones de cambio de licencia por versión. **No asumir que la fecha publicada de 2029 autoriza hoy una distribución comercial ni que Apache-2.0 se aplica ya**. Requiere resolución contractual/jurídica para el caso de uso concreto.

## Consulta concreta que debe resolverse antes de un bundle

Preguntas por escrito al departamento de licencias/representante autorizado de Couchbase; adjuntar rutas, etiqueta y hashes **sin enviar archivos fuente innecesarios**:

1. ¿Están los cuatro archivos citados de `goutils@v0.3.0` incluidos dentro del alcance definido como *Couchbase Server Version 8.0*, o se aplican otras condiciones para este módulo independiente?
2. ¿Puede un tercero distribuir o vender archivos fuente originales o modificados de esas cuatro rutas, dentro de un dataset de pares vulnerable/parche, con o sin transformaciones/anotaciones?
3. ¿Puede ese tercero entregar un binario Go compilado que incorpore esos paquetes, incluso como componente no central de un producto de seguridad comercial? ¿Existe una excepción, una licencia alternativa o autorización específica?
4. ¿Qué texto LICENSE, NOTICE, fuente correspondiente, marcas, titulares, historial de cambios y cláusulas deben acompañar cada modalidad (metadata-only, fragmentos, árbol completo, binario, servicio remoto)?
5. ¿La fecha de cambio está asociada a estos archivos y a esta etiqueta v0.3.0? ¿Existe una fecha anterior por la regla del cuarto aniversario prevista en la licencia? Facilitar confirmación de la base de cálculo.
6. ¿Qué documento escrito autoriza estos usos y quién tiene capacidad para otorgarlo? Registrar identidad, fecha, versión, restricciones territoriales y entregable exacto en un archivo **privado** de licencias, no como supuesto automático en el repositorio público.

## Decisión aplicable ahora mismo

| Modalidad | ¿Requiere incluir estos bytes Couchbase? | Decisión técnica |
| --- | --- | --- |
| Investigaciones internas efímeras sobre upstream original | Puede reconstruirse desde la fuente oficial sin subir ni revender archivos Couchbase | **RESEARCH_ONLY**; no equivale a permiso comercial |
| Producto **solo de metadatos originales de UltraSec**, sin source snippets ni binarios externos | **No**, si el manifiesto final y su inspección confirman ausencia total de código redistribuido | `SOURCE_EXCLUSION_POSSIBLE`; derechos sobre el resto del producto aún `NOT_VERIFIED` |
| ZIP autónomo o bundle Go, vendorización, fragmentos Go, binario compilado que incorpore el módulo | **Sí** o posible inclusión | **BLOCKED** hasta interpretación/permiso y cumplimiento de licencias por archivo |
| Distribución de otros módulos externos MIT/MPL/BSD/AGPL/GPL | Depende del entregable exacto | Revisión **por archivo, aviso, dependencia y modalidad**, no extrapolar MIT raíz |

No registrar `commercial_distribution_allowed=true` ni `GOLD_ADMITTED` porque pasen los tests o porque se haya redactado esta consulta. El objetivo es cerrar una **pregunta jurídica real**, no crear un certificado automatizado.

**Estado:** `RIGHTS_NOT_VERIFIED`, `BSL_APPLICABILITY=UNRESOLVED`, `STANDALONE_BUNDLE=BLOCKED`, `METADATA_ONLY_RIGHTS=NOT_VERIFIED`, `NOT_CERTIFIED`.
