# UltraSec V7 — Gitea, licencias por archivo y decisión sobre paquete autónomo

Corte: 2026-10-19. La evidencia original es el servicio `./services/release` de Gitea en los commits `7fdfb8d642201b388014f29889ef28e35b8c1872` (RED) y `e4ef995f2a162e3aca3f3a0b536afae067975d71` (GREEN). El objetivo de venta es un **overlay de fuentes mínimas para reproducción**, no copiar ni relanzar Gitea o sus dependencias bajo marca propia.

## Decisión de distribución para la V7 inicial

**No construir ni publicar todavía un paquete autónomo con árbol Gitea y dependencias Go vendorizadas.** No es necesario para la reproducción original ya verificada: GitHub Actions reconstruye cada commit upstream, verifica su procedencia, compara los nueve archivos del overlay original (seis cambiados, `LICENSE`, `go.mod`, `go.sum`) y ejecuta la regresión Go RED/GREEN. El ZIP temporal no se sube ni se vende. Solo existen recibos de hashes y protocolos públicos.

Una versión autónoma exigiría (1) un requisito comercial demostrado de funcionamiento offline/sin GitHub, (2) manifest completo de todos los archivos/código compilado/NOTICE y dependencias originales efectivamente incluidos, (3) auditoría de condiciones específicas para cada archivo, (4) política de mantenimiento de avisos y fuentes, (5) prueba RED/GREEN con **el paquete completo cerrado** fuera del árbol upstream. **Ninguno de esos requisitos de comercialización está acreditado**. La integridad del overlay original no equivale a ejecutabilidad autónoma.

## Hallazgo de riesgo: Couchbase goutils v0.3.0

La clausura original de Go incluye `github.com/couchbase/goutils@v0.3.0`, uno de los módulos inicialmente indeterminados. Su `LICENSE.txt` dice que el repositorio puede contener **licencias distintas por archivo**, incluida la Business Source License; no se puede trasladar una sola licencia del nivel raíz a toda la fuente.

Fuentes originales, inmutables por tag (v0.3.0), inspeccionadas:
- [LICENSE.txt](https://github.com/couchbase/goutils/blob/v0.3.0/LICENSE.txt): instrucciones de localizar la licencia efectiva en la cabecera del archivo.
- [logging/logger.go](https://github.com/couchbase/goutils/blob/v0.3.0/logging/logger.go) y [scramsha/scramsha.go](https://github.com/couchbase/goutils/blob/v0.3.0/scramsha/scramsha.go): muestran referencia a `licenses/BSL-Couchbase.txt`.
- [licenses/BSL-Couchbase.txt](https://github.com/couchbase/goutils/blob/v0.3.0/licenses/BSL-Couchbase.txt): declara Business Source License 1.1, `Licensed Work: Couchbase Server Version 8.0`, `Change Date: March 1, 2029`, `Change License: Apache License, Version 2.0`; contiene restricciones específicas sobre ciertos usos/distribuciones comerciales del Licensed Work.
- [licenses/APL2.txt](https://github.com/couchbase/goutils/blob/v0.3.0/licenses/APL2.txt): documento Apache-2.0 asociado a la fecha de cambio.

**Ambigüedad pendiente, no supuesto jurídico:** aunque las cabeceras Go remiten a `BSL-Couchbase.txt`, ese mismo texto identifica como Licensed Work *Couchbase Server Version 8.0*. No se puede concluir automáticamente que sus restricciones se apliquen a **cada paquete/archivo** de `goutils@v0.3.0`, ni lo contrario. Para una propuesta que redistribuya esos archivos se necesita identificar y documentar la licencia aplicable a cada archivo que se entregue, interpretar la sección Licensed Work, fecha de cambio y excepciones, y resolverlo antes de aprobar su uso en el SKU.

El workflow `v7-gitea-go-dependency-inventory.yml` ahora genera `gitea-couchbase-actual-source-scope.json` en **cada commit**, con únicamente el conjunto de `GoFiles/CgoFiles` compilados que importó Gitea desde ese módulo, indicadores de cabeceras, ruta relativa, SHA-256 y documentos `LICENSE.txt`, `BSL-Couchbase.txt`, `APL2.txt` con SHA-256. **No incluye bytes de código upstream.** Una cabecera y sus hashes son evidencia de procedencia, pero no autorización comercial ni dictamen legal.

## Otras licencias que exigían más categorías

Se añadieron detectores conservadores para las siguientes familias de **texto original**, con aviso de obligaciones, no una resolución jurídica:
- **MPL-2.0:** ejemplos de HashiCorp `errwrap`, `go-multierror`, `go-version`, `golang-lru/v2`, y `go-sql-driver/mysql`. Requiere preservar avisos y cumplir requisitos de fuente para archivos cubiertos cuando corresponda.
- **BSD-2-Clause:** ejemplos `pkg/errors`, `redis/go-redis/v9`, `syndtr/goleveldb`. Retener copyright, condiciones y exclusión de garantías; no confundir con BSD-3.
- **BSD-3-Clause:** se amplió el reconocimiento de variantes con cláusulas de no respaldo a la venta; `ulikunitz/xz` es un ejemplo.
- **BSD-2-Clause u otras licencias mixtas/terceros:** no inferir una licencia única a partir de un archivo raíz que contenga varias obras (p. ej. `emirpasic/gods`).
- **BSL-1.1 / licencias por archivo:** estado `PER_FILE_LICENSE_REVIEW_REQUIRED`, incluso si existen todos los archivos LICENSE.

Para los demás módulos sin identificación concluyente, el resultado debe seguir **UNKNOWN/REQUIRES_REVIEW**: comprobar el texto original, titulares, avisos y licencias anidadas; ninguna etiqueta declarada por el detector autoriza a comercializar. Los cuatro reemplazos `azcore`, `azblob`, `go-mssqldb`, `yaml/v4` conservan su clasificación previa y necesidad de verificar las condiciones del entregable real.

## Criterio de aprobación y alcance

El contrato técnico explícito permanece inalterado: `ready_to_distribute=false`, `commercial_licenses_cleared=0`, `commercial_distribution_cleared=false`, `NOT_CERTIFIED`. No subir ZIP de código de Gitea/Couchbase ni el holdout a GitHub. Si un comprador exige un bundle offline, tratarlo como producto **separado** con admisión técnica, SPDX/NOTICE por archivo y comprobación jurídica específica.

**No se generó ningún gold nuevo.** Los casos usados para la regresión se conocen previamente y no constituyen un benchmark ciego; `GOLD=0`, holdout privado aún no verificado, y doble revisión humana aplazada.
