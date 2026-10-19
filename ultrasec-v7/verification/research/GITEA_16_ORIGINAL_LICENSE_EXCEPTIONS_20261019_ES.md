# Gitea original: 16 excepciones de clasificación de licencias, documentadas por fuente

Fecha: 2026-10-19. Procedencia de la lista: [inventario real original de módulos Go](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39204770098), `go list -mod=readonly -tags sqlite -deps -json ./services/release` y manifiesto de `LICENSE` originales; versiones concretas fijadas en el commit original Gitea `e4ef995f2a162e3aca3f3a0b536afae067975d71`. Se inspeccionaron textos originales de ejemplos emblemáticos y se extendió el clasificador. **Las etiquetas son pistas observadas, no revisión jurídica ni certificado de titularidad/redistribución por archivo.**

| Módulo exacto del grafo corregido | Texto/licencia observada | Fuente original / riesgo |
| --- | --- | --- |
| `github.com/blevesearch/gtreap@v0.1.1` | MIT | [LICENSE original](https://github.com/blevesearch/gtreap/blob/v0.1.1/LICENSE), conservar copyright/permiso |
| `github.com/cespare/xxhash/v2@v2.3.0` | MIT | [LICENSE.txt original](https://github.com/cespare/xxhash/blob/v2.3.0/LICENSE.txt), conservar copyright/permiso |
| `github.com/couchbase/goutils@v0.3.0` | **Por archivo; cabeceras que remiten a BSL-1.1** | [LICENCE original](https://github.com/couchbase/goutils/blob/v0.3.0/LICENSE.txt), [BSL anidada](https://github.com/couchbase/goutils/blob/v0.3.0/licenses/BSL-Couchbase.txt). **Riesgo de redistribución autónoma sin interpretar alcance de Licensed Work** |
| `github.com/emirpasic/gods@v1.18.1` | Texto de condiciones BSD-2-Clause **con obras/avisos adicionales** | [LICENSE original](https://github.com/emirpasic/gods/blob/v1.18.1/LICENSE), necesita revisar avisos/obras anidadas |
| `github.com/go-sql-driver/mysql@v1.10.0` | MPL-2.0 | [LICENSE original](https://github.com/go-sql-driver/mysql/blob/v1.10.0/LICENSE), obligaciones de fuente sobre archivos cubiertos |
| `github.com/hashicorp/errwrap@v1.1.0` | MPL-2.0 | [LICENSE original](https://github.com/hashicorp/errwrap/blob/v1.1.0/LICENSE), revisar términos MPL |
| `github.com/hashicorp/go-multierror@v1.1.1` | MPL-2.0 | [LICENSE original](https://github.com/hashicorp/go-multierror/blob/v1.1.1/LICENSE), revisar términos MPL |
| `github.com/hashicorp/go-version@v1.9.0` | MPL-2.0 | [LICENSE original](https://github.com/hashicorp/go-version/blob/v1.9.0/LICENSE), revisar términos MPL |
| `github.com/hashicorp/golang-lru/v2@v2.0.7` | MPL-2.0 | [LICENSE original](https://github.com/hashicorp/golang-lru/blob/v2.0.7/LICENSE), revisar términos MPL |
| `github.com/pkg/errors@v0.9.1` | BSD-2-Clause | [LICENSE original](https://github.com/pkg/errors/blob/v0.9.1/LICENSE), conservar avisos |
| `github.com/redis/go-redis/v9@v9.21.0` | BSD-2-Clause | [LICENSE original](https://github.com/redis/go-redis/blob/v9.21.0/LICENSE), conservar avisos |
| `github.com/syndtr/goleveldb@v1.0.0` | BSD-2-Clause | [LICENSE original](https://github.com/syndtr/goleveldb/blob/v1.0.0/LICENSE), conservar avisos |
| `github.com/ulikunitz/xz@v0.5.15` | BSD-3-Clause | [LICENSE original](https://github.com/ulikunitz/xz/blob/v0.5.15/LICENSE), incluye cláusula de no respaldo |
| `github.com/xi2/xz@v0.0.0-20171230120015-48954b6210f8` | **Declaración explícita de dominio público; no SPDX estándar** | [LICENSE del commit original](https://github.com/xi2/xz/blob/48954b6210f8d154cb5f8484d3a3e1f83489309e/LICENSE). Debe comprobarse la cadena original de obras XZ Embedded/Utils, jurisdicción y titulares; **no marcar autorización automática** |
| `github.com/zeebo/xxh3@v1.1.0` | BSD-2-Clause | [LICENSE original](https://github.com/zeebo/xxh3/blob/v1.1.0/LICENSE), conservar avisos |
| `gopkg.in/warnings.v0@v0.1.2` | BSD-2-Clause | [LICENSE del repositorio original](https://github.com/go-warnings/warnings/blob/v0.1.2/LICENSE), preservar avisos |

Total: **16 de 16 con una ruta/hipótesis de investigación concreta**, no 16 con permiso comercial otorgado. Se distinguen 5 con MPL-2.0, 6 con condiciones BSD-2-Clause (una con terceros), 1 BSD-3-Clause, 2 MIT, 1 mapeo BSL por archivo y 1 declaración de dominio público sin SPDX. Algunas licencias mezcladas incluyen más titulares: verificar cada archivo del producto final, no inferir uniformidad por módulo.

## Licencia y distribución del producto

Las condiciones específicas de **MPL-2.0** se aplican a Covered Software y sus modificaciones según su alcance, incluidas obligaciones de disponibilidad de fuente y avisos; una copia en un paquete no convierte todo UltraSec en MPL automáticamente. **BSD-2-Clause** y **BSD-3-Clause** suelen permitir uso comercial condicionado a conservar avisos/descargos, mientras BSD-3 incluye cláusula de no respaldo. Una declaración de **dominio público** no equivale a certeza automática para cada país/obra derivada; el módulo `xi2/xz` requiere revisión de procedencia.

**Couchbase BSL:** [cabeceras originales de código](https://github.com/couchbase/goutils/blob/v0.3.0/logging/logger.go) remiten a BSL-Couchbase; su documento nombra como Licensed Work `Couchbase Server Version 8.0`, fecha `2029-03-01` y futura Apache-2.0. La aplicabilidad exacta a `goutils` y a cada archivo importado es una cuestión **no resuelta** por los hashes o el clasificador. El workflow nuevo genera recibos de los **GoFiles/CgoFiles realmente compilados** sobre los commits Gitea, sin subir código. Si las cabeceras mencionan Apache como cambio futuro, el resultado las etiqueta como `APACHE-2.0-FUTURE-CHANGE-REFERENCE`, nunca como licencia vigente. No vender ni incluir archivos afectados en un bundle autónomo hasta cerrar obligaciones y compatibilidad.

**Modalidad elegida:** mantener el **overlay original de 9 archivos** (seis del parche Gitea, `LICENSE` MIT original, `go.mod`, `go.sum`) exclusivamente como prueba de reproducción interna y reconstrucción desde repositorio original. No hay necesidad demostrada de generar una distribución offline autónoma con 155 dependencias redistribuidas; ese producto adicional queda bloqueado. **Ninguna licencia de módulo se fusiona ni sublicencia como propiedad exclusiva de UltraSec.**

## Estados honestos

- Ejecutados: Go list original; inspección de LICENSE/NOTICE raíz con SHA-256; clasificación conservadora de MPL/BSD y riesgo BSL; overlay RED/GREEN conocido.
- Por ejecutar o acreditar: recibos de origen compilado BSL ambos commits, auditoría SPDX por archivo de un eventual bundle offline, obligaciones legales en modalidad concreta, benchmark gold independiente/holdout y revisión jurídica según necesidad.
- `COMMERCIAL_RIGHTS_NOT_VERIFIED`, `GOLD=0`, `NOT_CERTIFIED`. Doble revisión humana aplazada.

Esto **no es un dictamen legal**; es un registro auditable de evidencia original, riesgos y decisiones técnicas.
