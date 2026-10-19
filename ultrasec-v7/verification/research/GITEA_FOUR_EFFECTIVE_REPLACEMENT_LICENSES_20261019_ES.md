# Gitea — cuatro módulos reemplazados: versiones y licencias originales

Corte: 2026-10-19. Investigación sobre los commits upstream `7fdfb8d642201b388014f29889ef28e35b8c1872` y `e4ef995f2a162e3aca3f3a0b536afae067975d71`. **Fuente primaria reproducida:** [GitHub Actions #39204477040](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39204477040), `go list -mod=readonly -tags sqlite -deps -json ./services/release`, inspección en `GOMODCACHE` de los módulos efectivos, 18/18 tests sintéticos del clasificador, artefactos `gitea-go-module-license-evidence.json` y `gitea-go-closure.json`. El par de fuentes reproduce las mismas huellas para estas licencias.

## Clasificación reproducible (por bytes efectivos; NO por versiones solicitadas)

| Módulo Go original | Versión declarada → efectiva por `replace` | Archivo de licencia observado | SPDX familiar observado en **texto original** | SHA-256 del archivo de licencia |
| --- | --- | --- | --- | --- |
| `github.com/Azure/azure-sdk-for-go/sdk/azcore` | `v1.22.0` → `v1.19.0` | `LICENSE.txt`, 1073 bytes | **MIT** | `646f8936b8ddcd14e13e578ff6857e368780b0d1a4f6066bee89211923a373e2` |
| `github.com/Azure/azure-sdk-for-go/sdk/storage/azblob` | `v1.7.0` → `v1.6.2` | `LICENSE.txt`, 1161 bytes | **MIT** | `a096a435e19bb6b631da46992c011a39be563e97ce7366879ad516c772904632` |
| `github.com/microsoft/go-mssqldb` | `v1.10.0` → `v1.9.7` | `LICENSE.txt`, 1516 bytes | **BSD-3-Clause** | `7d0793489653bfe020de7ea32047bad266f5e2e204ba12025d5300f39555addc` |
| `go.yaml.in/yaml/v4` | `v4.0.0-rc.5` → `v4.0.0-rc.3` | `LICENSE`, 11365 bytes | **Apache-2.0** identificado en licencia efectiva | `4a4e095045f46875715234a884741acd2b61b88959d6f47a243ae03ef95c4e76` |

**YAML tiene también `NOTICE`**, 708 bytes, SHA-256 `eaecbd48a908defec5acc088247b82d1fc1eb21d5b450348c25429bba42d9001`. El proyecto puede documentar alternativas de licencia en otra parte; el clasificador de esta ejecución detecta las condiciones **que aparecen en el `LICENSE` concreto cacheado** y no resuelve por sí solo opciones legales de licencia dual ni archivos anidados.

## Condiciones que debe cumplir el entregable cuando incluya material original

| Familia | Obligaciones habituales a verificar y preservar | Estado |
| --- | --- | --- |
| MIT | Retener avisos originales de copyright y texto de licencia/permiso en todas las copias o porciones sustanciales, y descargos aplicables | **Evidencia del texto identificada; cumplimiento del paquete sin verificar** |
| BSD-3-Clause | Mantener avisos de copyright, condiciones y exclusión de garantías en fuente o materiales que acompañen binarios; no usar nombres de titulares/contribuyentes para respaldar la venta sin autorización | **Evidencia del texto identificada; cumplimiento del paquete sin verificar** |
| Apache-2.0 | Incluir copia de la licencia, conservar avisos pertinentes, documentar cambios aplicables, cumplir obligaciones relativas a NOTICE y términos de patentes cuando correspondan | **LICENSE y NOTICE observados; cumplimiento del paquete sin verificar** |

**Las licencias permisivas no prohíben vender.** Sin embargo, hallar un `LICENSE` y anotar un patrón no garantiza que un archivo en subdirectorio no tenga un titular o término distinto, ni que el contrato B2B y las dependencias redistribuidas cumplan todas las obligaciones. Ninguno de los cuatro se considera jurídicamente autorizado de forma integral: `commercial_licenses_cleared=0`, `copyright_notice_completeness_verified=false`. El auditor conserva estos bloqueos incluso cuando los textos se clasifican automáticamente.

## Paquete mínimo de reproducción de Gitea

La modalidad propuesta **no vende un árbol copiado de terceros** como propio: crea temporalmente un **overlay original** con seis archivos modificados de Gitea más `LICENSE`, `go.mod` y `go.sum`, exactamente 9 archivos; valida Git blobs y SHA-256; abre de nuevo el ZIP y compara los bytes. La LICENSE MIT original viaja dentro del overlay. Para compilar y ejecutar la suite original se necesita descargar el **árbol público íntegro del commit exacto** y reconstruir sobre él, y luego ejecutar `go test -tags sqlite -count=1 -timeout 10m -run '^TestRelease_Update$' ./services/release -v`, con test de corrección conocido sobre la rama vulnerable.

El ZIP de código de terceros **se mantiene dentro del runner y se elimina**, no se publica en GitHub ni se vende. Solo se archivan recibos con rutas permitidas y hashes, no código de terceros. La validez del overlay como **paquete autónomo compilable** no se ha demostrado porque **no es** autónomo.

Esto evita redistribuir los 155 módulos externos de Gitea en el overlay. Si una modalidad futura incluye módulos, binarios, código generado, plantillas de terceros, tests y/o dependencias, debe ampliarse el inventario y cumplir las obligaciones propias de esa entrega. Ningún aviso MIT de Gitea se sustituye por una declaración propietaria de UltraSec.

**Pendiente:** auditoría de licencias por archivo de todo el material realmente entregable, estudio jurídico específico si corresponde, bundle compilable si se exige distribución autónoma, pruebas fuera del árbol completo, y corpus/holdout gold verdaderamente independientes. Dos revisores humanos siguen aplazados. `RIGHTS_NOT_VERIFIED`, `GOLD=0`, `NOT_CERTIFIED`.
