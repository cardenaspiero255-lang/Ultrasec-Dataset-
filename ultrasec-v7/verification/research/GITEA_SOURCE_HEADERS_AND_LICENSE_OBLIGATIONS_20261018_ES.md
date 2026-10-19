# Gitea original patch — observación directa de licencia por archivo (NO autorización de entrega)

Fecha del corte: 2026-10-18. **CVE-2026-58428**, aviso oficial: [GHSA-25gq-j9jx-43pg](https://github.com/go-gitea/gitea/security/advisories/GHSA-25gq-j9jx-43pg). Procedencia verificada contra la versión **vulnerable** `7fdfb8d642201b388014f29889ef28e35b8c1872` y la **corregida** `e4ef995f2a162e3aca3f3a0b536afae067975d71`, un único parche upstream. Comparación original: [GitHub diff](https://github.com/go-gitea/gitea/compare/7fdfb8d642201b388014f29889ef28e35b8c1872...e4ef995f2a162e3aca3f3a0b536afae067975d71).

## Archivos modificados realmente inspeccionados

| Ruta original | Git blob vulnerable | SPDX en primeras líneas | Copyright presente |
| --- | --- | --- | --- |
| `services/release/release.go` | `1be60731a930b2c442aafcb5174f6b727c930b97` | MIT | © 2019 The Gitea Authors |
| `services/release/release_test.go` | `579d92f2f4b26c4b5d3f78e50a996ef621526fe6` | MIT | © 2018 The Gitea Authors |
| `routers/web/repo/release.go` | `128fcd5369505d4d27c33842a646bf41d1f289af` | MIT | © 2014 The Gogs Authors; © 2018 The Gitea Authors |
| `routers/web/repo/release_test.go` | `82f3115ee5d34a3e09d0f8fab4fe6531e413ba8c` | MIT | © 2017 The Gitea Authors |
| `templates/repo/release/new.tmpl` | `cc73bdf13c50e8b7e88579cd8484f0384b132890` | **Sin SPDX en primeras 16 líneas** | Cabecera no observada; verificar alcance de LICENSE y posibles plantillas derivadas |
| `tests/integration/release_test.go` | `320661420ed80b53acd5a9e85914a1176c9c74bf` | MIT | © 2017 The Gitea Authors |

Los 6 paths corresponden exactamente a los 6 archivos del commit upstream. Las 12 huellas Git de las dos revisiones y `go.mod`, `go.sum`, `LICENSE` se controlan por separado en `GITEA_ORIGINAL_FILE_RIGHTS_SCOPE.json`. **Git blob SHA-1 identifica el objeto del repositorio, no es una firma moderna de seguridad**; para integridad de los bytes y entrega se requieren SHA-256 independientes.

## Licencia raíz

`LICENSE`, Git blob `a8d4b49dd073a4a38a7e58385eeff7cc52568697`, identifica copyright **The Gitea Authors (2016)** y **The Gogs Authors (2015)** y concede los permisos habituales de licencia MIT, incluidos copiar, modificar, distribuir y vender el material licenciado. Su condición exige conservar **el aviso de copyright y el texto de permiso** en todas las copias o porciones sustanciales. Ver el [archivo original](https://github.com/go-gitea/gitea/blob/7fdfb8d642201b388014f29889ef28e35b8c1872/LICENSE).

**Distinción jurídica importante:** la presencia de MIT no constituye una autorización para quitar avisos, apropiarse exclusivamente del código de terceros ni hacer pasar dependencias o plantillas no revisadas por propiedad de UltraSec. Una licencia abierta puede permitir distribución comercial **si se cumplen sus condiciones**; el estado de *cumplimiento para el paquete efectivo* se mantiene `NOT_VERIFIED`, no `PROHIBITED`.

## Dependencias originales y límites del paquete mínimo

- El módulo original es `gitea.dev`, declara **Go 1.26.4** en `go.mod`. `go.mod` y `go.sum` tienen los mismos Git blobs antes/después: `1f2e923ce21ee69e26b6e90e37146a633d3ad273` y `34ab2024ed6e41ae05212044f383e846901e9c5e`.
- La prueba realizada hoy ejecuta el servicio `./services/release` del **árbol completo de Gitea**, y usa `go test -tags sqlite -run '^TestRelease_Update$'` sobre la corrección original trasplantada al commit vulnerable. **Los seis archivos del parche aislados no constituyen por sí mismos un proyecto que compile o funcione.**
- La investigación adicional en `.github/workflows/v7-gitea-go-dependency-inventory.yml` solicita `go list -mod=readonly -tags sqlite -deps -json ./services/release` en los dos commits inmutables. El reporte se genera **solamente si el runner ejecuta sin errores**. Es un inventario de imports Go de producción; no cubre dependencias usadas solo en tests, plantillas, recursos de ejecución, JS/CSS, submódulos ni licencias SPDX de cada dependencia.
- Para entregar un bundle redistribuible deben cerrarse su árbol de origen, dependencias reales y avisos por archivo, junto con una prueba de compilación **sobre el bundle elegido**, no solamente sobre Gitea entero. Mientras falte esa comprobación, `PACKAGED_SOURCE_PATHS=[]`, `SOURCE_BUNDLE_READY=false`.

## Protección del benchmark y procedencia

La prueba RED/GREEN del servicio es real, pero **se conoce el commit correctivo y el test positivo procede de ese commit**. Puede usarse como prueba de regresión conocida para desarrollar herramientas; **no** debe adjudicarse como defecto desconocido de un benchmark ciego, ni proporciona un nuevo caso negativo independiente. El corpus gold y holdout permanecen `NOT_VERIFIED` y `NOT_ADMITTED`. La doble revisión humana continúa aplazada.

**Estado:** `ORIGINAL_PATCH_FILES=6`, `SPDX_MIT_FILE_HEADERS=5`, `ROOT_MIT_LICENSE_OBSERVED=true`, `MATERIALS_ACTUALLY_AUTHORIZED_FOR_B2B_PACKAGE=NOT_VERIFIED`, `THIRD_PARTY_LICENSE_OBLIGATIONS=NOT_AUDITED`, `REAL_BLIND_GOLD=0`, `CERTIFICATION=NOT_CERTIFIED`.
