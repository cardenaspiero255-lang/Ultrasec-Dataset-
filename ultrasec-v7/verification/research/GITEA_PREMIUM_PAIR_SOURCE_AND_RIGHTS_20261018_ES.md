# UltraSec V7 — Gitea CVE-2026-58428: procedencia original, alcance reproducible y obligaciones de entrega

**Estado:** evaluación técnica original en curso, `NOT_ADMITTED`, `NOT_CERTIFIED`, `RIGHTS_NOT_VERIFIED`. Este expediente es de **metadatos públicos y comprobaciones**, no una redistribución de código de Gitea.

## Par original y causa raíz

Proyecto upstream: [go-gitea/gitea](https://github.com/go-gitea/gitea).
Vulnerable: [7fdfb8d642201b388014f29889ef28e35b8c1872](https://github.com/go-gitea/gitea/commit/7fdfb8d642201b388014f29889ef28e35b8c1872).
Corregido: [e4ef995f2a162e3aca3f3a0b536afae067975d71](https://github.com/go-gitea/gitea/commit/e4ef995f2a162e3aca3f3a0b536afae067975d71), **hijo inmediato**.

El parche original declara que el formulario web permitía renombrar adjuntos de releases a una extensión prohibida, aunque la ruta API ya exigía `[repository.release] ALLOWED_TYPES`. La corrección añade `upload.Verify(nil, newName, setting.Repository.Release.AllowedTypes)` antes de persistir el nombre. La prueba original `TestRelease_Update` comprueba que se rechaza `test.exe` con `.zip` permitido y que el nombre anterior se conserva.

La [regresión Go nativa](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39181171504) hizo RED/GREEN: el test de la revisión corregida se **trasplantó a la revisión vulnerable**; pasó en la revisión corregida y falló en la vulnerable. Esto acredita el contraste del **servicio de releases**. No es un caso ciego del detector, ni demuestra por sí solo una integración web independiente de extremos a extremos.

## Lista exacta de archivos cambiados por ese commit

| Archivo | Función / alcance | Licencia a nivel de archivo observada |
|---|---|---|
| `services/release/release.go` | Validación central de nombre de adjunto | `SPDX-License-Identifier: MIT` |
| `services/release/release_test.go` | Test nativo RED/GREEN de la política | `SPDX-License-Identifier: MIT` |
| `routers/web/repo/release.go` | Interfaz web y error de tipo prohibido | `SPDX-License-Identifier: MIT` |
| `routers/web/repo/release_test.go` | Adaptación de pruebas de router | `SPDX-License-Identifier: MIT` |
| `templates/repo/release/new.tmpl` | Formulario UI | **Sin cabecera SPDX**; evaluar alcance de licencia raíz |
| `tests/integration/release_test.go` | Prueba integrada de renombrado web | `SPDX-License-Identifier: MIT` |

El commit modifica **exactamente seis archivos**; no siete. Los siguientes **tres archivos sin cambios** son necesarios para el expediente de reproducibilidad: `LICENSE`, `go.mod` y `go.sum`. Se han fijado por **18 ID de blobs Git** en `GITEA_ORIGINAL_FILE_RIGHTS_SCOPE.json`: uno por versión y archivo. Se ejecuta además una comparación automática de los **hashes SHA-256 de sus bytes originales** con los árboles Git reales, sin publicarlos como código fuente.

## Entorno y dependencias

- Módulo raíz: `gitea.dev`. Versión Go declarada: **1.26.4**.
- Regresión `go test -tags sqlite -count=1 -timeout 10m -run '^TestRelease_Update$' ./services/release -v`.
- Los archivos `go.mod` (ID Git `1f2e923ce21ee69e26b6e90e37146a633d3ad273`) y `go.sum` (ID `34ab2024ed6e41ae05212044f383e846901e9c5e`) no cambiaron entre los dos commits. **Eso NO equivale a SBOM, aislamiento de dependencias completo ni licencias de todos los módulos Go**.
- Los tests se ejecutan dentro del árbol completo upstream. **Todavía no se demostró la compilación de un paquete reducido** formado únicamente por los nueve archivos enumerados. Antes de comercializar pares mínimos, se debe medir y auditar su cierre de importaciones, assets, fixtures, base de datos y requisitos de build.

## Licencias y propuesta de distribución compatible — pendiente de cumplimiento

- El archivo `LICENSE` original (blob `a8d4b49dd073a4a38a7e58385eeff7cc52568697`) declara **MIT**, con copyrights de The Gitea Authors y The Gogs Authors. Permite expresamente usos comerciales **bajo sus condiciones** y exige conservar textos de copyright y permiso en copias o porciones sustanciales.
- Los cinco `.go` anteriores tienen cabecera SPDX MIT. La plantilla `.tmpl` requiere análisis de su cobertura por licencia raíz y autorías; no inventar cabecera. Dependencias, contribuciones y recursos externos requieren revisión por componente.
- **Modelo propuesto:** atribuciones completas, licencia original intacta en todo contenido redistribuido, código de terceros separado de la evaluación/harness propio y de las condiciones del servicio; un comprador mantiene los derechos MIT aplicables al código ajeno. La facturación empresarial puede cubrir curación, prueba, formato, actualizaciones, análisis y soporte.
- **NO aprobado:** empaquetar el árbol upstream, omitir notices, transformar código MIT en exclusivo, sublicenciar sin cumplir condiciones, presentar el origen como íntegramente original de UltraSec o afirmar que una licencia raíz acredita todos los activos/dependencias.

## Integridad en CI

- `tools/gitea_source_scope.py` valida manifest estructural, commits, lista exacta, estados `NOT_ADMITTED` y derechos sin acreditar; al recibir el checkout upstream verifica directamente `rev-list`, `git diff`, cada blob, cabeceras Go, MIT raíz, Go mod y hashes SHA-256 de bytes.
- `.github/workflows/v7-gitea-native-regression.yml` ejecuta esa comprobación en ambos jobs de pruebas upstream y almacena recibos **solo de metadatos**. La prueba no marca licencias verificadas jurídicamente.
- `tests/test_gitea_source_scope.py` cubre corrupción de SHA, diferencia de origen, ausencia de ficheros, falso SPDX, licencias comerciales, paquete prematuro y contaminación de evaluación.

**Estado comercial:** 0 archivos de terceros autorizados en un paquete definitivo, 0 pares gold admitidos, 0 cierres de licencias de dependencias, `PRODUCT_READY=false`. Los revisores externos siguen **DEFERRED**.

**Siguiente acción para pasar de expediente a paquete real:** completar SBOM y licencias de dependencias realmente distribuidas; probar el empaquetado mínimo en entorno hermético con licencias/notices completos; verificar causalidad del test web nativo y mantener Gitea fuera del holdout ciego de detectores entrenados con este parche.
