# UltraSec V7 — ejecución upstream real, versiones oficiales WordPress y sustitutos

**Corte:** 17-10-2026 · **Estado:** `NOT_ADMITTED / NOT_CERTIFIED`. Solo metadatos públicos; ningún fragmento de código vulnerable, resultados privados, gold o secretos publicados.

## 1. Crowdsignal Forms — experimentos reales en GitHub Actions

GitHub Actions del PR #10 ejecuta los commits oficiales, **fijados por SHA y comprobados con git**:
- 1.7.2: `e0084d0760a16babe9ae441e24de3f4910d57b27`.
- 1.8.0: `9ebf48d8d9d80fe96a2813d9a66120431399cac9`.
- Origen: [Automattic/crowdsignal-forms](https://github.com/Automattic/crowdsignal-forms).
- Entorno: Ubuntu 22.04 runner, PHP 8.1.34, WordPress 6.6.2 (biblioteca PHPUnit de WordPress desde SVN), MySQL 8.0, PHPUnit 9.6.38. Dependencias PHP del plugin tomadas de los `composer.lock` de las revisiones. PHPUnit Polyfills 2.0.0 instalado en directorio separado.
- Huella SHA-256 `composer.lock` 1.7.2: `7a87f526f870783cc75050155da51f1e7e08cda14495e2bd6a3acaf4333f44be`. 1.8.0: `cb27ad4b779bf396eab2e6221739d729f2ff2da9b09ac194db778db60799b9cd`.

**Resultados comprobados en logs originales del run** [39072993339](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39072993339):
- **1.8.0:** `OK (98 tests, 191 assertions)`, ejecución del `phpunit.xml` y `tests/bootstrap.php` upstream, sin modificar fuentes ni pruebas. Hubo avisos por `build/*.asset.php` faltantes: éxito PHPUnit **no** implica compilación integral del frontend o entorno libre de warnings.
- **1.7.2:** el primer intento de ejecutar PHPUnit falló en `setUp():void` del framework de tests de versiones modernas. Se aplicó una **adaptación temporal solo a siete declaraciones en cinco archivos de test**, con hashes antes/después; ninguna fuente de producción se modificó. Tras ello se ejecutaron `23 tests / 50 assertions / 1 error`: `Account_Controller_Test::test_get_capabilities` llama un método `Account_Controller::get_capabilities()` inexistente en la revisión antigua. **Suite completa FALLÓ; no ocultar, no contar como PASS.** Se programó un test focalizado sobre el controlador REST de polls de 1.7.2 sin alterar la suite general.
- Ambos ensayos son *upstream PHPUnit*; no representan un ataque CVE real de autorización NPS/Feedback. El aviso público [CVE-2025-69015](https://nvd.nist.gov/vuln/detail/CVE-2025-69015) no identifica inequívocamente la función vulnerable. Sigue pendiente atribución exacta, comparación del mismo test adversarial en vulnerable/corregido y reproducción E2E.

El workflow `.github/workflows/v7-crowdsignal-upstream-verification.yml` es de investigación y usa permisos `contents:read`, fuentes públicas fijadas, runner temporal y artefactos de **logs/metadatos**, no dataset ni holdout.

## 2. Bulgarisation — dos paquetes oficiales obtenidos y comparados

La referencia SVN en [NVD CVE-2024-2395](https://nvd.nist.gov/vuln/detail/CVE-2024-2395) señala la revisión `3034198`, pero la ruta SVN etiquetada 3.0.14 no pudo exportarse en esa revisión (`E160013`). **No afirmar que se han recuperado dos snapshots del SVN.**

Se descargaron, descomprimieron e inspeccionaron **dos ZIP oficiales versionados de WordPress.org**:
- [3.0.14](https://downloads.wordpress.org/plugin/bulgarisation-for-woocommerce.3.0.14.zip), SHA-256 ZIP `27d26aa7471ba11f93dad473bd055be5a3f38484a8e103abb7b6f0d404067612`.
- [3.0.15](https://downloads.wordpress.org/plugin/bulgarisation-for-woocommerce.3.0.15.zip), SHA-256 ZIP `84040bef3e55107962e16d49aebfdbccbbf61f790994642266a86096ee14f2f8`.
- [Ejecución 39072993339 y artefacto oficial de metadatos](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39072993339/artifacts/12116265364).
- Comparación del contenido de ambas distribuciones: **23 archivos diferentes**. `app/functions.php` añade una llamada `wp_verify_nonce` y otra a `current_user_can`. En `app/Admin/CVC.php`, `app/Admin/Econt.php`, `app/Admin/Speedy.php` se eliminan referencias de registro a `wp_ajax_` y `wp_ajax_nopriv_` en el diff. El artefacto contiene **hash SHA-256 por archivo de ambas versiones**, listado de rutas y conteos de llamadas de API de seguridad.
- El cambio de autorización aporta evidencia causal **estructural**, pero aún no se ha ejecutado el plugin ni demostrado la diferencia de resultado de una petición WordPress legítima/ilegítima; `CVE-2024-2395` (CSRF) y `CVE-2024-0683` (autorización) comparten versión corregida, por lo que no deben contarse como dos mecanismos gold sin pruebas independientes.
- Licencia de los archivos en ambas distribuciones y derechos contractuales individuales: **todavía no validados**. El repositorio espejo contemporáneo no sustituye una auditoría de la licencia en cada ZIP.

## 3. Cinco sustitutos — fuentes, límites y segregación

Las referencias de sustitución NO forman parte de los 100 CVE iniciales (comparación con 37+63 manifiestos) y **tampoco se admiten al gold**.

| CVE | Fuente oficial / revisión | Licencia histórica observada | Estado causal |
|---|---|---|---|
| CVE-2023-25170 / CWE-352 | [PrestaShop PR #32140](https://github.com/PrestaShop/PrestaShop/pull/32140); merge `82cebe6c40e724782925dfeaa56dd22b31eb144b` con dos padres | `LICENSE.md` blob `8352e430f1a6b4f5f1d96e31510ee71cc7cf7a30` indica OSL-3.0 core y AFL-3.0 módulos | Pendiente de elegir diff base y ejecutar tests SessionRenewer originales |
| CVE-2024-48645 / CWE-862 | [arm32x/command-block-ide](https://github.com/arm32x/command-block-ide/commit/42e09840168d9c2fe2ee07f4472d296000b2a416), fix `42e09840168d9c2fe2ee07f4472d296000b2a416`, padre `7da8ea77ba3443c42e0d9929f66b370bb97c0234`, un archivo Java modificado | LGPL-2.1 `LICENSE` blob `ee9ed415ee14252a64a1bba6d73c85deb6551dc7` | Control APPLY_FUNCTION vinculado a reporte CVE, falta test en servidor |
| CVE-2023-42799 / CWE-120 | [Moonlight common C](https://github.com/moonlight-stream/moonlight-common-c/commit/02b7742f4d19631024bd766bd2bb76715780004e), fix `02b7742f4d19631024bd766bd2bb76715780004e`, padre `116267a24569ec610f4c9efa1048541022981040`, un archivo `RtspConnection.c` | GPL-3.0 `LICENSE.txt` blob `9cecc1d4669ee8af2ca727a5d8cde10cd8b2d7cc` | Reemplaza operación de copia no acotada, sin compilación upstream ni test de límite |
| CVE-2026-55546 / CWE-94 | [QWED-AI/qwed-mcp](https://github.com/QWED-AI/qwed-mcp/commit/362e61892052e250c56cb1ee852024d6f98c467b), fix `362e61892052e250c56cb1ee852024d6f98c467b`, padre `54ac682699407310b5a71fbaed8c33f581b84301` | Apache-2.0 `LICENSE` blob `261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64` | Hubo endurecimiento posterior tras bypass; inicial NO acreditado como remediación completa, no ejecutar payloads |
| CVE-2026-58428 / CWE-434 | **[Gitea PR #38314](https://github.com/go-gitea/gitea/pull/38314)**, corrección específica `e4ef995f2a162e3aca3f3a0b536afae067975d71`, padre `7fdfb8d642201b388014f29889ef28e35b8c1872` | MIT `LICENSE` blob `a8d4b49dd073a4a38a7e58385eeff7cc52568697` | Mejor que batch genérico `f69e15...`: valida allowlist al renombrar adjunto web e introduce pruebas unitarias/integración. Repro upstream aún pendiente |

**Aislamiento:** cinco nuevas pistas solo en investigación (`QUARANTINED`), `DATA_SPLIT=UNASSIGNED`, `EVALUATION_HOLDOUT=NO`, `TRAINING_IMPORT=NO`, `INDEPENDENT_GOLD=NO`; no generar etiquetas ni contaminación cruzada antes de cierre del corpus y verificación independiente. No se infiere el derecho de vender snippets, parches o datasets derivados solo por hallar un texto de licencia upstream.

## 4. Decisión de admisión

No se ha ejecutado prueba vulnerable/fix E2E para Crowdsignal, Bulgarisation o sustitutos. Un check verde de la CI pública no certifica Causal V7, autoría, licencias, holdout, 500 familias independientes ni benchmark SAST real.

**GOLD=0 nuevos; REVIEWERS_SIGNED=0/2; COMMERCIAL_RIGHTS=NOT_VERIFIED; REAL_SAST=NOT_RUN; V7=NOT_CERTIFIED.**

El PR #7 y `main` no se deben fusionar por esta evidencia. Mantener #10 en Draft, con los fallos upstream visibles.
