# UltraSec V7 — Crowdsignal, SVN y sustituciones (17-10-2026)

**Ámbito:** investigación pública, sin material privado ni código vulnerable de terceros. **Estado: NOT_ADMITTED / NOT_CERTIFIED.** Este informe no sustituye pruebas humanas, SAST real ni autorización de uso comercial.

## 1. CVE-2025-69015 — Crowdsignal Forms

**Fuentes:** [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-69015), [Wordfence](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/crowdsignal-forms/crowdsignal-forms-172-missing-authorization), [Automattic PR #302](https://github.com/Automattic/crowdsignal-forms/pull/302).

| Control | 1.7.2 (vulnerable según CNA) | 1.8.0 (corregida según CNA) |
|---|---|---|
| Revisión Git de tag | `e0084d0760a16babe9ae441e24de3f4910d57b27` | `9ebf48d8d9d80fe96a2813d9a66120431399cac9` |
| REST `POST /nps`, `PUT /nps/:survey_id` | Presentes; permiso `publish_posts` | Ausentes |
| REST `POST /feedback`, `PUT /feedback/:survey_id` | Presentes; permiso `publish_posts` | Ausentes |
| Rutas de envío de respuestas NPS/Feedback | Presentes | Presentes |
| Guardado y edición en post | Mutaciones REST directas | Se incorpora sincronización con hooks de guardado y controles `edit_post` |

**Trazabilidad Git blob:**
- NPS `includes/rest-api/controllers/class-nps-controller.php`: 1.7.2 `941f904afc2a22d7d9ec3264ed18d2cdc060e105`, 1.8.0 `e338e1d94babcc0f45cda0ac946e1671658f4322`.
- Feedback `includes/rest-api/controllers/class-feedback-controller.php`: 1.7.2 `301d10253c5b43cf8f7200437bdc8dbcb90565dc`, 1.8.0 `a2f87d3683cf204f6a67ef1387bf6b7362beca85`.
- `LICENSE.TXT` de ambas versiones: `ecbc0593737be657aef92e3adcf3bcbd6fdb812e`, GPL-2.0.

**Prueba ejecutada:** snapshot manual de diez propiedades de rutas contrastado contra los cuatro archivos oficiales. `php test_route_snapshot.php` produjo **10/10 PASS**. El test se creó inicialmente sin el snapshot (RED, salida 2) y pasó al incorporar el snapshot (GREEN). Es una **prueba de estructura de rutas**, NO una ejecución del código upstream, ni WordPress/PHPUnit, ni una explotación reproducida de CVE-2025-69015. El aviso CNA no especifica función; vincular el CVE a un único cambio de #302 aún necesita corroboración upstream/E2E.

### Obligaciones GPLv2
El texto histórico GPLv2 **permite la venta de copias sujetas a la licencia**; no autoriza afirmar propiedad exclusiva del código upstream ni imponer restricciones de redistribución incompatibles a los receptores. Si se distribuye código o una obra derivada cubierta, son relevantes copia de licencia, avisos de copyright, acceso al fuente correspondiente y demás obligaciones específicas. El impacto sobre un dataset comercial que contenga extractos, parches, tests o derivaciones necesita análisis jurídico por **archivo, volumen, atribución y forma contractual de entrega**. Publicar solo metadatos no acredita derechos de reventa para la cohorte privada. **COMMERCIAL_RIGHTS=NOT_VERIFIED.** [Preguntas frecuentes GNU GPLv2](https://www.gnu.org/licenses/old-licenses/gpl-2.0-faq.html).

## 2. CVE-2024-2395 — Bulgarisation for WooCommerce

[NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-2395) identifica versiones hasta 3.0.14 afectadas, la versión 3.0.15 como umbral corregido y la revisión de SVN WordPress `3034198`. CWE-352 (NVD) / CWE-862 (CNA) **sin adjudicación mecanística independiente**. Además, [CVE-2024-0683](https://nvd.nist.gov/vuln/detail/CVE-2024-0683) se refiere a falta de autorización en el mismo plugin y la misma revisión; **no duplicar mecanismos sin diferenciar los cambios**.

**Limitación:** la URL oficial `https://plugins.trac.wordpress.org/changeset/3034198/bulgarisation-for-woocommerce` y las rutas SVN de tags 3.0.14/3.0.15 no devolvieron contenido accesible desde las herramientas actuales; no hay diff ni SHA descargados. Se verificó la **referencia** en NVD, no el contenido de la revisión SVN. Estado: **SVN_PATCH_NOT_RETRIEVED**, `UPSTREAM_TEST=NOT_RUN`, `RIGHTS=NOT_VERIFIED`.

## 3. Cinco propuestas de sustitución — no son admisiones

| CVE | CWE | Repositorio / commit original identificado | Padre o limitación | Licencia histórica observada | Estado |
|---|---|---|---|---|---|
| [CVE-2023-25170](https://nvd.nist.gov/vuln/detail/CVE-2023-25170) | 352 | [PrestaShop PR #32140](https://github.com/PrestaShop/PrestaShop/pull/32140), merge `82cebe6c40e724782925dfeaa56dd22b31eb144b` | Merge con **dos padres**; el primero `34e54550287d8a08d546d1b7bddc6ca2246ebef8` es base de rama 1.7.8.x. NO usar como fix causal `d24aaafdb4ffea40adf6f9cfeb25e02cd6077855`: su diff solo cambia CONTRIBUTORS.md. | Core OSL-3.0; módulos AFL-3.0, licencia `LICENSE.md` blob `8352e430f1a6b4f5f1d96e31510ee71cc7cf7a30`. | **PATCH_SOURCE_FOUND, NOT_REPRODUCED** |
| [CVE-2024-48645](https://nvd.nist.gov/vuln/detail/CVE-2024-48645) | 862 | [Command Block IDE](https://github.com/arm32x/command-block-ide/commit/42e09840168d9c2fe2ee07f4472d296000b2a416) `42e09840168d9c2fe2ee07f4472d296000b2a416` | Parent `7da8ea77ba3443c42e0d9929f66b370bb97c0234`, agrega verificación permissionLevel(2) antes del procesamiento de paquete APPLY_FUNCTION. | LGPL-2.1, licencia blob `ee9ed415ee14252a64a1bba6d73c85deb6551dc7`. | **PATCH_SOURCE_FOUND, NOT_REPRODUCED** |
| [CVE-2023-42799](https://nvd.nist.gov/vuln/detail/CVE-2023-42799) | 120 | [Moonlight Common C](https://github.com/moonlight-stream/moonlight-common-c/commit/02b7742f4d19631024bd766bd2bb76715780004e) `02b7742f4d19631024bd766bd2bb76715780004e` | Parent `116267a24569ec610f4c9efa1048541022981040`, reemplaza `strcpy` por copia acotada en RTSP. | GPL-3.0, blob `9cecc1d4669ee8af2ca727a5d8cde10cd8b2d7cc`. | **PATCH_SOURCE_FOUND, NOT_REPRODUCED** |
| [CVE-2026-55546](https://nvd.nist.gov/vuln/detail/CVE-2026-55546) | 94 | [QWED MCP](https://github.com/QWED-AI/qwed-mcp/commit/362e61892052e250c56cb1ee852024d6f98c467b) `362e61892052e250c56cb1ee852024d6f98c467b` | Parent `54ac682699407310b5a71fbaed8c33f581b84301`; hay posterior endurecimiento `d05f537f6e02f65cf3b6cf3ff4910a2555d10b1e` por bypass residual. | Apache-2.0, blob `261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64`. | **PATCH_SOURCE_FOUND, RESIDUAL_BYPASS_NOT_CLEARED** |
| [CVE-2026-58428](https://nvd.nist.gov/vuln/detail/CVE-2026-58428) | 434 | [Gitea GHSA](https://github.com/advisories/GHSA-25gq-j9jx-43pg), cambios `f69e15afe7496cc62e96dab244629c69eb31a7bf` y backport `de4b8277e9cb576f2315fb03b5ab6478b42a1d31` | **Parche multi-hallazgo** de 93 archivos: en la inspección no se aisló la corrección específica de extensión/adjuntos. No confundir referencia a commit con causalidad comprobada. | MIT, blob `a8d4b49dd073a4a38a7e58385eeff7cc52568697`. | **WEAK — FIX_CAUSALITY_UNCONFIRMED** |

Ninguno aparece en los 37 CVE del manifiesto histórico ni en los 63 de la rama de investigación, según comprobación de duplicados. **No sustituyen efectivamente** los cinco CVE bloqueados en el conjunto gold hasta quedar reproducidos, tener licencias/contratos validados y revisión independiente. Tampoco debe confundirse contar cinco candidatos con obtener cinco mecanismos independientes.

## 4. Admisión y CI

**Gold nuevos: 0. Firmas humanas: 0/2. SAST sobre gold real: NOT_RUN. Commercial rights: NOT_VERIFIED.** Mantener PR #7 y #10 Draft. La CI pública solo valida fixtures públicos. No se han efectuado capturas, ejecución de PHPUnit/WordPress, ni análisis jurídico que autorice comercialización.
