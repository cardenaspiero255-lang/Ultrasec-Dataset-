# UltraSec V7 — auditoría inicial de 4 commits y búsqueda de los 59 restantes

**Corte:** 17-10-2026 · **Ámbito:** metadatos de investigación pública, **NO_ADMITTED** · **Base:** PR #10 (Draft) sobre PR #7 (Draft).

Este documento **no certifica** código de terceros, licencias, CVE, reproducción completa, autorización comercial ni gold. No se exporta código vulnerable. Los estudios aislados detallados y sus logs se conservan fuera de GitHub.

## Cuatro CVE inicialmente vinculados a commits

| CVE / CWE | Repo oficial / SHA fix | Padre inmediato | Evidencia causal leída | Licencia en la revisión anterior | Reproducción |
|---|---|---|---|---|---|
| CVE-2021-25932 / CWE-79 | OpenNMS/opennms: `8a97e6869d6e49da18b208c837438ace80049c01` | `795106d2b216b88d872dc97fba3639cca70e5631` | Validación server-side de IDs de usuario/grupo; el mismo commit cubre múltiples pantallas, por lo que no asumir independencia con CVE-2021-25933 | `COPYING` blob `dba13ed2ddf783ee8118c6a581dbf75305f816a3`, `LICENSE.md` blob `58207820cdf807b7f4f4ce14102cd39544802c1e`: AGPL-3.0 | Tests de app NO ejecutados |
| CVE-2026-73140 / CWE-862 | MISP/cti-transmute: `5dbd19b39a61eab793586731f1a80d8c38907c42` | `06d408e3496fdfc31da22d7b2b427434c67eae94` | `build_evaluation_report` agrega un filtro por usuario para los comentarios del reporte; anteriormente la lista se incorporaba sin verificar privacidad | `LICENSE` blob `0ad25db4bd1d86c452db3f9602ccdbe172438f52`: AGPL-3.0 | Tests de app NO ejecutados |
| CVE-2023-43256 / CWE-22 | GladysAssistant/Gladys: `f27d0ea4689c3deca5739b5f9ed45a2ddbf00b7b` | `8d09d2be050b4f505fefe4b2528f9b9b1d07f830` | Controlador de streaming agrega validaciones y tests, pero la validación de nombre usa regex sin anclas y punto sin escapar; **la corrección es incompleta para ciertas entradas** según prueba unitaria aislada | `LICENSE` blob `7af6969976f3d720a8d7f6329fd76ebc0cfd4af9`: Apache-2.0 | Se reprodujeron tres fallos de validación en **el archivo exacto** del commit; no se demostró explotación HTTP E2E |
| CVE-2020-36280 / CWE-125 | DanBloomberg/leptonica: `5ba34b1fe741d69d43a6c8cf767756997eadd87c` | `ab66d051d8fd57584c350d687a8cc2424565c33c` | `src/tiffio.c` amplía reserva de línea TIFF para gray+alpha; parche relacionado con OSS-Fuzz #23654 | `leptonica-license.txt` blob `73d44c601c0746534128804c3fb0b93772897f82`: licencia permisiva con condiciones de atribución y aviso | Reproducción en binarios base/fix NO ejecutada |

**Los cuatro commits y sus primeros padres existen.** Un parche pertinente y el primer padre no prueban por sí solos que la versión previa sea vulnerable en una configuración reproducible.

### Hallazgo de seguridad en Gladys (sin publicar payload)

El blob **idéntico** al archivo `server/services/rtsp-camera/utils/validateStreamParams.js` de `f27d0ea...` fue comprobado mediante Git blob SHA-1:
`6585341516562db2707ed4817efedb3b462f89e6`.

- Runtime: Node.js 22.16.0; tests aislados sobre el archivo original más un stub mínimo de errores. Se ejecutaron 7 pruebas: **4 PASS / 3 FAIL**. Fallaron expectativas de rechazo de nombres de archivo con rutas o formato no válido.
- Control local, **no aplicado a upstream**: regularización de la expresión HLS con anclas y escape de punto. Sus 7 pruebas dieron **7 PASS**.
- Un test de ruta hace solo cálculo de `path.resolve`, **sin acceder a archivos del sistema**. No se hizo prueba real de endpoint, autorización ni decodificación URL. **No se declara que el CVE siga siendo explotable**, solo que el validador acepta entradas fuera de la intención declarada; el caso requiere auditoría adicional y exclusión del gold hasta aclarar el alcance.

### Búsqueda entre los 59 CVE antes sin enlaces a commits

| CVE | Evidencia localizada ahora | Clasificación |
|---|---|---|
| CVE-2021-32422 / CWE-120 | NVD enlaza el commit oficial dpic/GitLab `d317e4066c17f9ceb359b3af13264c32f6fb43cf`; GitLab lo muestra con padre abreviado `68ab9432`. El diff muestra cambios de robustez ante fuzzing y `Copyright.txt` declara BSD-2-Clause para fuente, pero otras licencias para documentación. | **COMMIT_REF_FOUND — NOT_REPRODUCED — RIGHTS_NOT_CLEARED** |
| CVE-2024-46724 / CWE-125 | El anuncio oficial de la lista de seguridad del kernel enumera **6 commits de backport**; upstream `d768394fa99467bcf2703bde74ddc96eeb0b71fa`. Revisar historia de ramas; **no usar automáticamente el primer padre de cada backport como caso independiente**. | **UPSTREAM_PATCH_REFS_FOUND — NOT_REPRODUCED — RIGHTS_NOT_CLEARED** |
| CVE-2025-45843 / CWE-787 | NVD refiere a firmware propietario TOTOLINK y a una publicación de investigación; **no se identificó un repositorio con ambos blobs originales redistribuibles**. | **DEPRIORITIZED_UNAVAILABLE_SOURCE — NOT_ADMITTED** |
| CVE-2022-37886 / CWE-120 | Afecta firmware Aruba/Siemens; solo se identificaron avisos y versiones de actualización, no commits fuente. | **DEPRIORITIZED_UNAVAILABLE_SOURCE — NOT_ADMITTED** |

Fuentes de revisión: [NVD dpic](https://nvd.nist.gov/vuln/detail/CVE-2021-32422), [GitLab commit dpic](https://gitlab.com/aplevich/dpic/-/commit/d317e4066c17f9ceb359b3af13264c32f6fb43cf), [anuncio kernel](https://lists.openwall.net/linux-cve-announce/2024/09/18/19), [Ubuntu kernel](https://ubuntu.com/security/CVE-2024-46724), [NVD TOTOLINK](https://nvd.nist.gov/vuln/detail/CVE-2025-45843).

**No se afirma haber revisado exhaustivamente los otros 55 registros sin commit localizado.** El resto permanece pendiente de cotejo NVD/aviso original y búsqueda de SHAs exactos. Esta fase identificó candidatos de mejor y peor calidad sin modificar sus criterios de admisión.


### Corroboración independiente del parche incompleto de Gladys

La base pública [CIRCL Vulnerability-Lookup](https://cve.circl.lu/vuln/gsd-2023-47440) documenta **GSD-2023-47440 / CVE-2023-47440** como una traversía de directorio en versiones Gladys <=4.27.0, describiendo explícitamente que el parche previo de CVE-2023-43256 era incompleto. Esta fuente externa es consistente con los fallos aislados del validador; **no sustituye la reproducción de un exploit en la aplicación**. La posible relación histórica entre ambas CVE requiere revisión: **no contarlas como dos mecanismos independientes sin demostrar causalidad distinta**.

## Derechos, holdout y liberación

Inspeccionar `LICENSE` en un commit acredita un texto histórico, no el derecho para *un paquete comercial derivado concreto*. Comprobar archivos cubiertos, titulares, terceros, avisos, condiciones copyleft, atribución, redistribución, sublicencia, privacidad y asesoramiento legal cuando corresponda.

Cualquier admisión futura exige evidencia externa independiente, caso vulnerable/fix ejecutado en sandbox con logs, huellas de contenido, revisión de derechos y control de leakage. El estado de todos los CVE aquí descritos sigue: **GOLD=NOT_ADMITTED; SAST_REAL=NOT_RUN; RIGHTS=NOT_VERIFIED**.

**PR #7 no se modifica ni se fusiona.** PR #10 debe permanecer Draft hasta comprobación final de CI y criterios de su propio alcance, sin confundir CI pública con certificación comercial.
