# UltraSec V7 — cohorte cerrada de 5 candidatos, NO gold

**Corte:** 2026-10-17. **Fuente de verdad:** [COHORT_5_PRE_ADMISSION_PUBLIC.json](COHORT_5_PRE_ADMISSION_PUBLIC.json).
**Estado irrevocable en el repositorio público:** `NOT_ADMITTED / NOT_CERTIFIED`; esta investigación no contiene código vulnerable, etiquetas privadas, muestras de entrenamiento ni holdout. Los cinco candidatos de sustitución **no se han añadido** a los 100 CVE históricos.

## Orden de cierre por evidencia, no por cantidad de CVE

| CVE / familia | Evidencia upstream comprobada | Paso que falta para prueba CVE | Derechos históricos | Decisión |
|---|---|---|---|---|
| [CVE-2026-58428 / CWE-434](https://github.com/go-gitea/gitea/pull/38314) | [RED/GREEN nativo Gitea](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39073712740): mismo test `TestRelease_Update` trasplantado al padre; vulnerabilidad permite renombrar extensión prohibida, parche la rechaza; Go 1.26.4; producción original en ambos lados | Verificar que la falla que identifica el test corresponde al mismo mecanismo CNA, conservar archivos, commits y hashes, revisión externa ciega | MIT histórico [LICENSE](https://github.com/go-gitea/gitea/blob/7fdfb8d642201b388014f29889ef28e35b8c1872/LICENSE); autorización **de uso comercial bajo condiciones**, atribución por archivo y contrato concreto NO adjudicados | **Primer caso para revisión independiente** |
| [CVE-2024-2395 / CWE-352](https://nvd.nist.gov/vuln/detail/CVE-2024-2395) | [Paquetes oficiales WordPress.org 3.0.14/3.0.15](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39072993339/artifacts/12116265364); SHA-256 por archivo y 23 cambios; `wp_verify_nonce` y `current_user_can` nuevos | Ejecutar la misma petición controlada en ambas versiones y atribuir diferencias a CVE-2024-2395 frente a CVE-2024-0683; no duplicar causas | Versiones antiguas y avisos por archivo: **NO verificados**; un espejo más moderno GPLv3 no basta | **Pendiente E2E y licencia histórica** |
| [CVE-2025-69015 / CWE-862](https://github.com/Automattic/crowdsignal-forms/pull/302) | [PHPUnit upstream](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39073712720): 1.8.0, 98/98 pruebas; 1.7.2, 23 tests/1 error conocido, subset polls 9/9; cambios en rutas NPS y Feedback | Identificar exactamente el endpoint/privilegio de la asesoría y exigir RED/GREEN del mismo test adversarial; fallo de suite histórica NO equivale a CVE | GPL-2.0 histórico, [LICENSE.TXT](https://github.com/Automattic/crowdsignal-forms/blob/e0084d0760a16babe9ae441e24de3f4910d57b27/LICENSE.TXT); análisis jurídico del fragmento NO terminado | **Pendiente CVE-specific regression** |
| [CVE-2023-42799 / CWE-120](https://github.com/moonlight-stream/moonlight-common-c/commit/02b7742f4d19631024bd766bd2bb76715780004e) | Par fuente/fix original `116267a24569ec610f4c9efa1048541022981040` → `02b7742f4d19631024bd766bd2bb76715780004e`; una función C modificada | Compilar y ejecutar la función original con sanitizer antes/después; validación causal solo si coincide AddressSanitizer RED/GREEN, sin considerar un harness aislado como suite completa | GPL-3.0 en [LICENSE.txt](https://github.com/moonlight-stream/moonlight-common-c/blob/116267a24569ec610f4c9efa1048541022981040/LICENSE.txt); comercialización condicionada, sin clearance | **Pendiente test nativo** |
| [CVE-2024-48645 / CWE-862](https://github.com/arm32x/command-block-ide/commit/42e09840168d9c2fe2ee07f4472d296000b2a416) | Commit único Java modifica permiso de paquete `APPLY_FUNCTION` | Simular operaciones autorizadas/no autorizadas en entorno original Minecraft, comprobar efecto y ausencia de bypass sin contaminar split | LGPL-2.1 en [LICENSE](https://github.com/arm32x/command-block-ide/blob/7da8ea77ba3443c42e0d9929f66b370bb97c0234/LICENSE); derechos concretos NO revisados | **Pendiente test de integración** |

## Aceptación real, orden obligatorio

**A. Ingeniería:** material original del proveedor con SHA-256 del mismo archivo antes/después, revisión SHA/release inmutable, CVE/CWE contrastado con CNA, mismo oráculo ejecutado en condiciones controladas, RED anterior/GREEN corregido, mecanismo distinto y sin alias.

**B. Derechos:** inventario completo de licencias y titulares por archivo en la revisión exacta, obligaciones para redistribuir fragmentos, código, diffs y anotaciones; conservar avisos y fuentes cuando aplique. Una licencia abierta **no** autoriza afirmar exclusividad, protección legal de la compilación ni certificado de reventa. Dictamen firmado de revisor legal competente para los términos y territorios de la oferta; estado `COMMERCIAL_RIGHTS=NOT_VERIFIED` hasta entonces. Fuentes primarias: [GNU GPL FAQ](https://www.gnu.org/licenses/gpl-faq.html), [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0), licencias históricas enlazadas arriba.

**C. Independencia:** dos revisores externos de seguridad sin acceso a etiquetas gold o respuestas del propio detector; registro de identidad real y conflictos de interés, hashes sellados, decisiones individuales y desacuerdos resueltos por protocolo. El autor, GitHub Actions, Exa, Sentry, Context7 y modelos de IA **no sustituyen firmas humanas independientes**.

**D. Separación:** sin importación a entrenamiento ni holdout hasta después de las verificaciones A–C; asignación de split por proyecto/familia/commit y comprobación de contaminación mediante hashes de código y grafo de dependencias; los cinco sustitutos están `UNASSIGNED` y `NOT_ADMITTED`. Para benchmark SAST se necesita escanear contra gold real congelado: los checks CodeQL/Semgrep de este repositorio son **solo referencia pública**.

**E. Admisión:** únicamente en el archivo privado bajo control del propietario, tras A–D, con referencia a autorización real. El registro público y su validador **nunca** certifican gold ni modifican el holdout; `gold_count=0` es correcto aquí.

## Control automático

- `python3 ultrasec-v7/tools/verify_candidate_cohort.py ultrasec-v7/verification/research/COHORT_5_PRE_ADMISSION_PUBLIC.json`
- `python3 -m pytest -q ultrasec-v7/tests/test_verify_candidate_cohort.py`
- Rechazar estados de certificación inventados, duplicados, fuentes sin SHA/release hash, derechos/autorizaciones autopropuestos y particiones asignadas antes de tiempo.
- **No confundir un check de estructura verde con verificación externa de URL, dictamen jurídico o examen ciego.**

## Observabilidad

El plugin Sentry solo aporta errores operativos de un proyecto conectado y autenticado; no determina si un CVE está correctamente etiquetado ni acredita licencias. No se ha comprobado un proyecto Sentry de UltraSec V7 asociado con este lote y **no** se declara instrumentación ni escaneo privado.

**Resultado actual:** cinco solicitudes de evidencia preparadas; **0 gold**, **0/2 revisores**, **0 derechos individuales aprobados**, benchmark SAST privado `NOT_RUN`, certificación `NOT_CERTIFIED`. Mantener PR #10 en Draft y el PR #7 independiente.
