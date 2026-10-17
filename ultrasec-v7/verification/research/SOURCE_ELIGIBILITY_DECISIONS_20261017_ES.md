# UltraSec V7 — decisiones de elegibilidad para 63 candidatos

**Corte:** 2026-10-17 · **Ámbito:** metadatos públicos, no gold. **HEAD de referencia:** PR #10 sobre PR #7. Los 63 candidatos GHSA iniciales **no** se consideran verificados porque existan avisos o correcciones.

## Casos prioritarios con fuente accesible

| CVE / CWE | Origen verificable | Comparación de revisiones | Estado de pruebas originales | Derechos | Decisión |
|---|---|---|---|---|---|
| CVE-2025-69015 / CWE-862 | [Automattic/crowdsignal-forms](https://github.com/Automattic/crowdsignal-forms), [PR #302](https://github.com/Automattic/crowdsignal-forms/pull/302), [WordPress.org](https://wordpress.org/plugins/crowdsignal-forms/), [Wordfence](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/crowdsignal-forms/crowdsignal-forms-172-missing-authorization) | Etiqueta 1.7.2 (tag anotado que apunta a **e0084d0760a16babe9ae441e24de3f4910d57b27**) frente a 1.8.0 (**9ebf48d8d9d80fe96a2813d9a66120431399cac9**); 9 commits entre versiones. [PR #302](https://github.com/Automattic/crowdsignal-forms/commit/e1f6d4733f61fccc620e28f2d2321046b1791187) introduce controles `edit_post` y medidas en API. **No se ha demostrado todavía que el cambio aislado de #302 sea la única corrección causal del CVE.** | `NOT_RUN`; requiere WordPress, PHP y dependencias completas; se han consultado instrucciones upstream, no ejecutado PHPUnit | `LICENSE.TXT` histórico GPLv2, Git blob **ecbc0593737be657aef92e3adcf3bcbd6fdb812e** idéntico en ambas etiquetas; derechos de reventa de dataset concreto `NOT_VERIFIED` | **HIGH_PRIORITY_PENDING_CAUSAL_REPRODUCTION** |
| CVE-2024-2395 / CWE-352 (CNA también CWE-862) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-2395) y [SVN WordPress](https://plugins.trac.wordpress.org/changeset/3034198/bulgarisation-for-woocommerce) | SVN changeset 3034198 referenciado, pero sin dos snapshots, hashes ni prueba; no inventar SHA Git | `NOT_RUN` | `NOT_VERIFIED` | **PENDING_SVN_DIFF_AND_LICENSE** |
| CVE-2024-11921 / CWE-79 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-11921), GiveWP | Release 3.19.0 identifica el umbral de corrección; sin diff causal verificado | `NOT_RUN` | `NOT_VERIFIED` | **PENDING_VERSIONED_SOURCE** |

## Candidatos NO elegibles hoy para holdout fuente/fix

| CVE | Hallazgo externo específico | Motivo de bloqueo | Estado |
|---|---|---|---|
| CVE-2025-60173 | [Patchstack](https://patchstack.com/database/wordpress/plugin/gst-for-woocommerce/vulnerability/wordpress-gst-for-woocommerce-plugin-2-0-cross-site-request-forgery-csrf-vulnerability) dice **No official patch available** | No existe un fix oficial acreditado para formar el par causal | **HOLDOUT_INELIGIBLE_NO_OFFICIAL_FIX** |
| CVE-2025-32279 | [Wordfence — ficha CVE](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/liveforms) indica **Unpatched**; distingue CVE-2025-30809 y CVE-2025-39560 sí corregidos | No asignar a este CVE la reparación 4.8.5 de otro defecto | **HOLDOUT_INELIGIBLE_UNPATCHED** |
| CVE-2022-1519 | [CISA ICSA-22-153-02](https://www.cisa.gov/ics/advisories/icsa-22-153-02) acredita **parche binario** y digest SHA-256, no entrega código fuente original ni licencia de redistribución | Prueba binaria del proveedor no es commit fuente ni concesión de reventa | **HOLDOUT_INELIGIBLE_NO_SOURCE_RIGHTS** |
| CVE-2024-36074 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-36074), [Netwrix ADV-2024-002](https://community.netwrix.com/t/adv-2024-002-remote-code-execution-vulnerabilities-in-cososys-endpoint-protector-and-cososys-unify/3472) | Avisos y hotfix de software comercial; no se acreditó código histórico redistribuible | **HOLDOUT_INELIGIBLE_NO_SOURCE_RIGHTS** |
| CVE-2025-6130 | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-6130) cita firmware TOTOLINK EX1200T, sin commit oficial fuente | Una prueba de concepto de terceros no constituye fuente autorizada ni fix | **HOLDOUT_INELIGIBLE_NO_SOURCE_RIGHTS** |

**Regla de recuento:** 63 identificadores de descubrimiento permanecen intactos; los cinco marcados `HOLDOUT_INELIGIBLE` quedan **fuera del conjunto elegible** hasta nueva evidencia, no borrados de la historia. Ninguno de estos cinco se reemplaza todavía con un caso ficticio. No asumir que 58 restantes son aptos: la elegibilidad de ellos **no está acreditada**.

## Casos con evidencia aislada previa (no upstream full suite)

- **CVE-2023-43256 / Gladys:** código exacto upstream del commit `f27d0ea4689c3deca5739b5f9ed45a2ddbf00b7b`, blob `6585341516562db2707ed4817efedb3b462f89e6`: prueba aislada de siete casos, **3 PASS / 4 FAIL**. El archivo de test upstream requiere `mocha`, `chai`, `sinon`, `proxyquire`, `fs-extra` y la app; **no** se ejecutó la suite completa.
- **CVE-2024-46724 / Linux:** [anuncio oficial](https://lists.openwall.net/linux-cve-announce/2024/09/18/19), upstream fix `d768394fa99467bcf2703bde74ddc96eeb0b71fa`, parent `cdca89bce4984f1bb6e53cd4084820d4ff54f977`; cinco backports **no son cinco CVE**. Harness C local aislado con GCC/UBSan detecta acceso fuera de límite en la variante previa y no en la corregida; **no** kernel compilado ni hardware probado.

## Limitaciones de entorno y próximas verificaciones

Se comprobó falta de resolución DNS de `github.com` desde la terminal de ejecución, impidiendo `git clone`, `npm ci` o descargar fuentes y dependencias upstream. Las consultas GitHub disponibles vía conector verifican blobs, revisiones y diffs, pero no ejecutan builds upstream. **No se simulan suites ni revisores.**

Priorizar CVE-2025-69015: cotejar cada archivo del PR #302, clasificar componentes, localizar la prueba de regresión original, fijar etiquetas 1.7.2 y 1.8.0, ejecutar comparativa en sandbox con WordPress autorizado y guardar digests. Paralelamente resolver la revisión SVN de CVE-2024-2395. Los candidatos no elegibles permanecen fuera del holdout y son candidatos para sustitución **solo cuando exista un reemplazo con procedencia real**.

**Estado contractual:** todos `COMMERCIAL_RIGHTS=NOT_VERIFIED`. **Gold nuevos:** 0. **Firmas humanas:** 0/2. **SAST real:** NOT_RUN. **Certificación:** NOT_CERTIFIED.
