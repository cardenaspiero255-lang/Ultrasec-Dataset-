# UltraSec Dataset V7 — controles negativos originales, causalidad y preinscripción de holdout/SAST

**Corte:** 19-10-2026. Documento de ingeniería, no certificado, adjudicación jurídica ni comercial.

## 1. Gitea: CVE-2026-58428 (CWE-434)

- Árbol original vulnerable: `7fdfb8d642201b388014f29889ef28e35b8c1872`.
- Árbol original corregido: `e4ef995f2a162e3aca3f3a0b536afae067975d71`.
- Oráculo original `TestRelease_Update` del parche (testigo sobre padre sin cambiar producción): antes falla por renombrado con extensión no permitida, después rechaza correctamente.
- **Control negativo nuevo:** [gitea_release_negative_control_test.go](../../verification/research/gitea_release_negative_control_test.go) se copia a los dos árboles originales solo durante CI. `TestUltraSecReleaseAllowedRename` verifica, bajo `AllowedTypes=.zip`, que el renombrado benigno `allowed.zip→renamed.zip` se acepta y persiste, y que un cambio de nota sin modificar adjuntos conserva nombre e identidad. Pasa en ambas revisiones.
- Prueba GitHub Actions original [run #39261617747](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39261617747) con 2/2 jobs exitosos; artefactos de logs + SHA sin subir paquetes fuentes; antes/after adicionales tienen `ULTRASEC_NEGATIVE_ALLOWED_RENAME=PASS` y `ULTRASEC_NEGATIVE_NOOP=PASS`.
- Fuente de descripción original: [GHSA-25gq-j9jx-43pg](https://github.com/go-gitea/gitea/security/advisories/GHSA-25gq-j9jx-43pg) y Gitea PR #38314. **Conclusión:** causa raíz técnica correlacionada con el mecanismo descrito y regresión original más control benigno. **No** afirmar revisión gold independiente ni derechos sobre los 155 módulos externos.

## 2. Bulgarisation: una misma función original, dos predicados de seguridad distintos

**Distribuciones oficiales** WordPress Plugin 3.0.14 (antes) y 3.0.15 (después), WordPress 6.6.2, WooCommerce 8.7.0, PHPUnit 9.6, HTTP del transportista interceptado. [Run original con invocaciones separadas #39260722064](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39260722064): los dos jobs completaron correctamente.

| Comprobación aislada | CNA/CVE de investigación | Versión 3.0.14 | Versión 3.0.15 |
| --- | --- | --- | --- |
| Administrador con nonce **inválido**, pero capacidad real | CVE-2024-2395 / CWE-352 | **RED:** 1 PHPUnit failure, transporte local interceptado | **GREEN:** 1 PHPUnit correcto, WP guard previo |
| Suscriptor con nonce **válido**, pero sin capacidad | CVE-2024-0683 / CWE-862 | **RED:** 1 PHPUnit failure, transporte local interceptado | **GREEN:** 1 PHPUnit correcto, WP guard previo |
| Administrador con nonce válido y capacidad | Negativo benigno compartido; no CVE | 1 PHPUnit correcto | 1 PHPUnit correcto |

Refs de fuente: [Wordfence CSRF](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/bulgarisation-for-woocommerce/), [Wordfence missing authorization](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/bulgarisation-for-woocommerce/bulgarisation-for-woocommerce-3014-missing-authorization), [NVD CVE-2024-2395](https://nvd.nist.gov/vuln/detail/CVE-2024-2395).

**Límite estricto:** distinguir nonce versus capacidad permite atribución de mecanismos, pero un único handler de plugin **no crea dos casos independientes** ni dos nuevas etiquetas GOLD; CVE-2024-0683 no se añade por ello a la cohorte gold. Otros handlers del plugin y protección HTTP de producción permanecen fuera del alcance del test.

Se reprodujo un defecto de la primera implementación del filtro PHPUnit: `No tests executed!` en [run #39260215599](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39260215599). Se corrigió el filtro sin anclar el nombre corto y con comprobación explícita de que corre 1 test por escenario; run #39260722064 verde.

## 3. Preparación de holdout no contaminado: puerta adicional

Código privado/offline de **metadatos sintéticos y reales bajo control del propietario**, nunca fuente: [future_holdout_exposure.py](../../tools/future_holdout_exposure.py). Recibe JSONL con campos `case_id,cve_id,project_fingerprint,mechanism_fingerprint,source_commit,fix_commit,source_sha256,fix_sha256` y reporta exclusivamente totales y errores genéricos, sin publicar IDs, CVE de entrada o código.

Contrato canónico de proyecto v1: SHA-256 de `ultrasec-project-url-sha256-v1|` concatenado con host y ruta canónicos en minúsculas; se aceptan URLs públicas de `github.com/owner/repo` (incluye alias opcional `.git`) y `wordpress.org/plugins/slug`. Aplicar este esquema consistentemente **antes** de construir metadatos privados. El filtro excluye ocho CVE ya investigados, ocho proyectos públicos/expuestos (incluye dependencia Couchbase) y bloquea alias conocidos, repetición de pares de commits o contenidos, y reutilizaciones de mecanismo/proyecto que requieren agrupación. Las [pruebas sintéticas](../../tests/test_future_holdout_exposure.py) no contienen corpus privado.

Comando local, no ejecutar en Actions con datos propietarios:

```bash
python3 ultrasec-v7/tools/future_holdout_exposure.py --private-metadata /ruta/privada/futuros_candidatos.jsonl
```

**No hay archivo privado aportado, ni split realmente asignado, ni prueba semántica de diversidad.** Incluso con `candidate_metadata_screen_pass=true`, los campos `independence_verified=false` y `holdout_assigned=false` permanecen; el inventario de exclusiones puede necesitar ampliarse conforme aparezcan nuevos casos públicos.

## 4. Congelación limitada de SAST para casos *futuros* y no vistos

- Regla pública [future-unseen-python-cwe94.yml](../rules/future-unseen-python-cwe94.yml): dos patrones Semgrep Python `exec($EXPR)` y `eval($EXPR)`, sólo CWE-94. No probar ninguna CVE actualmente conocida con estas reglas como evaluación ciega.
- [Manifiesto](FUTURE_UNSEEN_SAST_BYTE_FREEZE_PLAN.json) fija Semgrep OSS `1.180.0`, SHA-256 de los bytes del YAML `6f3d784e3fa683b25336899fb5424b9f22ba34712147b7163714b25e9af65f00`, ocho CVE excluidos y `holdout_status=UNASSIGNED`.
- [sast_ruleset_freeze.py](../../tools/sast_ruleset_freeze.py) rechaza alias remotos mutables como `p/security-audit`, cambios SHA, symlinks, traversal, nuevas admisiones GOLD y afirmaciones de benchmark, guardando opcionalmente recibos privados 0600 no sobrescribibles.
- Digest del lock verificable `1c4ea1fdfcf1955e28adf758e8c08421ab8cd279cfa058a378cb0bef84ab2eb3`. [CI #39263262972](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39263262972): reglas originales comprobadas y 2/2 detecciones en **fixture sintético**; no es un benchmark.
- La regla Moonlight local anterior se diseñó tras conocer el parche: mantenerla como **RESEARCH_POSTHOC_ONLY**, nunca incluirla en el holdout ciego de Moonlight.
- Queda pendiente congelar paquetes reales de CodeQL y restantes reglas Semgrep según lenguajes/CWE; Slither sólo donde haya Solidity/Vyper. Se necesita un testimonio temporal externo que demuestre que los bytes congelados precedían al acceso al holdout, además del Git SHA correspondiente. Sin holdout independiente no se computan TP/FP/TN/FN, precisión, recall ni F1.

## 5. Bloqueos y decisión

`GOLD=0`, `NOT_CERTIFIED`, `HOLDOUT_PRIVATE=NOT_VERIFIED`, `BLIND_BENCHMARK=NOT_RUN`, `RIGHTS_NOT_VERIFIED`. Los 63 CVE son candidatos de investigación, no admitidos. La doble revisión humana permanece **APLAZADA**; no se inventan firmas ni se exige para pruebas automatizadas.

PR #7 y #10 permanecen Draft, #10 apilado sobre #7. **No fusionar** aunque CI pública esté verde: origen, holdout, benchmark y distribución comercial del entregable siguen siendo gates materiales separados.
