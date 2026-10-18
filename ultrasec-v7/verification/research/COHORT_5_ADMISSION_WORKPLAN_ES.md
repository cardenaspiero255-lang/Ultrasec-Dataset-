# UltraSec V7 — cohorte cerrada de 5 candidatos, NO gold

**Corte:** 2026-10-17. **Fuente de verdad:** [COHORT_5_PRE_ADMISSION_PUBLIC.json](COHORT_5_PRE_ADMISSION_PUBLIC.json).
**Estado irrevocable en el repositorio público:** `NOT_ADMITTED / NOT_CERTIFIED`; esta investigación no contiene código vulnerable, etiquetas privadas, muestras de entrenamiento ni holdout. Los cinco candidatos de sustitución **no se han añadido** a los 100 CVE históricos.

## Orden de cierre por evidencia, no por cantidad de CVE

| CVE / familia | Evidencia upstream comprobada | Paso que falta para prueba CVE | Derechos históricos | Decisión |
|---|---|---|---|---|
| [CVE-2026-58428 / CWE-434](https://github.com/go-gitea/gitea/pull/38314) | [RED/GREEN nativo Gitea](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39073712740): mismo test `TestRelease_Update` trasplantado al padre; vulnerabilidad permite renombrar extensión prohibida, parche la rechaza; Go 1.26.4; producción original en ambos lados | Verificar que la falla que identifica el test corresponde al mismo mecanismo CNA, conservar archivos, commits y hashes, revisión externa ciega | MIT histórico [LICENSE](https://github.com/go-gitea/gitea/blob/7fdfb8d642201b388014f29889ef28e35b8c1872/LICENSE); autorización **de uso comercial bajo condiciones**, atribución por archivo y contrato concreto NO adjudicados | **Primer caso para revisión independiente** |
| [CVE-2024-2395 / CWE-352](https://nvd.nist.gov/vuln/detail/CVE-2024-2395) | [Prueba AJAX WordPress/WooCommerce nativa](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39081399130): plugin oficial 3.0.14, 3 pruebas/17 aserciones con dos fallos esperados; plugin 3.0.15, 3 pruebas/19 aserciones PASS; administrador con nonce falsificado y suscriptor sin permiso quedan bloqueados solo después; administrador con nonce válido conserva acceso a transportista interceptado | Pendiente atribuir separadamente CWE-352 frente a CWE-862 y alias CVE-2024-0683, ampliar rutas y revisar aviso PHP para nonce ausente | GPLv3+ histórica y dependencia MIT acreditadas como textos; derechos comerciales siguen NOT_VERIFIED | **RED_GREEN_REPRODUCED, WP AJAX real, HTTP remoto interceptado** |
| [CVE-2025-69015 / CWE-862](https://github.com/Automattic/crowdsignal-forms/pull/302) | [WordPress REST RED/GREEN](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39078935591): Autor pasa 4 checks POST/PUT NPS y Feedback en 1.7.2 (4 fallos esperados); 1.8.0 elimina esas rutas, 4/4 PASS | Vinculación exacta al CVE para la función del advisory y revisión ciega, no se efectuó escritura en backend | GPLv2 histórica de LICENSE.TXT; reventa de snippets sujeta a cumplimiento y sin dictamen | **RED_GREEN_REPRODUCED, REST permission scope** |
| [CVE-2023-42799 / CWE-120](https://github.com/moonlight-stream/moonlight-common-c/commit/02b7742f4d19631024bd766bd2bb76715780004e) | [ASan nativo RED/GREEN](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39076329630): función estática original extraída en cada commit, antes detecta stack-buffer-overflow y después copia acotada | El test fue **aislado** con shim mínimo de plataforma, no equivale al build de Moonlight ni a explotación completa; verificar mecanismo CVE, derechos y adjudicación independiente | GPL-3.0 en [LICENSE.txt](https://github.com/moonlight-stream/moonlight-common-c/blob/116267a24569ec610f4c9efa1048541022981040/LICENSE.txt); comercialización condicionada, sin clearance | **Segundo caso con evidencia causal técnica para revisión** |
| [CVE-2024-48645 / CWE-862](https://github.com/arm32x/command-block-ide/commit/42e09840168d9c2fe2ee07f4472d296000b2a416) | [Java RED/GREEN](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39078876423): prefijo original del receptor APPLY_FUNCTION compilado en javac 11, usuario no privilegiado continúa antes y se detiene después; privilegiado continúa siempre | No se ejecutó Minecraft/Fabric ni un paquete real; revisión independiente | LGPL-2.1 histórica, sin aprobación comercial | **RED_GREEN_REPRODUCED, prefijo aislado** |

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


## Actualización: segundo RED/GREEN reproducible

El 17-10-2026, el [run Moonlight](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39076329630) comprobó los SHAs fuente originales, compiló la función RTSP extraída sin modificar usando GCC con ASan/UBSan y ejecutó idéntico estímulo aislado. En el padre `116267a24569ec610f4c9efa1048541022981040` la prueba detectó `AddressSanitizer: stack-buffer-overflow` (RED esperado); en el fix `02b7742f4d19631024bd766bd2bb76715780004e`, `PARSE=1 DEST_LENGTH=15` con exit 0 (GREEN). Los dos jobs terminaron correctamente porque validan de forma explícita el resultado esperado, NO porque el código vulnerable pase una prueba.
**Límites:** el harness usa una sustitución controlada de `PltSafeStrcpy`, no ejecuta todo el programa Moonlight ni ha verificado licencias de cada fragmento. Es evidencia técnica reproducible para **solicitar** revisión independiente, no gold. Recuento inicial: dos RED/GREEN (Gitea y Moonlight). Actualización: cuatro (sumadas Crowdsignal y Command Block IDE); gold sigue cero.

## Validación CSRF nativa adicional — 17-10-2026

La [suite original de tres escenarios](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39081399130) fue ejecutada con WordPress 6.6.2, WooCommerce 8.7.0, PHPUnit 9.6 y ambos ZIP oficiales. Antes: `Tests: 3, Assertions: 17, Failures: 2` (nonce falsificado y suscriptor con nonce válido alcanzan el transporte interceptado); después: `OK (3 tests, 19 assertions)`, las dos solicitudes no autorizadas se bloquean antes del transporte y el administrador con nonce válido sigue funcionando con transporte simulado. Todos los requests HTTP fueron interceptados antes de enviarse, sin credenciales de proveedores. Esta evidencia es técnicamente válida para la ruta evaluada, pero no asigna automáticamente CWE/CVE independientes ni acredita venta comercial.

**Estado corregido:** 5/5 contrastes RED/GREEN técnicos, 0/5 entradas gold, 0/2 revisores externos y 0/5 derechos comerciales dictaminados. La CI de este informe no implica certificación.
