# UltraSec Dataset V7 — auditoría de recibos originales y puertas materiales

**Corte:** 19 de octubre de 2026. Alcance: metadatos y artefactos **públicos** de investigación; no se recibió ni se publicó el corpus privado. El orden de trabajo fue (1) TDD/CI, (2) pruebas upstream, (3) holdout, (4) SAST, (5) derechos, (6) decisión de fusión.

**Resultado:** `NOT_CERTIFIED`, `GOLD=0`, `RIGHTS_NOT_VERIFIED`, `HOLDOUT_PRIVATE=NOT_VERIFIED`, `BLIND_SAST_BENCHMARK=NOT_RUN`. Revisión humana de dos personas **DEFERRED**, no simulada y no exigida durante esta fase técnica.

## 1. Integridad del validador — corregida con TDD

Se reprodujeron tres fallos por reutilizar dentro de train/validation pares `(source_commit,fix_commit)` y `(source_sha256,fix_sha256)` bajo distintos IDs. [CI RED #39256845262](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39256845262), commit `8e6f6ef804f4e8ec5a6c3811f84e73da33034628`. Corrección `a55c5d35b2088834af3bffc36035f9c8a73b71e5`: rechazar los dos pares repetidos en cualquier split, sin bloquear dos parches diferentes del mismo proyecto. [CI GREEN #39256954302](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39256954302): 396 pruebas correctas y cobertura informada del código público de referencia 97%, 7/7 gates.

**Limitación:** son pruebas sintéticas; no hay garantía de independencia semántica, commits verdaderos ni etiquetas gold.

## 2. Recuperación y análisis de artefactos originales

Se descargaron realmente **10 ZIP** públicos de Actions, correspondientes a cinco pares antes/después. Los 10 SHA-256 de los ZIP coinciden con el campo `digest` de GitHub Actions y la integridad ZIP se verificó. Dentro de los ZIP se compararon **16 checksums** de recibos con los bytes de archivos efectivamente presentes; los 16 coincidieron. Otros hashes sólo referencian fuentes originales que **no** están incluidas en esos ZIP, por lo que no se han validado sus bytes desde estos recibos aislados. La evidencia original queda en GitHub Actions, no en un dataset gold.

| Caso | Artefacto RED / GREEN | Resultado del experimento original | Alcance y limitación |
| --- | --- | --- | --- |
| [Gitea CVE-2026-58428](https://github.com/advisories/GHSA-25gq-j9jx-43pg) | [run 39208771097](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39208771097), ZIP 12167160495 / 12166866656 | `TestRelease_Update` falla en `7fdfb8d642201b388014f29889ef28e35b8c1872` y pasa en `e4ef995f2a162e3aca3f3a0b536afae067975d71`. Test original del fix trasplantado al padre. | Coincide en mecanismo general con advisory del bypass de extensiones, pero no acredita nuevos negativos independientes ni autorización comercial |
| Crowdsignal CVE-2025-69015 | [run 39208770963](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39208770963), ZIP 12166961369 / 12166796136 | REST original en WP: 4 fallos esperados en 1.7.2 y 4 pruebas/12 aserciones correctas en 1.8.0. Mismo test SHA en ambos archivos de evidencia. | La suite upstream *completa* previa informa `FULL_SUITE=EXPECTED_LEGACY_ERROR_NOT_PASS`; no afirmar full suite verde en 1.7.2. Vinculación exacta a la función del CNA aún provisional |
| Bulgarisation CVE-2024-2395 | [run 39208771050](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39208771050), ZIP 12166424638 / 12166319918 | ZIP oficiales 3.0.14/3.0.15, PHPUnit 3 pruebas con 2 fallos esperados antes y 3 pruebas/19 aserciones correctas después; HTTP de transportista interceptado | Advertencias de tablas WooCommerce faltantes, no bloqueantes para prueba enfocada. Separar CSRF de falta de autorización (CVE-2024-0683); otros handlers no revisados |
| Moonlight CVE-2023-42799 | [run 39208770953](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39208770953), ZIP 12165664906 / 12166771037 | Función original extraída de commits `116267a24569ec610f4c9efa1048541022981040` y `02b7742f4d19631024bd766bd2bb76715780004e`: exit 1 bajo ASan antes; exit 0 después | Ensayo con shim y parser aislado, no build integral upstream |
| CommandBlock IDE CVE-2024-48645 | [run 39208771011](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39208771011), ZIP 12166906311 / 12166956151 | Prefijo original receptor Java: usuario no autorizado alcanza escritura antes, no después; privilegiado conserva acceso | No se ejecutó Minecraft/Fabric, sólo prefijo aislado |

Evidencia de fuente adicional **sin prueba causal nativa RED/GREEN admitida**: [GiveWP run #39208771101](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39208771101) compara PHP original y confirma sanitización estática; [3DViewer run #39208771068](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39208771068) comprueba dos ZIP oficiales, hashes y cambio de archivo PHP; no hay prueba WordPress de explotación/corrección. Ninguno es GOLD.

## 3. Holdout e independencia

Los cinco candidatos del `COHORT_5_PRE_ADMISSION_PUBLIC.json` siguen `NOT_ADMITTED`, `split=UNASSIGNED`, `training_import=NO`. El inventario grande contiene **63 candidatos de investigación, no 63 positivos admitidos**. Ningún split privado fue entregado para ejecutar `private_holdout_preflight.py` contra metadatos reales; no se garantiza separación entre familias, code clones, proyectos ni contaminación léxica. Los 5.000 pares V7.3 mantienen `SYNTHETIC_UNCERTIFIED`. La corrección de duplicados no crea GOLD ni rompe por sí sola la ausencia de holdout independiente.

## 4. SAST, distinción de ámbitos

La [ejecución real de Semgrep OSS y CodeQL #39256954344](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39256954344) pasó sobre los verificadores públicos Python, **no** sobre el corpus propietario. Las corridas originales Moonlight y GiveWP de Semgrep y sus límites están en [REAL_SAST_TWO_PROJECTS_20261018_ES.md](REAL_SAST_TWO_PROJECTS_20261018_ES.md): Moonlight `p/security-audit` 2→1 y regla local post-hoc 1→0; GiveWP 0→0 en un archivo PHP. Resultados **de investigación**, no benchmark ciego. Falta congelación previa comprobable del conjunto completo de reglas, holdout independiente, etiquetas por CWE, negativos y matriz TP/FP/FN/TN. No publicar precisión/recall/F1 como métricas acreditadas. Slither no aplica a C/Go/PHP/Python; sólo evaluar donde exista Solidity compatible.

## 5. Derechos comerciales

El inventario de Gitea observa 16 excepciones originales: 5 MPL-2.0, 6 BSD-2-Clause, 1 BSD-3-Clause, 2 MIT, 1 referencia BSL/Couchbase por archivo y 1 reclamo de dominio público no-SPDX. La licencia raíz MIT de Gitea y los SHA de archivos LICENSE **no** prueban cadena completa de derechos ni permiso incondicional de redistribuir una compilación de terceros. `github.com/couchbase/goutils@v0.3.0` muestra cabeceras BSL y un `Licensed Work` identificado como *Couchbase Server Version 8.0*: interpretación jurídica pendiente. [Decisión de alcance](GITEA_AUTONOMOUS_BUNDLE_AND_COUCHBASE_BSL_DECISION_20261019_ES.md): conservar overlay original mínimo de nueve rutas para **reconstrucción interna efímera**, no distribuir bundle autónomo de Go con 155 dependencias sin revisión. Derechos por archivo, NOTICE, modalidad comercial y condiciones contractuales siguen sin acreditar.

## 6. CI y decisión

Para el código `a55c5d35b2088834af3bffc36035f9c8a73b71e5` se observaron **14/14 workflows correctos** (incluidos Go, WordPress, trazabilidad, Semgrep y CodeQL públicos). Este documento se añade después en otro commit: los checks deben revalidarse para el nuevo HEAD y no heredan validez temporal por semejanza. PR #7 sigue Draft sobre main; PR #10 sigue Draft apilado sobre #7. **NO FUSIONAR** mientras falten las puertas de independencia, benchmark y derechos pertinentes. La revisión humana aplazada no se presenta como realizada.

### Prioridad material siguiente

1. Conservar y reprocesar los recibos originales; preparar controles negativos auténticos y separar las rutas/mecanismos Bulgarisation.
2. Obtener material original adicional para GiveWP/3DViewer con oráculos reproducibles antes de reclasificar; mantener los demás 58 candidatos sin elevar.
3. Obtener metadatos privados minimizados y ejecutar la puerta de holdout **fuera de GitHub**, con congelación externa de reglas SAST antes de evaluar.
4. Definir entregable comercial exacto, resolver BSL/Couchbase y obligaciones por archivo/NOTICE; sin redistribuir código ajeno mientras falte clearance.
5. Auditoría final de PR y CI por SHA; fusión en secuencia sólo cuando corresponda. Automatización de UltraSec **mantener pausada**.
