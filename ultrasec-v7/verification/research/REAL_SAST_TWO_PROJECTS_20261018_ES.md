# UltraSec V7 — escáner SAST real en dos proyectos originales (SIN benchmark gold)

Corte: 18 de octubre de 2026. Dos proyectos originales, archivos concretos y revisiones Git inmóviles. Resultados de ejecutables reales, **no** etiquetas de benchmark ciego.

| Proyecto y lenguaje | Origen vulnerable | Versión corregida | Semgrep/configuración | Resultado antes | Resultado después | Evaluación |
| --- | --- | --- | --- | ---: | ---: | --- |
| [Moonlight Common C](https://github.com/moonlight-stream/moonlight-common-c), C | `116267a24569ec610f4c9efa1048541022981040` | `02b7742f4d19631024bd766bd2bb76715780004e` | Semgrep OSS 1.180.0, `p/security-audit` | 2 | 1 | Reglas públicas no congeladas |
| [Moonlight Common C](https://github.com/moonlight-stream/moonlight-common-c), C | mismo par | mismo par | Semgrep OSS 1.180.0, regla específica local con contenido fijado por el propio commit | 1 | 0 | **Regla diseñada tras conocer el parche. Evaluación post-hoc, no ciega** |
| [GiveWP](https://github.com/impress-org/givewp), PHP | `3.18.0` `d056e04cbb1b43664b2b13c1df6fb7328cc0db11` | `3.19.0` `b24415fee1438d321407dee8739733092ac0b90a` | Semgrep OSS 1.180.0, `p/security-audit` | **0** | **0** | El escaneo termina sin alertas en el archivo concreto; **no confirma detección ni ausencia de XSS** |

GitHub Actions verificadas:
- [Moonlight, SHA del original + salida Semgrep + regla local](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39170767535) — 2 trabajos exitosos.
- [GiveWP, tags exactos + SHA de fuente + Semgrep OSS](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39176154772) — 2 trabajos exitosos.
- El escaneo PHP se limitó a `src/Framework/Migrations/Controllers/ManualMigration.php` y no examina todas las rutas de salida HTML ni un sitio WordPress completo. El escaneo C se limita a `src/RtspConnection.c`.

## Lo que NO se puede concluir

- **0 hallazgos** en GiveWP no son necesariamente **0 falsos negativos**: primero hay que comprobar qué reglas para PHP/CWE-79 se ejecutaron y si cubren flujo desde entrada a salida en ese contexto.
- **1→0** para una regla post-hoc en Moonlight no prueba rendimiento sobre CVE desconocidos. Nunca incluir ese par como *holdout ciego* de esa regla.
- **2→1** y **0→0** son conteos brutos sin gold por línea/CWE; no permiten obtener TP, FP, FN, TN, precisión, recall, F1 ni FPR.
- `p/security-audit` es referencia al registro y puede evolucionar; no hay digest congelado de todo el conjunto de reglas remotas, aunque se fijó la versión del CLI.
- El dato previo de 63 avisos GHSA se considera investigación. Ningún caso se declara `GOLD_ADMITTED`.

## Criterios del primer benchmark puntuable

1. Resolver procedencia de cada vulnerabilidad y línea original afectada, comparar en laboratorio el mismo oráculo sobre fuente base y fix, y registrar SHA de entradas, herramienta y logs.
2. Preinscribir herramienta/reglas/CWE/estrategia de triage **antes de consultar etiquetas reservadas**. No usar ni afinar esas reglas con el holdout.
3. Verificar separación por proyecto, commit, hash de contenido, firma de mecanismo y semántica, en particiones train/validation/test. Requerir negativos difíciles por CWE y controles de cambio benigno.
4. Ejecutar el escáner sobre código original en un entorno reproducible con reglas locales congeladas; registrar resultado completo original y conteos, sin publicar privados.
5. Solo con los pasos anteriores finalizados y evidencia independiente de las etiquetas, medir TP/FP/FN/TN por CWE; reportar fallos, no_rule, tool_failed y diferencias de cobertura.
6. Inventariar licencia por **archivo incluido** y modalidad de entrega del artefacto; no convertir licencias upstream en autorización automática del dataset.

**Estado:** `REAL_SCANNER_EXECUTED=YES`, `UPSTREAM_PROJECTS=2`, `INDEPENDENT_PRIVATE_GOLD=0`, `BLIND_BENCHMARK=NOT_RUN`, `COMMERCIAL_RIGHTS=NOT_VERIFIED`, `HUMAN_REVIEW=DEFERRED`, `CERTIFICATION=NOT_CERTIFIED`.
