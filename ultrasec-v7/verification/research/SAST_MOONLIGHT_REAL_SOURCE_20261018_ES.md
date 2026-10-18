# UltraSec V7 — Semgrep OSS real-source shadow scan (NO benchmark)

Corte: 18-10-2026. Ejecución GitHub Actions [39167000254](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39167000254). Los dos jobs terminaron en `success`.

| Fuente original de Moonlight Common C | Resultado del escáner `p/security-audit` | Dictamen |
| --- | ---: | --- |
| Antes: `116267a24569ec610f4c9efa1048541022981040` | **2 hallazgos** | Ejecución Semgrep real completada |
| Después: `02b7742f4d19631024bd766bd2bb76715780004e` | **1 hallazgo** | Ejecución Semgrep real completada |

- Comando: Semgrep OSS CLI fijada a `semgrep==1.180.0`, ejecutada contra el archivo original `src/RtspConnection.c` de cada revisión Git fijada, con reglas públicas `p/security-audit`.
- Captura: SHA del archivo origen, Git blob, versión del CLI, SHA-256 del JSON bruto del escáner y resumen de reglas/hallazgos. Artefactos públicos: [before](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39167000254/artifacts/12151495849) y [after](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39167000254/artifacts/12151017546). Los artefactos **no** incluyen código original ni el reporte crudo para evitar redistribución accidental.
- El ruleset `p/security-audit` del registro remoto **no está congelado por SHA**; aun fijando el CLI y el código, repetir la ejecución más tarde puede cambiar el número de hallazgos. Esto impide llamarla completamente reproducible.
- La disminución de **2 a 1** es un recuento bruto; **no prueba** que el escáner detectó correctamente CVE-2023-42799, que el hallazgo restante sea falso positivo o que se alcanzó cualquier precisión/recall/F1.
- El oráculo ASan RED/GREEN anterior es independiente de este escáner, pero el dataset aún carece de un gold adjudicado con negativos compatibles por CWE y holdout de entrenamiento aislado.

**Estado:** `TOOL_EXECUTED=YES`, `INDEPENDENT_GOLD=NO`, `RULESET_IMMUTABLE=NO`, `TP_FP_FN_TN=NOT_COMPUTED`, `PRIVATE_SAST_BENCHMARK=NOT_RUN`, `COMMERCIAL_RIGHTS=NOT_VERIFIED`, `CERTIFICATION=NOT_CERTIFIED`.

Próximo avance medible: congelar ruleset o registrar su digest verificable, definir reglas y CWE aplicables antes de inspeccionar los resultados, construir positivos/negativos de referencia sin contaminar splits, obtener salida SARIF/JSON custodiada y sólo entonces puntuar TP/FP/FN/TN. Slither no aplica a un archivo C.
