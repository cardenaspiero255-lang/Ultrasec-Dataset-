# UltraSec V7 — recuperación forense de TRAIN histórico original (19-10-2026)

**Resultado: recuperados dos exportadores históricos privados y verificadas sus relaciones originales. No se ha demostrado su consumo efectivo por el detector/modelo actual.** `GOLD=0`, `BLIND_BENCHMARK=NOT_RUN`, `TRAIN_MODEL_CONSUMPTION=NOT_VERIFIED`, `COMMERCIAL_RIGHTS=NOT_VERIFIED`, `NOT_CERTIFIED`.

## Procedencia de las fuentes recuperadas (owner Library; no incluidas en el PR)

Se recuperaron mediante el almacenamiento privado del propietario **sin incluir código, pares, claves o labels en GitHub**:

| Paquete original (solo nombre, no distribución pública) | SHA-256 del ZIP comprobado |
| --- | --- |
| `UltraSec_V7_3_5_Lenguajes_PRESERVADOS_PRIVADO.zip` | `27e09c0cf484335f7a1d00ef1d05e534db43f1e438b282d51758e034f868f69b` |
| `UltraSec_V7_9_Entrenamiento_Enterprise_PILOTO_PRIVADO.zip` | `6e7689b760c1afd534d1fec8daf2301bc448616253aecbb967819d8d18effcc0` |
| `UltraSec_Enterprise_V4_OWNER_MASTER.zip` | `ce8d0998d69adba64d9a7d3723f76bca4988df8082b260cd7cbd7507b436056d` |

Los recibos originales completos y los scripts de inspección permanecen en la sesión **privada** del propietario; aquí se documentan exclusivamente cifras y conclusiones agregadas.

## V7.3 → V7.9: auditoría directa de los bytes originales

- Archivo V7.3: **10.022/10.022** entradas manifestadas verificadas por SHA-256, incluidos **10.000 archivos fuente** de 5.000 pares. Archivo V7.9: **61/61** entradas verificadas por SHA-256.
- Se cotejaron los **5.000 pares V7.9 con sus dos fuentes originales V7.3**: código vulnerable y corregido coinciden byte por byte con sus hashes originales **si se respeta la orientación variable de las variantes A/B** indicada en el fichero privado original `owner/reserved/truth_private.jsonl`. La hipótesis `A=vulnerable` es FALSA para 2.511 pares; asumirla produce falsos fallos de identidad. La comparación canónica respaldada en el truth original da **5.000/5.000 pares correctos**.
- Los **3.000/3.000** pares de `datasets/legacy_v73_train_3000_pairs_unverified.jsonl` coinciden con la partición histórica `train` del corpus de 5.000; **600 pares por lenguaje** (C, Go, Java, Rust, Solidity).
- Los **6.000/6.000** registros de `detection_train_6000_unverified.jsonl` proceden exclusivamente de esos mismos 3.000 pares: una muestra vulnerable + una mitigada por par. Los **3.000/3.000** registros de `sft_patch_train_3000_unverified.jsonl` mantienen el vulnerable como entrada y el corregido como salida del mismo par, sin diversidad nueva. No contar 9.000 tareas derivadas como 9.000 defectos independientes.
- Prototipo V7.9: **60/60** registros TRAIN y **40 reservados** (20 dev, 20 test) cotejados con el truth privado de 100 muestras. No aporta oráculos de CVE reales.
- Los **2.000 pares históricos no TRAIN** (1.250 holdout-family, 375 validación, 375 holdout-instance) permanecen excluidos del TRAIN V7.9 original. Como son anteriores y sintéticos, NO representan un holdout futuro nunca visto.
- La identidad se verificó con ZIPs originales sin ejecutar código vulnerable, sin extraer fuentes, sin publicar filas, y sin modificar los archivos privados. La integridad relativa a un manifiesto local NO acredita que un modelo concreto haya entrenado con estos datos.

## V4/V3: auditoría de un millón y exportación etiquetada

- Lectura de flujo GZIP del archivo `owner/v3/data/ultrasec_v3_1m.jsonl.gz`: **1.000.000/1.000.000** filas; SHA-256 del JSONL descomprimido coincide exactamente con el manifiesto V4. TRAIN **750.016**, validación **124.992** y TEST histórico **124.992**.
- `owner/v3/data/BUYER_train_validation_labeled.jsonl.gz`: **875.008/875.008** filas y SHA-256 propio válidos; su **flujo completo de bytes descomprimidos coincide con el subconjunto ordenado TRAIN+validación del millón original**.
- Todos los registros conservan `independently_validated=false`; no hay derechos comerciales de código fuente acreditados. El manifiesto declara 500.000 pares sintéticos, no 500.000 vulnerabilidades reales distintas.
- Este corpus V4 **es independiente como archivo de exportación** del V7.9, pero NO se ha acreditado independencia causal/semántica, ni si fue utilizado para entrenar el detector actual. Cualquier holdout futuro deberá descartar sus contenidos/clones si la historia de entrenamiento lo requiere.

## Bloqueo de TRAIN de modelo que permanece abierto

**No se localizaron** en los ZIPs examinados la cadena completa de `training_runs.json`, registros de consumo de cada época/lote, artefactos de modelo entrenado (checkpoint) ni firmas/recibos externos de entrenamiento vinculados al detector actual. El piloto TF-IDF/regresión logística tiene scripts e informes A/B internos, **no una cadena de checkpoints verificable**. Los ZIP contienen **exportaciones legítimas de origen histórico**, no el historial completo de ejecución de un modelo. No debe introducirse una afirmación `TRAIN_COMPLETE=true`.

El validador `tools/training_lineage_gate.py` requiere una estructura distinta: registros TRAIN con identificadores de origen/commit y SHA, más todos los recibos auténticos de runs/checkpoints. Los archivos V4 y V7.9 tienen **esquemas propios de generadores sintéticos, sin orígenes CVE/commits externos originales**. No falsificar campos para pasarlos al validador de casos reales. Mantener ambos inventarios en **un registro histórico de exposición separado** y validar la cadena de consumo por modelo antes de declarar una partición final.

Los **107 CVE de investigación conocidos** (70 referencias públicas y 37 registros históricos privados, todos `NOT_ADMITTED`) son una **lista de exclusión adicional**. **No añadirlos a TRAIN ni a GOLD para superar los mínimos de 100.** Tampoco promover las filas sintéticas de V4/V7.9 a GOLD.

## Siguiente criterio de aceptación

1. Recuperar para el modelo/detector concreto: ID/digest de cada artefacto entrenado, código de entrenamiento y semilla, lista real de archivos consumidos, fechas de ejecuciones, logs firmados, parent checkpoints y modo exacto de ingestión; no basta tener ZIPs.
2. Consolidar manifiesto propietario de **todas** las exposiciones previas (V4/V3, V5, V7.3/V7.9, candidatos CVE investigados, sintéticos públicos), separando lo *exportado*, lo *probablemente visto* y lo *efectivamente consumido*. Conservar su trazabilidad, agrupación por familia y reglas para clones semánticos.
3. Solo después seleccionar nuevos originales nunca vistos, sellar TRAIN/TEST y excluir los 107 CVE y las demás exposiciones; cada positivo/negativo requiere oráculo upstream auténtico y causa independiente.
4. Evaluar con rulesets congelados y herramientas reales sobre TEST únicamente cuando estén confirmados todos los requisitos. Mantener cierre comercial BSL/Couchbase por archivo antes de vender bundles.

**Estado de cierre:** `HISTORIC_EXPORTS_BYTE_VERIFIED=true`, `ORIGINAL_TRAIN_SOURCE_PAIR_MAPPING_V73_V79_VERIFIED=true`, `V4_EXPORT_SPLIT_BYTE_VERIFIED=true`, `ACTUAL_MODEL_CONSUMPTION=NOT_VERIFIED`, `CURRENT_TRAIN_HISTORY_COMPLETE=false`, `FUTURE_HOLDOUT=UNASSIGNED`, `GOLD=0`, `NOT_CERTIFIED`. La revisión doble AppSec continúa APLAZADA por decisión del propietario.

No fusionar PR #7 ni PR #10 por este informe; la CI verde del código no reemplaza las puertas materiales.
