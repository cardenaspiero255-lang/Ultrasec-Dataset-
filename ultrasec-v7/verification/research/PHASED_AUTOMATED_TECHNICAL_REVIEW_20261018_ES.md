# UltraSec V7 — fase automatizada sin exigencia de dos revisores humanos

**Decisión del propietario (2026-10-18):** aplazar la revisión de dos especialistas AppSec. No solicitarla ni bloquear el trabajo técnico actual por su ausencia. No eliminar pruebas existentes ni fingir firmas o dictámenes. La revisión externa queda como **fase posterior opcional para una evaluación independiente**, no como requisito para ejecutar validaciones internas.

## Alcance de esta fase

1. Conservar los cinco casos de investigación originales, sus SHA o hashes de versiones, y referencias a ejecuciones RED/GREEN. No convertir referencias públicas en verdad gold.
2. Ejecutar pruebas upstream acotadas para cada caso y almacenar logs/versiones/hash/salida; identificar qué pruebas usan test original, trasplante controlado o harness parcial.
3. Verificar automáticamente integridad y duplicados, procedencia de commits, URL canónica de GitHub Actions (repositorio propio e identificador numérico), clasificación de fallos, y aislamiento del holdout y del corpus de entrenamiento.
4. Preparar evaluación SAST reproducible por CWE y versión de herramienta solo donde exista oráculo válido; no contar *no_rule*, *not_applicable*, fallo de build o ausencia de etiqueta como negativo real.
5. Inventariar licencias por archivo y obligaciones conocidas, manteniendo `COMMERCIAL_RIGHTS=NOT_VERIFIED` hasta comprobar la posibilidad real de redistribuir el entregable. Una auditoría jurídica externa, si fuera necesaria para una oferta concreta, es independiente de esta fase.
6. Mantener controles de seguridad, CI, análisis de regresiones y documentación verificable antes de cualquier fusión.

## Semántica invariable

| Campo | Significado autorizado |
| --- | --- |
| `automated_phase=METADATA_CONSISTENCY_ONLY` | El verificador público revisa estructura y consistencia local; **no inspecciona los logs de terceros** |
| `human_review_phase=DEFERRED` | Dos revisores externos NO son un bloqueo para la investigación técnica actual |
| `native_red_green_count=5` | Cinco declaraciones de reproducción en el registro público; referenciadas, **no acreditadas por este validador** |
| `gold_count=0` | Ningún caso admitido como gold independiente |
| `certification=NOT_CERTIFIED` | Sin certificación externa, comercial, ISO, NIST ni de terceros |
| `commercial_rights=NOT_VERIFIED` | Sin dictamen concluyente de permisos de redistribución por entregable |
| `split=UNASSIGNED`, `training_import=NO` | Mantener separación frente al dataset privado y holdout |

## Evidencia existente

La cohorte de cinco candidatos declara RED/GREEN para Gitea, Bulgarisation (WordPress AJAX), Crowdsignal (REST), Moonlight (ASan sobre función aislada) y Command Block IDE (prefijo Java aislado). Los cinco enlaces de GitHub Actions están en `COHORT_5_PRE_ADMISSION_PUBLIC.json`. Su calidad es distinta: el control automatizado no debe equiparar un harness aislado con una ejecución upstream integral.

Los 63 CVE adicionales son **candidatos de descubrimiento**: 7/63 commits inspeccionados en el informe parcial, cero admisiones gold. Los 37 candidatos previos y estos 63 no equivalen a cien pares validados.

## Comandos reproducibles

```bash
python3 -m unittest discover -s ultrasec-v7/tests -p test_verify_candidate_cohort.py -v
python3 -m unittest discover -s ultrasec-v7/tests -p test_prepare_blind_cohort.py -v
python3 ultrasec-v7/tools/verify_candidate_cohort.py ultrasec-v7/verification/research/COHORT_5_PRE_ADMISSION_PUBLIC.json
```

**Criterio de terminación de esta fase:** tests locales y CI relevantes limpios, informe por caso sin fallos ocultos y sin falsos reclamos de gold, procedencia o licencias. Esta fase puede cerrar aunque dos expertos humanos no participen; **no habilita por sí sola un sello de certificación independiente ni derechos de venta**.
