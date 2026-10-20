# Puerta local de separación TRAIN frente a HOLDOUT — UltraSec V7

**Enfoque:** comparar en local manifiestos privados de metadatos sin publicar ejemplos, hashes privados, ID o código en GitHub. Herramienta: ultrasec-v7/tools/private_training_disjointness.py.

## Datos de entrada

Dos archivos JSONL **distintos**, fuera del repositorio público y almacenados por el propietario:
- TRAIN: casos de entrenamiento real, con split=train.
- HOLDOUT: candidatos futuros para evaluación, con split=test. No debe incluir Gladys, MISP, Leptonica, OpenNMS, Gitea, Bulgarisation, Crowdsignal, Moonlight, GiveWP, CommandBlock IDE u otros proyectos ya examinados, ni alias.

Campos exactos por fila: case_id, project_url, project_fingerprint, cve_id, cwe_id, mechanism_fingerprint, source_commit, fix_commit, source_sha256, fix_sha256, oracle_type, oracle_run_sha256, split, vulnerable.

Los fingerprint de proyecto se calculan desde URL pública normalizada con el contrato ultrasec-project-url-sha256-v1. Las huellas de mecanismo y código **deben derivarse de originales auténticos** y de un protocolo separado (la estructura JSONL no los autentica).

## Comando del propietario — no ejecutar en Actions con datos reales

    python3 ultrasec-v7/tools/private_training_disjointness.py --train /ruta/privada/train_metadata.jsonl --holdout /ruta/privada/holdout_metadata.jsonl --prior-research /ruta/privada/candidatos_historicos_37_NO_ADMITIDOS.jsonl --private-receipt /ruta/privada/disjointness-receipt.json

Umbrales predeterminados: >=100 registros válidos de entrenamiento, >=100 test, >=12 CWE test con **positivos y negativos por CWE**, distintos proyectos y mecanismos en TEST. Rechaza:
- Proyectos iguales aunque el URL use alias de mayúsculas, .git o barra final; exige que el hash declarado corresponda al URL canónico.
- CVE, mecanismo, cualquier commit antes/después o SHA-256 antes/después compartido con entrenamiento.
- CVE y proyectos conocidos de la investigación pública.
- Dos ejemplos de TEST del mismo proyecto/mecanismo, particiones falsas, metadatos con formato inválido o ausencia de prueba/oráculo.
- Entradas cero, mismo archivo en TRAIN/TEST, metadatos dentro de checkout público; destino de recibo ya existente.

Recibo opcional es un archivo exclusivo con permiso 0600, contiene resúmenes y SHA-256 de ambos manifiestos para posterior custodia. El CLI **no imprime** IDs, URLs, hashes ni contenido de casos, sólo totales y códigos de error.

## Evidencia y limitaciones

- Pasar metadata_separation_pass=true es *sólo* una exclusión sintáctica/exacta de las claves suministradas.
- El programa NO contrasta SHAs declarados contra árboles Git originales, no garantiza que las firmas de mecanismos representen la misma causa raíz, no detecta clones semánticos de distinto lenguaje ni verifica el origen del entrenamiento.
- Cualquier pareja vulnerable/corregida conocida por quien diseñó el detector queda fuera de un benchmark ciego, salvo que haya un protocolo previo riguroso de separación de roles, fecha de preinscripción y ausencia de tuning.
- No calcular precisión, recall, F1 ni TP/FP/TN/FN sin resultados SAST originales en un conjunto independiente con reglas versionadas **y prueba temporal de congelación**.
- Estado actual: ningún manifiesto privado del propietario ha sido inspeccionado, HOLDOUT_PRIVATE=NOT_VERIFIED, GOLD=0, NOT_CERTIFIED. Dos revisores humanos permanecen aplazados por decisión del propietario.


## Actualización del 19-10-2026: lista privada histórica obligatoria

Se encontró y verificó **fuera de GitHub**, en los archivos privados del propietario, un inventario de **37 candidatos históricos `NOT_ADMITTED`**, de **37 CVE distintos en 33 repositorios**, ninguno con derechos comerciales ni oráculos de causa raíz acreditados. Los 37 CVE **no coinciden** con los 63 CVE públicos de investigación. Por tanto hay **100 referencias distintas conocidas que deben quedar fuera** de cualquier holdout futuro: esto NO es un corpus GOLD de 100 casos.

El CLI ahora **exige `--prior-research`** para leer un tercer JSONL en la máquina del propietario. No subirlo al repositorio ni adjuntarlo a Actions. Los campos públicos usados para excluir son `schema=ultrasec.public-cve-candidate.v1`, `admission_status=NOT_ADMITTED`, `commercial_rights=NOT_VERIFIED`, `cve_id`, `repo_url` y `fix_commit` (SHA completo). Acepta campos adicionales; nunca exporta los IDs ni URLs. El origen no debe estar en el checkout y sus bytes SHA-256 se guardan sólo en el recibo local de permisos `0600`.

La puerta rechaza colisiones por CVE y por proyecto normalizado contra el inventario histórico; falla si este tiene menos de 37 filas válidas, CVE duplicados, URLs ilegítimas, estados de admisión falsos o está ausente. El resultado contiene recuentos agregados y conserva `causal_independence_certified=false`, `blind_benchmark_ready=false`, `GOLD=0`. Una coincidencia de hashes no sustituye análisis semántico, y el inventario de 37 NO equivale a todos los datos de entrenamiento que pudieran existir. El propietario debe aportar además los metadatos completos de TRAIN para una verdadera separación.

**Seguridad:** no se volcó el contenido del JSONL privado al PR; sólo se añadieron pruebas con datos sintéticos. 
