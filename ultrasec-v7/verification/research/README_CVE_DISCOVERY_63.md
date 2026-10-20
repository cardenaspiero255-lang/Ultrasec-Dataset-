# UltraSec V7 — segundo lote de descubrimiento CVE (NO ADMITIDO)

**Corte de auditoría:** 2026-10-17. **Origen:** ficheros JSON de `github/advisory-database`, obtenidos individualmente mediante el conector GitHub. **Estado:** metadatos no certificados, sin extracción de código fuente vulnerable.

## Qué contiene
- `CVE_CANDIDATES_63_PUBLIC_METADATA.md`: tabla Markdown de 63 CVE distintos y sus referencias GHSA; sin solapamiento con los 37 CVE del inventario local anterior (37 + 63 = 100 **identificadores candidatos**, no 100 casos admitidos).
- La procedencia de cada fila figura en sus enlaces públicos a GHSA y NVD. Los JSONL intermedios están excluidos del HEAD por la política de activos públicos del repositorio.
- Distribución de los nuevos 63: CWE-79=6, CWE-89=5, CWE-352=6, CWE-862=5, CWE-787=6, CWE-22=5, CWE-416=6, CWE-125=5, CWE-78=6, CWE-94=5, CWE-120=4, CWE-434=4.

## Procedencia y límites probatorios
Las 63 entradas son **GitHub Advisory Database UNREVIEWED**, no avisos revisados por GitHub. Cada una tiene un identificador CVE y un CWE listados en el JSON público de GHSA. El campo `nvd_url` sirve de puntero para contrastar con la fuente oficial; **no afirma que se haya cotejado individualmente el documento NVD o la asignación CWE**.

Solo **4/63** contienen enlaces a posibles commits en la lista de referencias del aviso. Se comprobó la existencia de una referencia GitHub por cada uno (OpenNMS, MISP/cti-transmute, GladysAssistant/Gladys y Leptonica), pero NO se verificó su causalidad, licencia, versión vulnerable ni ejecución de pruebas. Las otras **59/63** carecen por ahora de referencia de commit en esos avisos. No se han descargado ni ejecutado proyectos upstream.

Para las 63 filas: **0 commits acreditados como fixes**, **0 pruebas upstream**, **0 derechos comerciales**, **0 admisiones al gold**. Los JSONL de descubrimiento se mantienen fuera de la rama por la restricción de archivos binarios/privados.

## Próximas puertas de validación (por CVE, sin promociones automáticas)
1. Contrastar el CVE, descripción y CWE en NVD/CVE.org y el aviso upstream; excluir rechazos, disputas, alias y clasificaciones incorrectas.
2. Resolver repo original y commit de corrección **SHA completo**. Comprobar padres del commit, ancestría, SHA-256 de blobs y diferencia causal; no usar ciegamente el primer padre de un merge.
3. Fijar versiones, dependencias, instrucciones de pruebas y contenedor/sandbox seguro; ejecutar el mismo caso sobre versión vulnerable y corregida y conservar hashes de logs. Una prueba incluida upstream no equivale a una prueba ejecutada.
4. Consultar archivos LICENSE/COPYRIGHT/NOTICE **en las revisiones históricas**, atribución, código tercero, obligaciones de licencias, permisos de redistribución y eventual necesidad de autorización comercial. Hasta entonces no afirmar derechos de reventa.
5. Excluir duplicados mecánicos, proyectos solapados, fuga entre conjuntos y variación léxica engañosa; establecer adjudicación independiente, holdout y pruebas SAST reales antes del gold.
6. `real_case_candidate_triage.py` **NO consume directamente este archivo**: requiere entradas MoreFixes/CVEfixes con SHA completos, source_dataset y campos de origen. No inventar esos campos ni forzar conversiones para obtener PASS.

**Certificación comercial:** NOT_CERTIFIED. **Casos admitidos de este lote:** 0. **Derechos verificados:** 0. **Pruebas upstream ejecutadas:** 0. **Autorización para fusionar PR #7:** ninguna.
