# UltraSec V7 — segundo lote de descubrimiento CVE (NO ADMITIDO)

**Corte de auditoría:** 2026-10-17. **Origen:** ficheros JSON de `github/advisory-database`, obtenidos individualmente mediante el conector GitHub. **Estado:** metadatos no certificados, sin extracción de código fuente vulnerable.

## Qué contiene
- `cve_additional_63_NOT_ADMITTED.jsonl`: 63 CVE distintos; 63 referencias GHSA distintas, sin solapamiento con los 37 CVE del manifiesto externo previo (37 + 63 = 100 **identificadores candidatos**, no 100 casos admitidos).
- `cve_discovery_batch_01.jsonl` a `cve_discovery_batch_06.jsonl`: lotes originales de descubrimiento que sustentan el consolidado.
- Distribución de los nuevos 63: CWE-79=6, CWE-89=5, CWE-352=6, CWE-862=5, CWE-787=6, CWE-22=5, CWE-416=6, CWE-125=5, CWE-78=6, CWE-94=5, CWE-120=4, CWE-434=4.

## Procedencia y límites probatorios
Las 63 entradas son **GitHub Advisory Database UNREVIEWED**, no avisos revisados por GitHub. Cada una tiene un identificador CVE y un CWE listados en el JSON público de GHSA. El campo `nvd_url` sirve de puntero para contrastar con la fuente oficial; **no afirma que se haya cotejado individualmente el documento NVD o la asignación CWE**.

Solo **4/63** contienen enlaces a posibles commits en la lista de referencias del aviso. Son referencias **no verificadas**; no está probado que representen la corrección, su versión vulnerable, un commit padre apropiado ni pruebas ejecutables. Las otras **59/63** carecen por ahora de referencia de commit en esos avisos. No se han descargado ni ejecutado proyectos upstream.

En todos los registros: `fix_commit_verified=false`, `source_parent_commit=null`, `upstream_test_execution=NOT_RUN`, `historical_license=NOT_VERIFIED`, `commercial_rights=NOT_VERIFIED`, `gold_admission=NOT_ADMITTED`.

## Próximas puertas de validación (por CVE, sin promociones automáticas)
1. Contrastar el CVE, descripción y CWE en NVD/CVE.org y el aviso upstream; excluir rechazos, disputas, alias y clasificaciones incorrectas.
2. Resolver repo original y commit de corrección **SHA completo**. Comprobar padres del commit, ancestría, SHA-256 de blobs y diferencia causal; no usar ciegamente el primer padre de un merge.
3. Fijar versiones, dependencias, instrucciones de pruebas y contenedor/sandbox seguro; ejecutar el mismo caso sobre versión vulnerable y corregida y conservar hashes de logs. Una prueba incluida upstream no equivale a una prueba ejecutada.
4. Consultar archivos LICENSE/COPYRIGHT/NOTICE **en las revisiones históricas**, atribución, código tercero, obligaciones de licencias, permisos de redistribución y eventual necesidad de autorización comercial. Hasta entonces no afirmar derechos de reventa.
5. Excluir duplicados mecánicos, proyectos solapados, fuga entre conjuntos y variación léxica engañosa; establecer adjudicación independiente, holdout y pruebas SAST reales antes del gold.
6. `real_case_candidate_triage.py` **NO consume directamente este archivo**: requiere entradas MoreFixes/CVEfixes con SHA completos, source_dataset y campos de origen. No inventar esos campos ni forzar conversiones para obtener PASS.

**Certificación comercial:** NOT_CERTIFIED. **Casos admitidos de este lote:** 0. **Derechos verificados:** 0. **Pruebas upstream ejecutadas:** 0. **Autorización para fusionar PR #7:** ninguna.
