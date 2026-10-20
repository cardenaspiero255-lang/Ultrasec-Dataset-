# UltraSec V7 — diez licencias de orígenes históricos (NO aprobación comercial)

**Corte:** 2026-10-18. Separamos **inventario de textos de licencia** de **evaluación de conformidad de una modalidad específica de entrega**. Se distinguen diez casos del inventario CVE63 con evidencia técnica parcial; no se les asigna gold. El inventario estructurado anterior de cinco casos sustitutos sigue en `LICENSE_SCOPE_INVENTORY_5.json` y **no** se suma a estos diez como si fueran quince casos independientes.

| CVE / origen | Licencia histórica *observada o descrita*, sin garantía por archivo | Procedencia |
|---|---|---|
| CVE-2021-25932 — OpenNMS | AGPL-3.0 | [registro de siete commits, parent original](CVE_VERIFICATION_7_OF_63_2026-10-17.md) |
| CVE-2026-73140 — MISP/cti-transmute | AGPL-3.0 | [registro de siete commits](CVE_VERIFICATION_7_OF_63_2026-10-17.md) |
| CVE-2023-43256 — Gladys | Apache-2.0 | [registro original, con fallo parcial del parche](CAUSAL_REVIEW_4_AND_MISSING_59_ES.md) |
| CVE-2020-36280 — Leptonica | Permisiva según licencia histórica del proyecto | [registro de siete commits](CVE_VERIFICATION_7_OF_63_2026-10-17.md) |
| CVE-2024-46724 — Linux/AMD GPU | Componentes y cabeceras con condiciones distintas; no basta la raíz GPL | [registro del parche y backports](CAUSAL_REVIEW_4_AND_MISSING_59_ES.md) |
| CVE-2026-60002 — OpenSSH | Familia BSD/permisiva, comprobar cada archivo | [registro de siete commits](CVE_VERIFICATION_7_OF_63_2026-10-17.md) |
| CVE-2026-29035 — CivetWeb | Permisiva, posible diferencia por componente | [registro de siete commits](CVE_VERIFICATION_7_OF_63_2026-10-17.md) |
| CVE-2024-11921 — GiveWP | GPLv3 o posterior, `license.txt` Git blob `41caf864643409541acecae6b449abefa1425bb4` | [análisis de etiquetas 3.18.0 y 3.19.0](CVE_GIVEWP_2024_11921_SOURCE_TRACE_20261018_ES.md) |
| CVE-2024-2395 — Bulgarisation/WooCommerce | GPL-3.0-or-later y dependencia MIT empaquetada | [prueba WordPress y registro de cohorte](COHORT_5_ADMISSION_WORKPLAN_ES.md) |
| CVE-2025-69015 — Crowdsignal Forms | GPL-2.0, licencia original presente en 1.7.2/1.8.0 | [registro de elegibilidad y suite PHPUnit](SOURCE_ELIGIBILITY_DECISIONS_20261017_ES.md) |

## Tres modalidades con obligaciones diferentes

| Entrega prevista | Control técnico/documental antes de afirmar conformidad |
|---|---|
| **Solo metadatos y enlaces al original** | Acreditar procedencia, términos del dataset, marcas, trazabilidad del proyecto y ausencia de redistribución no autorizada de fragmentos |
| **Fragmentos de código fuente** | Revisar titulares, avisos, licencias por archivo, tamaño/contexto del fragmento, obligaciones de atribución y copyleft que sean aplicables |
| **Pares completos fuente vulnerable/corregido** | Revisar cobertura de dependencias, licencias y avisos originales, modificaciones, deberes de ofrecer fuente y términos aplicables a la redistribución del conjunto |

**Precisión legal esencial:** licencias GPL y AGPL **no prohíben vender software o distribuirlo comercialmente**; sí imponen condiciones de licencia y redistribución. Por tanto, `COMMERCIAL_RIGHTS=NOT_VERIFIED` significa **que UltraSec aún no ha acreditado el cumplimiento para su entregable específico**, no que todos los repositorios requieran una licencia privada adicional, ni que la venta esté prohibida. Las licencias permisivas también tienen deberes de aviso/atribución y no garantizan que el código tercero dentro del proyecto esté cubierto.

## Verificaciones aún sin hacer

1. Extraer una lista exacta de los archivos que se pretenda entregar y el titular/licencia de cada uno en **la revisión original**, incluyendo submódulos y dependencias.
2. Conservar hashes SHA-256 de los archivos de avisos, licencia y fuente en ambas revisiones. Un Git blob SHA-1 ayuda a identificar, pero **no sustituye** la verificación de derechos del fichero.
3. Asociar caso→modalidad de entrega→obligaciones aplicables→evidencia de cumplimiento; registrar conflictos o archivos sin licencias con estado pendiente.
4. Si se comercializa a un cliente, revisar contrato, cláusulas de redistribución, uso de marcas, garantías y restricciones aplicables. No elaborar ni simular dictámenes legales firmados.

**Resultado global:** 10 descripciones históricas, **0 de 10 entregables con conformidad comercial completa acreditada**, `GOLD=0`, `BENCHMARK_PRIVATE=NOT_RUN`, `CERTIFICATION=NOT_CERTIFIED`. Esta matriz es inventario de investigación, no asesoramiento o aprobación jurídica formal.
