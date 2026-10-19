# UltraSec V7 — elección del producto de mayor valor potencial

**Decisión del propietario, 18-10-2026:** priorizar un producto **B2B privado de pares de código real vulnerable/corregido con pruebas reproducibles**, no la venta del millón sintético ni una simple lista de CVE. Este documento es un **alcance de investigación y preparación**, no una propuesta comercial certificada. No hay ofertas de compra, cifras de disposición a pagar ni tasación validada.

## El contenido que realmente podría aportar valor

Para cada caso real, entregar el mínimo material autorizado que permita reconstruir y comprobar el fallo:

1. Referencia CVE/CWE con clasificación causal confirmada, proyecto upstream, archivo/línea y commits o releases originales fijados.
2. Dos versiones originales (vulnerable y corregida) y dependencias mínimas fijadas, **sólo en la medida permitida por las licencias de cada archivo**. No entregar repositorios enteros porque sí.
3. Test original de regresión o contrato de seguridad que reproduzca **RED antes / GREEN después**, con código de salida, logs y hashes.
4. Descripción independiente del mecanismo causal, falsos positivos difíciles y negativos funcionales, sin introducir variantes sintéticas como defectos independientes.
5. Benchmark separado por proyecto, origen del defecto y mecanismo, contra Semgrep/CodeQL/Slither solo cuando corresponda, con reglas/versiones congeladas antes del holdout.
6. Inventario **por archivo** de titulares, SPDX, LICENSE/NOTICE, dependencias, modificaciones, cumplimiento copyleft/atribución, derechos de redistribución y modalidad autorizada.
7. Cadena de custodia privada de los datos gold y un evaluador blindado; publicar solo agregados permitidos, nunca el holdout o el contenido propietario en GitHub.

## Priorización de las 5 fuentes originales para investigación

| Prioridad | Caso | Razón técnica/comercial de investigar primero | Restricción actual |
|---:|---|---|---|
| 1 | Gitea, CVE-2026-58428 | Regresión Go original de actualización de releases con tags SHAs fijos; licencia MIT observada (notices obligatorios) | Sin inventario exacto de archivos del paquete, revisión de titulares/terceros ni admisión gold |
| 2 | Moonlight C, CVE-2023-42799 | Reproducción aislada bajo ASan y contraste claro de límites de buffer | Licencia GPL-3.0 observada; la regla Semgrep preparada conociendo el parche no vale como benchmark ciego |
| 3 | Command Block IDE, CVE-2024-48645 | Testigo de permisos Java sobre código original | LGPL-2.1 observada; simulación parcial, sin suite integrada del servidor |
| 4 | Crowdsignal Forms, CVE-2025-69015 | Callback WordPress real, PHPUnit RED/GREEN | GPL-2.0 y asignación causal al CVE todavía sujetas a comprobación |
| 5 | Bulgarisation, CVE-2024-2395 | WordPress AJAX con versiones originales y oráculo RED/GREEN | GPLv3 + biblioteca MIT; discrepancia en asignación CWE/CVE y dependencias por archivo pendientes |

El orden es de **facilidad inicial de acreditación**, no una estimación monetaria por CVE. Un repositorio MIT no otorga por sí solo conformidad sobre todo el paquete ni autoriza apropiarse de la obra ajena.

## Política de producto y licencias

- **El código upstream conserva su licencia original.** UltraSec no puede convertir código GPL, AGPL, MIT o LGPL de terceros en exclusivamente propietario ni privar al destinatario de los derechos que su licencia le otorga.
- Si la redistribución del código es compatible y sus obligaciones se cumplen, el negocio puede cobrar por la **curación propia, validaciones, tests originales propios sujetos a derechos, actualizaciones, herramienta evaluadora y soporte**. No se promete exclusividad sobre código abierto.
- Para cada comprador y entrega concreta deben definirse los formatos: **referencias y metadatos**, **pares mínimos de archivos**, o **entorno reproducible**. Si no puede acreditarse cumplimiento con fragmentos/pares, entregar solo enlaces a la fuente cuando sea apropiado o excluir el caso.
- **Nunca** incrustar copias no verificadas de código ajeno en el manifest público; conservar el producto completo y el holdout en almacenamiento privado controlado.

## Gates de entrega (ninguno se da por cumplido por escribir este plan)

| Control | Estado actual |
|---|---|
| Cinco fuentes candidatas con testimonios RED/GREEN de diverso alcance | Investigación técnica; **5 NOT_ADMITTED** |
| Licencias históricas observadas | Sí, **5 en matriz estructurada, 10 descripciones del inventario ampliado** |
| Lista exhaustiva de cada archivo real que el comprador recibiría | **PENDIENTE** |
| Cumplimiento por archivo y modalidad, notices, derechos por dependencias | **PENDIENTE** |
| Corpus privado con ≥100 casos reales independientes y adjudicados | **PENDIENTE — 0 gold** |
| Reglas congeladas y benchmark SAST blindado sobre esos casos | **NO EJECUTADO** |
| Dos revisores humanos | **APLAZADOS** |
| Documento de venta/licencia definitivo | **NO APROBADO** |
| Producto comercial listo para entregar | **NO — NOT_CERTIFIED** |

La especificación comprobable está en `PREMIUM_SOURCE_PAIR_PRODUCT_DRAFT.json` y su validador en `../../tools/premium_source_pair_scope.py`. Mientras cualquiera de los gates comerciales permanezca abierto, `ready_to_sell=false` y `commercially_releaseable_pairs=0`. El inventario anterior `DELIVERY_SCOPE_PUBLIC_METADATA_DRAFT.json` se preserva como **opción informativa distinta**, no se confunde con el producto premium definido aquí.

**No hay un precio verificable todavía.** Deberá determinarse mediante piloto técnico con compradores reales, acuerdos de licencia y utilidad diferencial medida.
