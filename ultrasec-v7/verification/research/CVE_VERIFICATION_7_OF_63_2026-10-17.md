# UltraSec V7: auditoría parcial de 7/63 candidatos (NO_ADMITTED)

Corte: 2026-10-17. Inspección de commits históricos del proyecto original, no admisión independiente. Son 4 referencias del primer lote y 3 identificadas entre los otros 59.

| CVE | CWE | Commit original inspeccionado | Padre candidato | Licencia histórica observada |
|---|---|---|---|---|
| CVE-2021-25932 | CWE-79 | [8a97e6869d6e](https://github.com/OpenNMS/opennms/commit/8a97e6869d6e49da18b208c837438ace80049c01) | `795106d2b216b88d872dc97fba3639cca70e5631` | AGPL-3.0 |
| CVE-2026-73140 | CWE-862 | [5dbd19b39a61](https://github.com/MISP/cti-transmute/commit/5dbd19b39a61eab793586731f1a80d8c38907c42) | `06d408e3496fdfc31da22d7b2b427434c67eae94` | AGPL-3.0 |
| CVE-2023-43256 | CWE-22 | [f27d0ea4689c](https://github.com/GladysAssistant/Gladys/commit/f27d0ea4689c3deca5739b5f9ed45a2ddbf00b7b) | `8d09d2be050b4f505fefe4b2528f9b9b1d07f830` | Apache-2.0 |
| CVE-2020-36280 | CWE-125 | [5ba34b1fe741](https://github.com/DanBloomberg/leptonica/commit/5ba34b1fe741d69d43a6c8cf767756997eadd87c) | `ab66d051d8fd57584c350d687a8cc2424565c33c` | permisiva, texto histórico |
| CVE-2024-46724 | CWE-125 | [d768394fa994](https://github.com/torvalds/linux/commit/d768394fa99467bcf2703bde74ddc96eeb0b71fa) | `cdca89bce4984f1bb6e53cd4084820d4ff54f977` | cabecera AMD permisiva |
| CVE-2026-60002 | CWE-416 | [e8bdfb151a35](https://github.com/openssh/openssh-portable/commit/e8bdfb151a356d0171fea4194dd205fbb252be23) | `d43ba60c91cb323ca921049b7d43b1908c318454` | varias BSD/permisivas |
| CVE-2026-29035 | CWE-787 | [d110e8731c6a](https://github.com/civetweb/civetweb/commit/d110e8731c6aa0fcd04504deb449bdb773cfb9da) | `3c0fb6ad582224b91959caf79a25dd98389c084d` | permisiva, por componente |

## Resultados reales

- OpenNMS: se verificaron los tres commits XSS referenciados por el aviso; el primero valida ID y otros dos agregan escape de salida en vistas. No son tres casos gold distintos.
- MISP: el cambio filtra comentarios de informes según el usuario solicitante.
- Leptonica: amplía reserva del buffer TIFF de escala de grises + alfa; no se ejecutó el caso ASan.
- Linux: añade un chequeo del límite de índice; fuente primaria: https://lists.openwall.net/linux-cve-announce/2024/09/18/19.
- OpenSSH: repara la vida útil del estado de conexión; corroboración del CVE: https://patchwork.yoctoproject.org/project/oe-core/patch/20260720185749.4098075-8-devanshp%40cisco.com/.
- CivetWeb: reserva cuatro bytes adicionales para WebSocket comprimido; sin ejecutar con dependencias y opciones del proyecto.
- Gladys: **2 de 4** pruebas locales de validación fallaron contra el archivo patched de Git SHA de blob `6585341516562db2707ed4817efedb3b462f89e6`. El validador permite entradas no canónicas por expresión regular sin delimitación; una corrección **solo local** pasa 4/4. Se usó stub aislado del error y no se probó el endpoint completo ni se modificó el upstream.

## Límites de evidencia

- Inspección de archivos de licencia histórica en los padres de estos 7 commits. Una licencia pública NO acredita por sí sola condiciones de comercialización o sublicencia del corpus.
- **0/7** pruebas upstream completas; **0/7** derechos comerciales acreditados; **0/7** admitidos al gold; **0** informes humanos independientes.
- Los otros **56/63** candidatos todavía necesitan un commit original comprobado; algunos son proyectos propietarios o anuncios sin parche.
- Antes de promover a gold: cotejar CVE y CWE, verificar ancestros, SHA-256 de contenidos, repetir pruebas con igual ambiente vulnerable/fixed, revisión jurídica, control de contaminación y evaluación ciega.
- Este informe solo documenta verificaciones parciales; no altera gold, SAST, PR #7 ni autorizaciones comerciales.
