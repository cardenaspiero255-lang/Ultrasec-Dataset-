# Revisión causal — lote de 63 CVE (17-10-2026)

**Alcance:** rama de investigación de PR #10, derivada de PR #7. Este archivo conserva **solo evidencia y referencias públicas**. No altera pares gold, no declara verificación comercial y no publica muestras vulnerables ni datos de revisores.

## Estado verificable

- 63 IDs públicos de la fase de descubrimiento; 12 CWE representadas. **Ninguno admitido al gold**.
- 4 CVE tenían enlaces a commits upstream en las referencias GHSA. Confirmada la existencia del commit y revisado el diff original para cada uno.
- Un quinto CVE (CVE-2024-46724) obtuvo un commit verificado adicional consultando el aviso del equipo de seguridad Linux.
- **0/63 suites de integración de la aplicación ejecutadas**; **0/63 pruebas vulnerabilidad → corrección completas acreditadas**; **0/63 derechos de reventa certificados**.
- Tres fallos detectados en siete tests aislados del validador de Gladys del *commit corregido* (4 PASS, 3 FAIL). Este es un hallazgo acotado sobre el validador, **no prueba explotación de la aplicación**.

## 1. Commits originales revisados

| CVE / CWE | Repositorio y commit (SHA de 40) | Primer padre | Resultado del diff |
|---|---|---|---|
| CVE-2021-25932 / CWE-79 | [OpenNMS](https://github.com/OpenNMS/opennms/commit/8a97e6869d6e49da18b208c837438ace80049c01) | `795106d2b216b88d872dc97fba3639cca70e5631` | Validación de IDs de usuario y grupo para limitar marcado HTML |
| CVE-2021-25932 / CWE-79 | [OpenNMS, parche asociado 2](https://github.com/OpenNMS/opennms/commit/eb08b5ed4c5548f3e941a1f0d0363ae4439fa98c) | Verificar ancestría conjunta | Escapado de cadenas en controladores JS y tests asociados |
| CVE-2021-25932 / CWE-79 | [OpenNMS, parche asociado 3](https://github.com/OpenNMS/opennms/commit/f3ebfa3da5352b4d57f238b54c6db315ad99f10e) | Verificar ancestría conjunta | Escapado de JSP y salidas HTML |
| CVE-2026-73140 / CWE-862 | [MISP cti-transmute](https://github.com/MISP/cti-transmute/commit/5dbd19b39a61eab793586731f1a80d8c38907c42) | `06d408e3496fdfc31da22d7b2b427434c67eae94` | Pasa usuario solicitante a reportes y filtra comentarios privados |
| CVE-2023-43256 / CWE-22 | [Gladys](https://github.com/GladysAssistant/Gladys/commit/f27d0ea4689c3deca5739b5f9ed45a2ddbf00b7b) | `8d09d2be050b4f505fefe4b2528f9b9b1d07f830` | Incorpora validación de IDs y nombres de archivos RTSP |
| CVE-2020-36280 / CWE-125 | [Leptonica](https://github.com/DanBloomberg/leptonica/commit/5ba34b1fe741d69d43a6c8cf767756997eadd87c) | `ab66d051d8fd57584c350d687a8cc2424565c33c` | Incrementa búfer TIFF para lectura de imágenes gray+alpha |
| CVE-2024-46724 / CWE-125 | [Linux (torvalds/linux)](https://github.com/torvalds/linux/commit/d768394fa99467bcf2703bde74ddc96eeb0b71fa) | `cdca89bce4984f1bb6e53cd4084820d4ff54f977` | Añade validación de rango antes del índice `df_v1_7_channel_number` |

**Aviso oficial kernel:** https://lists.openwall.net/linux-cve-announce/2024/09/18/19. No confundir el commit del árbol principal con los seis backports; no sumarlos como casos independientes.

## 2. Prueba aislada real sobre archivo upstream Gladys

Fuente exacta: `server/services/rtsp-camera/utils/validateStreamParams.js` en `f27d0ea4689c3deca5739b5f9ed45a2ddbf00b7b`.
**Git blob original coincidente con archivo ejecutado en laboratorio:** `6585341516562db2707ed4817efedb3b462f89e6`.

Con `node --test` se ejecutó el módulo original en un contexto `vm` con su única dependencia (`Error400`) reemplazada por stub inocuo. No se abrió ninguna conexión ni archivo de cámara; no se iniciaron servicios.

- 4 PASS: rutas válidas e inválidas ordinarias, sesión válida e inválida.
- 3 FAIL: entradas con prefijo de ruta, sufijo extra o carácter en la posición de punto se aceptan inesperadamente.
- Causa visible en el archivo de corrección: `HLS_CHUNK_REGEX` usa una expresión regular sin anclajes y un punto no escapado.
- **Clasificación:** regresión/limitación del validador aislado que requiere revisión de alcance y regresión upstream; no declarar que este bug es la explotación CVE confirmada. **No admitir al gold.**

## 3. Licencias históricas (snapshot previo a fix)

| Repositorio | Documento histórico / Git blob | Lectura observada | Estado |
|---|---|---|---|
| OpenNMS | `LICENSE.md` `58207820cdf807b7f4f4ce14102cd39544802c1e` | AGPL-3.0, con archivos sujetos a excepciones | RIGHTS_NOT_VERIFIED |
| MISP cti-transmute | `LICENSE` `0ad25db4bd1d86c452db3f9602ccdbe172438f52` | AGPL-3.0 | RIGHTS_NOT_VERIFIED |
| Gladys | `LICENSE` `7af6969976f3d720a8d7f6329fd76ebc0cfd4af9` | Apache-2.0 | RIGHTS_NOT_VERIFIED |
| Leptonica | `leptonica-license.txt` `73d44c601c0746534128804c3fb0b93772897f82` | licencia permisiva propia con obligaciones de atribución | RIGHTS_NOT_VERIFIED |
| Linux | `COPYING` histórico blob `a635a38ef9405fdfcfe97f3a435393c1e9cae971`; `df_v1_7.c` blob `5dfab80ffff213f11d5de27dd7e5c90faa06545e` | Kernel bajo GPL-2.0-only con Linux-syscall-note; el archivo AMD tiene cabecera de licencia permisiva propia; reconciliar derechos y atribución por archivo | RIGHTS_NOT_VERIFIED |

**Advertencia:** localizar y leer licencias históricas no demuestra permiso para vender un dataset concreto sin revisar alcance, terceros, atribución y naturaleza de derivados.

## 4. Triaje adicional dentro de los 59 sin commit de referencia inicial

- **CVE-2024-46724:** enlace de corrección original confirmado en `torvalds/linux`. El aviso oficial lista seis variantes por rama. Falta el test vulnerable/fixed sobre condiciones de ejecución reales.
- **CVE-2024-53015 (CWE-416):** aviso oficial de Qualcomm para Snapdragon/Computer Vision; no se ha obtenido el parche de código fuente original ni derechos. `BLOCKED_NO_PUBLIC_SOURCE`. https://www.cve.org/CVERecord?id=CVE-2024-53015
- **CVE-2024-36074 (CWE-94):** Netwrix CoSoSys (producto propietario); no se ha obtenido código/patch auditables ni licencia de reutilización. `BLOCKED_NO_PUBLIC_SOURCE`. https://nvd.nist.gov/vuln/detail/CVE-2024-36074
- **CVE-2024-54506 (CWE-125):** firmware de Apple; falta código de fuente y parche verificables. `BLOCKED_NO_PUBLIC_SOURCE`. https://nvd.nist.gov/vuln/detail/CVE-2024-54506
- **CVE-2025-60109 (CWE-89):** plugin comercial WordPress LambertGroup; solo aviso disponible, sin parche/licencia de redistribución acreditados. `BLOCKED_PROVENANCE_AND_RIGHTS`.
- **CVE-2026-63048 (CWE-434):** extensión Joomla Page Builder CK; ausencia de fuente/patch verificables para el uso solicitado. `BLOCKED_PROVENANCE_AND_RIGHTS`.

- **CVE-2024-38638 (CWE-787):** comunicado de seguridad QNAP para QTS/QuTS hero (https://www.qnap.com/en/security-advisory/qsa-24-52). No se ha conseguido el código fuente y un diff reparador reproducible: `BLOCKED_NO_PUBLIC_SOURCE`.

Ningún caso bloqueado se descuenta silenciosamente: hay **100 IDs como inventario de descubrimiento**, pero **NO 100 casos potencialmente reproducibles demostrados**, y deberán sustituirse los que no cumplan los requisitos.

## Requisitos siguientes

1. Poner en cuarentena los cinco candidatos sin fuente/derechos suficientes; sustituirlos por proyectos públicos con SHA antes/después, tests y licencia.
2. Completar cadenas de commits, oráculos de comportamiento y prueba fuente→fix del lote de 5 priorizados, en sandboxes sin red con dependencias fijadas y logs SHA-256.
3. Reexaminar el validador Gladys en la aplicación real; el parche examinado es insuficiente para certificar todos los formatos de archivo.
4. Avanzar la revisión de los demás CVE en grupos diversificados por CWE. No contar referencias a commits de metadatos, dependencias o repositorios espejo como fixes originales.
5. Mantener PR #10 y PR #7 **Draft, sin fusionar**, hasta requisitos materiales y CI completa. 0 nuevos al gold, derechos comerciales sin acreditar, SAST real aún NOT_RUN.
