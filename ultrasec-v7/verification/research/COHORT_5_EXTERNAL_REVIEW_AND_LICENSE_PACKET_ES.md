# UltraSec V7 — paquete de revisión externa y derechos, cohorte de 5

Fecha de corte: 2026-10-17. Naturaleza: expediente PUBLIC_METADATA_ONLY, no distribuye código fuente tercero ni dataset privado. Ningún caso del lote puede adjudicarse a sí mismo. Estado: NOT_CERTIFIED.

## Resumen del estado técnico

| CVE | CWE alegado | Técnica verificada | Fuente verificable | Falta |
|---|---|---|---|---|
| CVE-2026-58428 | 434 | Gitea Go: el test original del fix falla sobre código padre y pasa sobre el fix | https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39073712740 | Identificación ciega del mecanismo CVE; derechos |
| CVE-2025-69015 | 862 | Crowdsignal: cuatro permisos REST del rol Autor permisivos en 1.7.2 y cuatro resultados corregidos en 1.8.0 con WordPress PHPUnit | https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39078935591 | Vincular la función al advisory preciso, derechos |
| CVE-2023-42799 | 120 | Moonlight: ASan detecta desbordamiento de pila de función original en padre y copia acotada en fix | https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39076329630 | Prueba del proyecto completo, atribución y derechos |
| CVE-2024-48645 | 862 | Command Block IDE: prefijo original Java permite procesamiento sin privilegio antes y lo rechaza después | https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39078876423 | Servidor Fabric real, atribución y derechos |
| CVE-2024-2395 | 352 | Bulgarisation: helper original nuevo controla nonce y manage_woocommerce, pruebas aisladas 4/4 PASS y nueve llamadas en tres transportistas | https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39078707779 | Petición CSRF WordPress/WooCommerce antes/después, derechos y distinción CVE-2024-0683 |

Los resultados anteriores son de distinto nivel de integración. La prueba de Gitea es Go nativo, la de Crowdsignal usa WordPress PHPUnit, Moonlight y Command Block IDE extraen fragmentos de fuente original y Bulgarisation prueba solo el guard de la versión corregida. No se pueden equiparar ni extrapolar a una garantía de ausencia de otras vulnerabilidades.

## Registro histórico de licencias: evidencia primaria observada

| Producto | Revisión histórica / artefacto | Archivo y licencia observada | Obligaciones a evaluar antes de vender fragmentos |
|---|---|---|---|
| Gitea | Padre Git 7fdfb8d642201b388014f29889ef28e35b8c1872 | LICENSE blob a8d4b49dd073a4a38a7e58385eeff7cc52568697, MIT | Preservar aviso copyright y licencia donde corresponda; aclarar titularidad de la anotación y alcance comercial |
| Crowdsignal Forms | Etiquetas 1.7.2 y 1.8.0 | LICENSE.TXT blob ecbc0593737be657aef92e3adcf3bcbd6fdb812e, GPLv2 | Condiciones de distribución/modificación y de disponibilidad de fuente si se distribuyen porciones cubiertas |
| Moonlight Common C | Padre Git 116267a24569ec610f4c9efa1048541022981040 | LICENSE.txt blob 9cecc1d4669ee8af2ca727a5d8cde10cd8b2d7cc, GPLv3 | Origen de archivos y avisos GPL; posible obligación copyleft según el producto y material redistribuido |
| Command Block IDE | Padre Git 7da8ea77ba3443c42e0d9929f66b370bb97c0234 | LICENSE blob ee9ed415ee14252a64a1bba6d73c85deb6551dc7, LGPLv2.1 | Revisar si se redistribuye código de biblioteca cubierto, obligaciones de copyright y acceso a fuentes |
| Bulgarisation for WooCommerce | ZIP oficiales WordPress 3.0.14 SHA-256 27d26aa7471ba11f93dad473bd055be5a3f38484a8e103abb7b6f0d404067612, 3.0.15 SHA-256 84040bef3e55107962e16d49aebfdbccbbf61f790994642266a86096ee14f2f8 | license.txt y readme.txt: GPLv3 o posterior; vendor/chillerlan/php-qrcode/LICENSE: MIT | Inventario SBOM completo, atribución por archivo, fuentes y redistribución según contenido efectivamente vendido |

Un archivo LICENSE visible demuestra la existencia de una licencia publicada, NO que se haya revisado cada contribución, cabecera, archivo de terceros, distribución comercial propuesta ni titularidad del nuevo dataset. No existe dictamen legal firmado. Estado de cada caso: COMMERCIAL_RIGHTS=NOT_VERIFIED.

Fuentes oficiales para el análisis independiente:
- GPL FAQ: https://www.gnu.org/licenses/gpl-faq.html
- GNU GPLv3: https://www.gnu.org/licenses/gpl-3.0.html
- Apache license and attribution guidance: https://www.apache.org/licenses/LICENSE-2.0
- Los archivos históricos de los repositorios Git y paquetes oficiales citados en la tabla.

## Diligencia legal independiente necesaria

La persona revisora debe precisar primero el producto real que se entregará: solo metadatos/anotaciones, snippets, pares completos, diffs, ejecutables o base de entrenamiento; después verificar por archivo y titular los permisos, los avisos de derechos, las obligaciones de entrega de fuente, restricciones para marcas y patentes y las condiciones contractuales que se desean imponer a compradores. Registrar jurisdicción de venta y versión exacta de cada paquete. Una conclusión favorable puede ser condicionada, negativa o pendiente.

Campos abiertos: organización/profesional [SIN DESIGNAR], fecha [SIN FIRMAR], alcance [PENDIENTE], digest de informe jurídico [NO EXISTE], conclusión por CVE [NO DICTAMINADA].

## Revisión de seguridad: dos dictámenes independientes

Para cada caso, dos evaluadores independientes deben recibir individualmente una copia privada recortada de la evidencia SIN etiqueta CVE/CWE, sin salida del detector y sin acceso al informe público etiquetado antes de emitir su dictamen. Deben registrar criterios de inclusión/independencia, si han visto previamente el caso, revisión del diff y el oráculo, pruebas negativas, compatibilidad, datos de origen y si el fix trata o no la misma causa. Asignación real de split solamente después de medir riesgos de contaminación y duplicados entre proyectos, commits y muestras.

Revisor A: [NO CONTRATADO], firma [NO EXISTE], hallazgo [PENDIENTE].
Revisor B: [NO CONTRATADO], firma [NO EXISTE], hallazgo [PENDIENTE].
Adjudicación de desacuerdos: [NO REALIZADA].
Las respuestas de GitHub Actions, asistentes, búsquedas y el propio autor NO son revisiones externas humanas.

## Protección de holdout y aceptación

A la fecha: 5 investigaciones públicas, 4 contrastes RED/GREEN técnicos, 1 guard aislado, 0/5 derechos comerciales dictaminados, 0/2 revisores externos, 0 gold admitido, ningún caso importado a entrenamiento/holdout, SAST sobre gold real NOT_RUN y V7 NOT_CERTIFIED. No publicar ni firmar certificados ficticios.

El único punto de entrada del lote público es COHORT_5_PRE_ADMISSION_PUBLIC.json; su verificador rechaza admisiones y particiones autodeclaradas.
