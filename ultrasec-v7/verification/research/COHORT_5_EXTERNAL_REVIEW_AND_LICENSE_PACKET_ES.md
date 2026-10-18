# UltraSec V7 — paquete de revisión externa y derechos, cohorte de 5

Fecha de corte: 2026-10-17. Naturaleza: expediente PUBLIC_METADATA_ONLY, no distribuye código fuente tercero ni dataset privado. Ningún caso del lote puede adjudicarse a sí mismo. Estado: NOT_CERTIFIED.

## Resumen del estado técnico

| CVE | CWE alegado | Técnica verificada | Fuente verificable | Falta |
|---|---|---|---|---|
| CVE-2026-58428 | 434 | Gitea Go: el test original del fix falla sobre código padre y pasa sobre el fix | https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39073712740 | Identificación ciega del mecanismo CVE; derechos |
| CVE-2025-69015 | 862 | Crowdsignal: cuatro permisos REST del rol Autor permisivos en 1.7.2 y cuatro resultados corregidos en 1.8.0 con WordPress PHPUnit | https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39078935591 | Vincular la función al advisory preciso, derechos |
| CVE-2023-42799 | 120 | Moonlight: ASan detecta desbordamiento de pila de función original en padre y copia acotada en fix | https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39076329630 | Prueba del proyecto completo, atribución y derechos |
| CVE-2024-48645 | 862 | Command Block IDE: prefijo original Java permite procesamiento sin privilegio antes y lo rechaza después | https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39078876423 | Servidor Fabric real, atribución y derechos |
| CVE-2024-2395 | 352 | Bulgarisation: WP/WooCommerce admin-AJAX original con tres casos, RED 3.0.14 (dos fallos esperados) y GREEN 3.0.15 (3 tests / 19 assertions); transportes interceptados | https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39081399130 | Atribución CWE y distinción CVE-2024-0683, alcance de otros handlers y derechos |

Los resultados son de distinto nivel de integración. Gitea emplea Go nativo, Crowdsignal usa WordPress PHPUnit, Moonlight y Command Block IDE extraen fragmentos originales, y Bulgarisation usa el callback AJAX original en WordPress + WooCommerce con todo el tráfico de proveedores interceptado. No se pueden equiparar ni extrapolar a una garantía de ausencia de otras vulnerabilidades.

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

A la fecha: 5 investigaciones públicas, 5 contrastes RED/GREEN técnicos (con distinto alcance de integración), 1 guard aislado adicional, 0/5 derechos comerciales dictaminados, 0/2 revisores externos, 0 gold admitido, ningún caso importado a entrenamiento/holdout, SAST sobre gold real NOT_RUN y V7 NOT_CERTIFIED. No publicar ni firmar certificados ficticios.

El único punto de entrada del lote público es COHORT_5_PRE_ADMISSION_PUBLIC.json; su verificador rechaza admisiones y particiones autodeclaradas.


## Avance posterior: WP AJAX original y protocolo HMAC

### CSRF de Bulgarisation 3.0.14 → 3.0.15

En el [run RED/GREEN del AJAX original](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39081141414) se cargó **WordPress 6.6.2 + WooCommerce 8.7.0** y los ZIP oficiales 3.0.14/3.0.15. La prueba crea una orden efímera y emite `do_action('wp_ajax_woo_bg_cvc_delete_label')` como administrador con permiso legítimo pero un nonce falsificado. **Cada** solicitud HTTP desde WordPress está interceptada antes de salir; nunca se contacta a CVC, Econt ni Speedy.

- Antes: el controlador aceptó el nonce inválido y alcanzó la preparación de la solicitud HTTP externa (interceptada, 1 intento) → PHPUnit RED esperado.
- Después: `wp_send_json_error`/manejador `wp_die` negó la acción sin intentar HTTP (0 intentos), PHPUnit GREEN con 6 aserciones.
- La respuesta con nonce ausente —no presente en `$_REQUEST`— provocaba un aviso `Undefined array key "nonce"` en la versión corregida bajo PHPUnit. Se usó un **nonce presente, inválido** para probar el control CSRF sin confundir el aviso con una denegación normal. Este aviso debe quedar como caso funcional residual para una auditoría de calidad; no declarar rechazo limpio de toda entrada posible.
- El ensayo no realiza la cancelación real en transportistas; verifica la diferencia de **llegada al límite de salida** usando callback WordPress y WooCommerce reales.
- Ejecutar además roles no privilegiados con nonce válido y el control positivo de administrador con nonce válido, antes de cerrar el rango completo de autorizaciones. **La asociación exacta y alcance de CVE-2024-2395 frente a CVE-2024-0683 aún debe ser adjudicada independientemente.**

### Protocolo para revisión independiente real

- Código: `ultrasec-v7/tools/prepare_blind_cohort.py`; tests `ultrasec-v7/tests/test_prepare_blind_cohort.py`.
- Dos *slots* A y B con ID opacos distintos por HMAC y clave que **nunca** se almacena en este repositorio; respuestas iniciales en blanco, `signature=null`, conflicto/exposición previa pendiente.
- La correspondencia CVE ↔ ID se conserva **fuera del repositorio y con permisos 0600** bajo el custodio. Nunca publicar ni subir la correspondencia como artefacto de GitHub CI; ejecutar la utilidad únicamente en una máquina o entorno privado controlado.
- No se incorpora código protegido de terceros a los paquetes sin evaluación previa de permisos de entrega; el custodio proveerá material autorizado y anonimizado tras acordar confidencialidad.
- Estos pasos solo preparan una evaluación; no certifican que sea verdaderamente ciega si el experto conoce previamente el CVE o identifica el proyecto por su código. La exposición previa y los conflictos deben declararse.
- [Convocatoria humana específica — issue #12](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/issues/12). **0/2 revisores confirmados; ningún dictamen ni firmas.**

### Encargo jurídico externo

- [Solicitud de revisión jurídica humana — issue #11](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/issues/11). El alcance distingue tres modalidades: metadatos sin código; fragmentos/diffs; y pares completos de código. La modalidad de venta no está contractual ni técnicamente fijada.
- La [FAQ oficial de GNU](https://www.gnu.org/licenses/gpl-faq.es.html) permite vender copias GPL cumpliendo la licencia, pero no da un derecho de exclusividad ni autoriza imponer restricciones adicionales incompatibles a las copias cubiertas.
- Fuentes de licencias históricas verificadas ≠ autorización comercial del producto concreto ni informe de abogado firmado.
- Se exigen titulares y avisos por archivo, dependencias, interpretación de licencia por modalidad/jurisdicción y dictamen humano. **0/5 derechos confirmados; estado `COMMERCIAL_RIGHTS=NOT_VERIFIED`.**

**Al cierre de estas notas, el dataset privado, sus etiquetas y el holdout no se han modificado. `gold=0`, `reviews_signed=0`, `SAST_PRIVATE=NOT_RUN`, `V7=NOT_CERTIFIED`.**


## Rectificación de corte — prueba de tres escenarios

El [run 39081399130](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39081399130) acredita el mismo flujo AJAX original en los ZIP 3.0.14 y 3.0.15: administrador con nonce falsificado, suscriptor con nonce válido y administrador autorizado con nonce válido. En 3.0.14 los dos casos no autorizados llegaron al transporte HTTP interceptado (2 fallos esperados de 3 pruebas); en 3.0.15 fueron rechazados antes del transporte y el control autorizado siguió avanzando (3 pruebas y 19 aserciones exitosas). **No se enviaron solicitudes reales a transportistas**. Esto completa el contraste de la ruta bajo prueba, no un examen exhaustivo de los AJAX del plugin. El acoplamiento exacto del advisory CVE-2024-2395 y CVE-2024-0683 requiere revisión independiente.

**Solicitudes externas reales:** [issue #12, dos revisores AppSec](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/issues/12) y [issue #11, revisión jurídica profesional](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/issues/11). Crearlas no acredita personas asignadas ni firmas: **0/2 revisores, 0/5 derechos comerciales, gold 0/5**.
