# UltraSec V7 — candidatos originales nuevos y controles auténticos (19-10-2026)

**Alcance:** investigación con originales de terceros, no admisión GOLD, no benchmark ciego, no autorización de venta de código. Se verifican experimentos originales y atributos de los repositorios; no se afirma independencia del corpus privado.

## A. Gladys Assistant — CVE-2023-43256, CWE-22

- Proyecto original: https://github.com/GladysAssistant/Gladys
- Commit vulnerable: 8d09d2be050b4f505fefe4b2528f9b9b1d07f830; commit fix: f27d0ea4689c3deca5739b5f9ed45a2ddbf00b7b, padre/hijo directos.
- Función original: server/services/rtsp-camera/api/rtspCamera.controller.js. El fix añade comprobación del ID de sesión y nombre de archivo mediante el archivo original validateStreamParams.js; NO se reescribió el controlador.
- Ensayo https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39269900172: ambos jobs PASS. Antes, el endpoint autenticado podía abrir un archivo canary (texto sintético) fuera del directorio de streaming; después falla con Error400. Controles BENIGNOS: index.m3u8 e index1.ts leen correctamente en **ambos** commits, con streaming real limitado a mkdtemp y adaptadores de dependencias. No hubo acceso a archivos reales externos ni servidor HTTP.
- Alcance: función original RTSP + Node vm/adaptadores; **no** prueba integrada con middleware de Express, despliegue Gladys completo ni explotación remota.
- Licencia observada en commit fix: raíz Apache-2.0, blob Git 7af6969976f3d720a8d7f6329fd76ebc0cfd4af9. No se ha acreditado obligación/permiso comercial por archivo del entregable final.
- Estado: ORIGINAL_REPRODUCED (aislado), CANDIDATE_NOT_ADMITTED, gold=0, futuro HOLDOUT=EXCLUDED_KNOWN_RESEARCH.

## B. MISP cti-transmute — CVE-2026-73140, CWE-862

- Proyecto original: https://github.com/MISP/cti-transmute
- Commit vulnerable: 06d408e3496fdfc31da22d7b2b427434c67eae94; fix: 5dbd19b39a61eab793586731f1a80d8c38907c42, padre/hijo directos.
- Función: website/web/evaluate/evaluate_core.py, build_evaluation_report; en el fix se propaga actor y se usa access.can_see_comment(), funciones originales del mismo proyecto.
- Prueba principal https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39270678645 — 2/2 jobs PASS. Antes, un informe exportable de una conversión pública incluye contenido de comentario privado; después se filtra para visitante ajeno y se preservan comentarios públicos, del propietario, autor o administrador. Se usa AST de función original, consultas en memoria y datos sintéticos; sin Flask ni base externa. Ejecución de corroboración: https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39270678179.
- Alcance: función original aislada; no prueba integrada del endpoint Markdown/PDF, filtros de rutas ni producción.
- Licencia raíz en commit fix: AGPL-3.0, blob Git 0ad25db4bd1d86c452db3f9602ccdbe172438f52. Cualquier entrega/comercialización necesita plan de cumplimiento AGPL para el alcance real; no concedida ni certificada.
- Estado: ORIGINAL_REPRODUCED (aislado), CANDIDATE_NOT_ADMITTED, gold=0, futuro HOLDOUT=EXCLUDED_KNOWN_RESEARCH.

Los originales de estos dos proyectos NO pertenecen a los cinco candidatos previamente reproducidos (Gitea, Crowdsignal, Bulgarisation, Moonlight, CommandBlock IDE). **Esto no demuestra separación respecto del entrenamiento privado**, cuyos metadatos y clones semánticos no han sido presentados. Tampoco son candidatos ciegos futuros: sus parches y resultados han sido examinados públicamente.

## C. Resolución de alcance comercial Couchbase/BSL mediante exclusión, no dictamen

Referencia de artefactos reales del GO servicio Gitea:
- Original vulnerable: https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/39264516653 (archivo gitea-public-go-import-closure-vulnerable), 118 módulos externos, **sin goutils en esta clausura concreta**.
- Original corregido: el mismo run, archivo gitea-public-go-import-closure-fixed, 155 módulos externos, goutils v0.3.0 con dos paquetes y estos **cuatro archivos Go compilados**:
  1. logging/logger.go — SHA256 49077aba6fbe5241fa6a93f7d00d94df4add65b1ec7d247995391e0034cba270
  2. logging/logger_golog.go — SHA256 d32725e23d15ec9af4cffb8d8a299eb76cbf50ba2cb51b9c47fd69a2dec8ac27
  3. scramsha/scramsha.go — SHA256 8a43d5236b3212b1e6bfb63cbce3faf9f6e16d2bf4583d046e5edf7ec64ec00f
  4. scramsha/scramsha_http.go — SHA256 20bdfdf5ef281fcafb79fe528823ec627d90afd7fba06b3636053dccee67c684
- Original LICENSE.txt de https://github.com/couchbase/goutils/blob/v0.3.0/LICENSE.txt requiere licencias **por archivo**. Las cuatro cabeceras originales remiten a https://github.com/couchbase/goutils/blob/v0.3.0/licenses/BSL-Couchbase.txt, Licensed Work redactado como Couchbase Server Version 8.0, Change Date March 1, 2029, Change License Apache-2.0. Su aplicabilidad exacta a goutils requiere interpretación legal por el alcance de obra/paquete.
- La puerta de distribución no debe emitir commercial_distribution_allowed=true. Paquete Go autónomo con terceros: **BLOQUEADO**. Método de reproducción original mediante upstream efímero (sin publicar ZIP de código ajeno): investigación, NO aprobación de venta. Un primer SKU de referencias y evidencias **sin bytes de Go/Couchbase/Gitea incluidos** reduce exposición a este componente, pero no prueba clearance comercial del resto de anotaciones/derechos.

## D. Clasificación y prioridad

- GOLD_ADMITTED: **0**.
- Dos reproducciones técnicas originales aisladas **no** equivalen a dos etiquetas gold independientes adjudicadas.
- RIGHTS_NOT_VERIFIED, PRIVATE_HOLDOUT_NOT_VERIFIED, SAST_BLIND_BENCHMARK_NOT_RUN, NOT_CERTIFIED.
- Doble revisión humana EXPRESAMENTE APLAZADA; ninguna firma fingida o exigida en esta fase.
- Próximo hito: correr el screening propietario TRAIN/TEST con metadatos auténticos no publicados, autenticar fuentes y oráculos, bloquear clones y familias cruzadas, congelar reglas aplicables por CWE **antes** de escanear. Revisión real de derechos y NOTICE por modalidad comercial.
