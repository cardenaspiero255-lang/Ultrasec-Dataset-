# UltraSec V7.0 — Registro público del proyecto

**Estado:** proyecto propietario en desarrollo; directorio público de documentación. **No es una publicación de software de código abierto.**

Este directorio está separado de GameHub Ultra y de las herramientas Gamehub-autoOptimizer. No altera sus commits, ramas ni workflows.

## Titularidad y permisos

El uso, ejecución, modificación, distribución y comercialización de los materiales originales de UltraSec V7.0 requieren autorización del titular, sujeto a las excepciones y derechos aplicables. Consulta [el aviso de derechos reservados](LICENSE-PROPRIETARY.txt).

**Límite esencial:** una licencia restrictiva no puede impedir que alguien descargue o clone contenido de un repositorio público. Para controlar realmente la ejecución, el código propietario debe permanecer en almacenamiento privado o detrás de autenticación y autorización en un servicio.

## Estado técnico verificable

La fuente pública de estado es [release-status.json](release-status.json): **Semgrep y CodeQL aún no ejecutados sobre el dataset privado**, certificación externa **NOT_CERTIFIED**, unicidad semántica del millón histórico y 500 mecanismos aún no verificados. Los datos históricos no forman parte de una versión comercial certificada.

### Analizadores independientes: ejecuciones reales sobre el verificador público

El workflow [Independent SAST](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/workflows/ultrasec-public-sast.yml) ejecuta Semgrep OSS con reglas comunitarias y CodeQL con la suite de seguridad ampliada, **exclusivamente sobre el código público Python de validación**.

La [ejecución verificable #38446975445](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/runs/38446975445) completó **2/2 jobs**: Semgrep OSS 1.180.0 encontró 0 hallazgos y 0 errores de parser; CodeQL completó el análisis y publicó resultados en GitHub. **No se escaneó el dataset propietario**.

El análisis privado interno de V7 etapa 1 verificó 324 fragmentos, 162 pares completos y 0 duplicados normalizados; los experimentos funcionales privados de V5.6 se repitieron con 60.000 ejecuciones correctas usando servicios simulados y SQLite en memoria. Estas son comprobaciones internas, **no certificación externa**. Todavía no hay resultados Semgrep/CodeQL sobre las vulnerabilidades privadas ni revisión humana independiente firmada.

### Dos baterías públicas de CI

[7 controles documentales](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/workflows/ultrasec-public-ci.yml) y [7 controles técnicos de una muestra pública](https://github.com/cardenaspiero255-lang/Ultrasec-Dataset-/actions/workflows/ultrasec-enterprise-public.yml). Su estado en verde no certifica el corpus privado, la causalidad de sus etiquetas ni un valor comercial.


### CI público: 7 comprobaciones de política

Los siete checks verifican límites de archivos públicos, posibles secretos, aviso de derechos, afirmaciones respaldadas, trazabilidad mínima, enlaces relativos y robustez básica del propio validador. **Un 7/7 verde demuestra solo la salud de este repositorio documental, NO la exactitud de etiquetas de vulnerabilidades, pruebas del motor privado, dificultad ante SAST ni valoración comercial.**

## Política de publicación segura

- Publicar solo documentación, avisos legales y resultados no sensibles debidamente verificados.
- No publicar datasets completos, generadores propietarios, código ejecutable, respuestas de holdout, claves, credenciales ni material comercial reservado.
- Mantener los componentes protegidos fuera del repositorio público.
- Solicitar autorización expresa del propietario antes de incorporar workflows, binarios, código o datos al directorio.
