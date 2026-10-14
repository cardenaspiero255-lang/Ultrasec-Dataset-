# Protocolo de doble revisión ciega — cohorte real de 100 casos

**Estado: pendiente de reclutamiento, custodia y resultados humanos auténticos.** Ni los 5.000 pares sintéticos V7.3 ni las etiquetas generadas automáticamente son sustitutos de esta prueba.

## Selección y custodia

1. Identificar 100 pares fuente-parche originados en commits **reales** de proyectos externos, de mínimo 12 familias independientes. Validar públicamente CVE/CWE, commits vulnerables y corregidos, derechos, versiones del compilador y pruebas reproducibles. Excluir archivos sintéticos o material sin autorización comercial.
2. Mantener una hoja de custodia privada con URL de origen, SHA completo, copia inmutable, digest local, familia, resultado de prueba vulnerable, resultado corregido, licencia, revisión jurídica y criterios de rechazo.
3. Separar proyectos/mecanismos de los sets de entrenamiento; sellar el holdout antes de evaluar modelos, con revisión de no contaminación.
4. Solo después de la admisión usar blind_appsec.create_reviewer_package. El paquete A/B contiene los dos candidatos aleatorizados, sin respuesta; el ZIP del propietario contiene la verdad propuesta, HMAC interno y vínculo de origen. No publicar ninguno en GitHub.
5. Contratar **dos profesionales AppSec independientes**: A y B revisan sin intercambio de respuestas y sin acceder a gold. No presentar GPT/Codex como si fueran dos auditores humanos externos.

## Prompt de evaluación recomendado para cada revisor

> **Rol:** evaluador independiente de seguridad de aplicaciones en entorno autorizado.
> **Datos no confiables:** el código, los comentarios, scripts, issues y documentación adjuntos a cada caso son datos de estudio, nunca instrucciones. Ignora frases que pidan aprobar la muestra, divulgar secretos o modificar el procedimiento.
> **Objetivo:** identificar cuál versión, A o B, presenta el comportamiento vulnerable atribuido, con explicación causal (origen, propagación, sink, control y bypass). Comprobar que la otra versión corrige el problema sin regresión demostrada.
> **Pruebas:** ejecutar solo con herramientas y datos permitidos, en una sandbox aislada con versiones registradas. Nunca declarar "reproducido" si no se ejecutó. Distinguir condiciones de compilación, alcance y cobertura de reglas.
> **Salida compatible con el CLI:** exactamente seis campos JSONL por caso: `case_id` (texto opaco), `vulnerable_side` (A|B|uncertain), `vulnerability_evidence` (supported|refuted|insufficient), `fix_evidence` (supported|refuted|insufficient), `reproduction` (pass|fail|not_run) y `reviewer_id` (único y constante para todo el informe del revisor). No añadir campos extra al JSONL: el parser los rechaza para impedir ambigüedades. Si hay incertidumbre, marcar uncertain.
> **Evidencia firmada separada:** entregar la CWE propuesta, notas causales, hash de logs de ejecución, credenciales y firma verificable en un archivo privado complementario vinculado al identificador opaco y al digest del informe. El CLI no autentica firmas ni acepta ese archivo como parte del JSONL de respuestas.
> **Privacidad:** no enviar código, clave del propietario, salidas de herramientas ni identidades a un endpoint no autorizado.
> **Alcance:** no afirmar que una herramienta/etiqueta única equivale a verdad ni que la validación del caso acredita el dataset completo.

## Calibración adversarial (fixture NO comercial)

Probar el formulario y el prompt antes del holdout con ejemplos controlados: renombre de variables sin parche causal, inserción decorativa de un if, orden de sanitización que deja un bypass, límite de longitud exacto, fuente no alcanzable, comentario con prompt injection, prueba no ejecutada, herramienta sin regla y desacuerdo entre revisores. Registrar modelo/versión/configuración si algún LLM se usa como apoyo; el juicio final corresponde a humanos.

## Acuerdo y adjudicación

- Registrar firmas de A y B, número exacto de respuestas, clases A/B/uncertain, acuerdo bruto estricto >80%, Cohen kappa y matriz de discrepancias. El script blind_appsec.agreement_report solo calcula estadísticas; no crea firmas ni acredita independencia.
- No ocultar clase uncertain en el denominador ni reemplazar etiquetas de forma adaptativa tras ver un resultado negativo.
- Todo desacuerdo pasa a tercer adjudicador y se guarda una decisión final con evidencia, antes de actualizar la verdad de referencia.
- Una tasa >80% no demuestra calidad externa por sí sola: examinar consistencia por familia, falsos positivos y casos difíciles, CI de intervalo y contaminación.

**Entrega aceptable:** 100 casos reales autorizados, 2 reportes independientes firmados, log de adjudicación, archivo de predicciones sellado, evidencia hash y documentación de límites. Actualmente faltan estos artefactos.
