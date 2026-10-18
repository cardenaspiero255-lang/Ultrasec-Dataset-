# CVE-2024-11921 — GiveWP: original patch trace, NO gold

Corte: 2026-10-18. Fuente primaria: [NVD CVE-2024-11921](https://nvd.nist.gov/vuln/detail/CVE-2024-11921) (CWE-79), [Wordfence advisory](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/give/givewp-donation-plugin-and-fundraising-platform-3180-reflected-cross-site-scripting), [upstream original](https://github.com/impress-org/givewp). El advisory identifica el parámetro de migración `give-run-migration` y la remediación en **3.19.0**, sin afirmar que la inspección de código equivale a un exploit reproducido.

## Nueva inspección de commit original (no suite integrada)

| CVE | CWE | Commit original inspeccionado | Padre candidato | Licencia histórica observada |
|---|---|---|---|---|
| CVE-2024-11921 | CWE-79 | [4fb99af5304257ce0a5adf0df78f02b59755c2df](https://github.com/impress-org/givewp/commit/4fb99af5304257ce0a5adf0df78f02b59755c2df) | `a20c9d8f727adc9863bbd4bff098087f2af9a29c` | GPLv3 o posterior, `license.txt` en ambos tags; Git blob `41caf864643409541acecae6b449abefa1425bb4` |

## Evidencia primaria exacta

- Tag vulnerable de origen: [3.18.0](https://github.com/impress-org/givewp/tree/3.18.0) resuelve commit `d056e04cbb1b43664b2b13c1df6fb7328cc0db11`. Archivo afectado `src/Framework/Migrations/Controllers/ManualMigration.php` con blob Git `1693d95e6c3e88106169eb540630a1ece5978b2a`.
- Tag corregido: [3.19.0](https://github.com/impress-org/givewp/tree/3.19.0) resuelve commit `b24415fee1438d321407dee8739733092ac0b90a`; mismo archivo, blob `2daa91f1c627a4c3d8e28bdcdbf148a0cf9ecef5`.
- La comparación de tags contiene **6 commits y 8 archivos cambiados**. Un commit original [4fb99af...](https://github.com/impress-org/givewp/commit/4fb99af5304257ce0a5adf0df78f02b59755c2df) fue incluido con título `Fix: sanitize migration param url (#7634)`.
- En `ManualMigration::__invoke`, ambos parámetros `give-run-migration` y `give-clear-update` recibían valores directos de `$_GET` antes del parche; después se pasan por `give_clean(...)`. **Un cambio de dos parámetros en un único commit no crea dos CVE ni dos mecanismos independientes.**
- `license.txt` aparece en ambas revisiones con idéntico blob `41caf864643409541acecae6b449abefa1425bb4` y declara GPLv3 o posterior. Observar esta licencia **no equivale a autorizar un producto premium restrictivo que incluya el código**.
- No se ejecutó WordPress/GiveWP completo, ni pruebas XSS end-to-end, ni se examinó todavía el flujo final de renderizado de avisos. El patch-diff es consistente con el advisory; no acredita por sí solo eliminación universal de XSS.

**Clasificación:** `ORIGINAL_COMMIT_INSPECTED_NO_FULL_UPSTREAM_REPRO`, `GOLD=NOT_ADMITTED`, `INDEPENDENT_HOLDOUT=NOT_VERIFIED`, `SAST_FOR_THIS_CVE=NOT_RUN`, `COMMERCIAL_RIGHTS=NOT_VERIFIED`, `CERTIFICATION=NOT_CERTIFIED`.

**Siguiente prueba original:** fijar versiones exactas y dependencias, reproducir sin ejecutar contenido externo el mismo caso funcional en 3.18.0 y 3.19.0 bajo WordPress, obtener salida verificable y asociar causalmente el parámetro afectado a la salida HTML sin asumirlo por nombre de commit.
