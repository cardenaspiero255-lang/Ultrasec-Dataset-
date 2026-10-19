# Caso externo independiente en investigación: CVE-2024-12514 / 3D Viewer Online

Fecha: 2026-10-18. **Separado de los cinco candidatos Gitea/Moonlight/Command Block IDE/Crowdsignal/Bulgarisation y del GiveWP ya inspeccionado.** Procedencia de aviso, no gold ni conjunto ciego.

- CVE oficial: [CVE-2024-12514](https://nvd.nist.gov/vuln/detail/CVE-2024-12514), CWE-79.
- Plugin: `3dvieweronline-wp`, WordPress Plugin Directory [página oficial](https://wordpress.org/plugins/3dvieweronline-wp/).
- Aviso del productor de inteligencia Wordfence: [3DVieweronline](https://www.wordfence.com/threat-intel/vulnerabilities/id/ee1c9c62-d5b5-4213-ae5a-d3d4e9103d15). Afecta a `<= 2.2.2`; cambio reparador disponible en `2.2.3`, según el changelog oficial publicado 14 de febrero de 2025.
- Ruta PHP referida expresamente por el registro CVE: `public/class-threedvieweronline-iframe-public.php`. Entrada vulnerable descrita: atributos de shortcode `3Dvo-model`.
- Referencia al archivo SVN Trac por el advisory: [WordPress Trac r3240457](https://plugins.trac.wordpress.org/changeset/3240457/3dvieweronline-wp). **No** suponer que este changeset identifica todos los cambios o que una versión nueva equivale a un fix causal sin inspección.
- Comparación reproducible nueva, cuando el runner la haya ejecutado: `.github/workflows/v7-3dvieweronline-original-source.yml`, obtiene **exclusivamente** distribuciones oficiales versionadas `2.2.2` y `2.2.3`, comprueba PHP sin ejecutarlo, conserva SHA-256 de las descargas y del archivo referenciado, evidencia de ruta y metadatos de licencia. No sube código ni ZIP fuente como artefactos.
- No hay todavía ejecución integrada WordPress que demuestre XSS RED en 2.2.2 y salida escapada GREEN en 2.2.3, ni se verificaron por archivo licencias, NOTICE y titularidad. No inventar `source_git_commit` si los snapshots sólo tienen revisión SVN y checksum.

**Fases intransferibles:** `EXTERNAL_INDEPENDENT_PROJECT_DISCOVERED` (independencia de origen respecto de la cohorte Gitea, **no** independencia de mecanismo frente al holdout) → `ORIGINAL_RELEASE_BYTES_VERIFIED` **sólo cuando la CI real lo confirme** → `SOURCE_CHANGE_CAUSALLY_LINKED` tras inspección → `RED_GREEN_WP_NATIVE` tras WordPress con versiones fijadas → `RIGHTS_PER_FILE_CHECKED` → candidato gold sujeto al protocolo independiente.

**Estado hoy:** `GOLD=NOT_ADMITTED`, `SOURCE_ORIGINAL_CI=UNVERIFIED_UNTIL_RUN`, `HOLDOUT_SPLIT=UNASSIGNED`, `COMMERCIAL_RIGHTS=NOT_VERIFIED`, `CERTIFICATION=NOT_CERTIFIED`; dos revisores humanos aplazados, no sustituídos por anotación automática.
