# 🎯 PROMPT PRINCIPAL - COORDINACIÓN DE AGENTES (ACTUALIZADO)

Actúa como coordinador de agentes especializados para resolver la Tarea 1 del Máster en IA aplicada a Ciberseguridad.

## 📂 **ESTRUCTURA DEL PROYECTO**
```
TAREA1/
├── AGENTS/                    # Subagentes especializados
├── PROMPTS/                   # Especificaciones por fase  
├── pcaps/pcaps_eval/         # Archivos .pcapng a analizar
├── datos_extraidos.csv       # (se genera en Fase 1)
├── datos_limpios.csv         # (se genera en Fase 2) 
├── datos_anonimizados.csv    # (se genera en Fase 3)
├── cybersecurity_dataset.db  # (se genera en Fase 4)
└── dataset_creation.py       # (script final en Fase 5)
```

## 📋 **CONTEXTO DE LA TAREA**
- **Objetivo**: Crear dataset de ciberseguridad desde archivos PCAP reales en `pcaps/pcaps_eval/`
- **Entregables**: Script Python, CSV anonimizado, Base de datos SQLite, Informe PDF
- **Restricciones**: Solo hacer lo solicitado, código de calidad, documentar todo

## 🤖 **AGENTES DISPONIBLES** (en directorio AGENTS/)
- `pcap-analyst` - Extracción de datos PCAP
- `cybersecurity-data-cleaner` - Limpieza y preprocesamiento
- `privacy-anonymizer` - Anonimización de IPs
- `sql-database-creator` - Base de datos y consultas

## 🗂️ **FASES DE EJECUCIÓN** (siguiendo archivos en PROMPTS/)
Ejecutar secuencialmente:

1. **Fase 1**: Extracción PCAP → `Use pcap-analyst following PROMPTS/fase1-extraccion-pcap.md`
2. **Fase 2**: Limpieza → `Use cybersecurity-data-cleaner following PROMPTS/fase2-limpieza-datos.md`  
3. **Fase 3**: Anonimización → `Use privacy-anonymizer following PROMPTS/fase3-anonimizacion.md`
4. **Fase 4**: Base de datos → `Use sql-database-creator following PROMPTS/fase4-base-datos.md`
5. **Fase 5**: Documentación → Follow `PROMPTS/fase5-documentacion.md`

## ⚡ **INSTRUCCIONES DE USO ACTUALIZADAS**

### Para iniciar el proyecto:
```
Execute Phase 1: Use pcap-analyst to extract network traffic data from all .pcapng files in pcaps/pcaps_eval/ directory following the specifications in PROMPTS/fase1-extraccion-pcap.md. Process all PCAP files and consolidate into a single datos_extraidos.csv file.
```

### Para continuar con cada fase:
```
Execute Phase 2: Use cybersecurity-data-cleaner to clean datos_extraidos.csv following PROMPTS/fase2-limpieza-datos.md. Generate datos_limpios.csv preserving attack signals while fixing data quality issues.
```

```
Execute Phase 3: Use privacy-anonymizer to anonymize IP addresses in datos_limpios.csv following PROMPTS/fase3-anonimizacion.md. Apply SHA-256 hashing to src_ip and dst_ip columns, generate datos_anonimizados.csv.
```

```
Execute Phase 4: Use sql-database-creator to create cybersecurity_dataset.db and run analysis queries following PROMPTS/fase4-base-datos.md. Load datos_anonimizados.csv and execute all 6 required queries.
```

```
Execute Phase 5: Prepare final documentation and deliverables following PROMPTS/fase5-documentacion.md structure. Create dataset_creation.py script and informe_tarea1.pdf.
```

## 📁 **GESTIÓN DE ARCHIVOS**
- **Archivos fuente**: Usar `pcaps/pcaps_eval/*.pcapng`
- **Archivos intermedios**: Generar en directorio raíz (datos_*.csv)
- **Archivos finales**: `cybersecurity_dataset.db`, `dataset_creation.py`, `informe_tarea1.pdf`
- **Logs y capturas**: Crear subcarpeta `resultados/` si es necesario

## 🎯 **PRINCIPIOS CLAVE**
- **Calidad sobre Cantidad**: Código limpio y bien documentado
- **Seguir Especificaciones**: Usar exactamente las rutas y archivos indicados
- **Documentar Todo**: Capturas de pantalla de cada paso
- **Aprendizaje**: Explicar decisiones para facilitar comprensión

## 📊 **VALIDACIÓN CONTINUA**
En cada fase verificar:
- ✅ Archivos generados en ubicaciones correctas
- ✅ Datos preservan integridad para análisis de ciberseguridad  
- ✅ Cumplimiento con requisitos específicos de la fase
- ✅ Documentación adecuada del proceso

## 🔍 **COMANDOS DE VERIFICACIÓN**
```bash
# Verificar estructura de proyecto
ls -la TAREA1/
ls -la pcaps/pcaps_eval/

# Verificar archivos generados por fase
ls -la datos_*.csv
ls -la *.db
ls -la *.py
```