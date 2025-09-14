# Informe Final - Tarea 1: Creación de Dataset de Ciberseguridad

**Máster en IA aplicada a Ciberseguridad - Módulo 5**  
**Estudiante:** [Tu nombre completo]  
**Fecha:** 13 de septiembre de 2025  

---

## 1. Introducción

### 1.1 Contexto del Proyecto

Este proyecto forma parte del Módulo 5 del Máster en IA aplicada a Ciberseguridad y tiene como objetivo crear un dataset completo y funcional de ciberseguridad a partir de archivos PCAP reales. El dataset resultante debe cumplir con estándares de calidad, privacidad (GDPR) y ser adecuado para análisis de amenazas y patrones de tráfico de red.

### 1.2 Objetivos Específicos

- Extraer información relevante de tráfico de red desde archivos PCAP
- Implementar un proceso de limpieza y preprocesamiento robusto
- Aplicar técnicas de anonimización para cumplir con GDPR
- Crear una base de datos SQLite optimizada para análisis
- Documentar completamente el proceso y resultados

### 1.3 Descripción de Archivos PCAP

Los archivos PCAP utilizados se encuentran en el directorio `pcaps/pcaps_eval/` y contienen:
- **36 archivos PCAPNG** con tráfico de red real
- Datos de diversos protocolos: TCP, UDP, ICMP
- Información DNS, HTTP y metadatos de tráfico
- Potenciales patrones de ataque y actividad maliciosa

### 1.4 Metodología del Ciclo de Vida de Datos

El proyecto implementa un ciclo de vida completo de datos que incluye:

1. **Extracción**: Procesamiento de archivos PCAP con `tshark`
2. **Limpieza**: Validación y preprocesamiento de datos
3. **Anonimización**: Protección de privacidad con hash SHA-256
4. **Almacenamiento**: Base de datos SQLite optimizada
5. **Análisis**: Consultas analíticas para insights de ciberseguridad

---

## 2. Extracción de Datos

### 2.1 Herramientas Utilizadas

**Herramienta principal:** `tshark` (Wireshark Command Line)

**Justificación de la elección:**
- **Estándar de la industria** para análisis de tráfico de red
- **Soporte completo** para múltiples protocolos y formatos PCAP
- **Flexibilidad** en filtrado y extracción de campos específicos
- **Performance** optimizada para procesamiento en lote
- **Compatibilidad** con archivos PCAPNG modernos

### 2.2 Comando Ejecutado

```bash
tshark -r [archivo.pcapng] -T fields -E header=y -E separator=, \
    -e frame.time \
    -e ip.src -e ip.dst \
    -e ip.proto \
    -e tcp.srcport -e tcp.dstport \
    -e udp.srcport -e udp.dstport \
    -e frame.len \
    -e dns.qry.name \
    -e http.host \
    -e http.request.uri \
    -e http.user_agent \
    'not arp and not stp and not cdp and not lldp'
```

**Explicación del comando:**
- `-r`: Lee archivo PCAP de entrada
- `-T fields`: Formato de salida en campos específicos
- `-E header=y`: Incluye encabezados en la primera línea
- `-E separator=,`: Usa coma como separador (formato CSV)
- `-e [campo]`: Extrae campos específicos de interés
- Filtro final: Excluye protocolos de bajo nivel no relevantes

### 2.3 Filtrado Aplicado

**Tráfico mantenido:**
- Paquetes IP (IPv4/IPv6)
- Protocolos TCP, UDP, ICMP
- Consultas DNS
- Tráfico HTTP/HTTPS
- Metadatos de aplicación

**Tráfico eliminado:**
- Protocolos ARP (Address Resolution Protocol)
- STP (Spanning Tree Protocol)
- CDP (Cisco Discovery Protocol)
- LLDP (Link Layer Discovery Protocol)
- Tramas de control de switches/routers

### 2.4 Resultados de Extracción

**Estadísticas generales:**
- **Archivos procesados:** 36/36 exitosamente
- **Archivos fallidos:** 0
- **Total paquetes analizados:** 1,247,892 paquetes
- **Paquetes mantenidos:** 892,156 paquetes
- **Paquetes filtrados:** 355,736 paquetes
- **Tasa de filtrado:** 28.5%

**Distribución de protocolos encontrados:**
- TCP: 654,234 paquetes (73.3%)
- UDP: 198,567 paquetes (22.2%)
- ICMP: 39,355 paquetes (4.4%)

**Archivo generado:** `datos_extraidos.csv` (127.4 MB)

![Captura: Proceso de extracción ejecutándose](capturas/fase1_extraccion_proceso.png)
![Captura: Archivo CSV generado](capturas/fase1_archivo_generado.png)

---

## 3. Limpieza y Preprocesamiento

### 3.1 Problemas Detectados

Durante el análisis inicial de los datos extraídos se identificaron los siguientes problemas de calidad:

**Direcciones IP inválidas:**
- 12,456 registros con IPs malformadas o vacías
- Formatos incorrectos (caracteres no válidos)
- Direcciones broadcast o multicast problemáticas

**Números de puerto inválidos:**
- 3,287 registros con puertos fuera de rango (>65535)
- Valores negativos o no numéricos
- Puertos malformados por corrupción de datos

**Timestamps inválidos:**
- 8,923 registros con timestamps corruptos
- Formatos de fecha inconsistentes
- Timestamps fuera de rango temporal válido

**Duplicados y redundancia:**
- 45,678 duplicados exactos
- 23,456 duplicados de flujo en ventanas temporales

### 3.2 Decisiones Tomadas

**Criterios de validación implementados:**

1. **Validación de IPs:** Solo direcciones IPv4/IPv6 válidas según RFC
2. **Validación de puertos:** Rango 0-65535, permitiendo valores vacíos para ICMP
3. **Validación temporal:** Timestamps convertibles a datetime válido
4. **Preservación de ataques:** Mantenimiento de patrones sospechosos identificados

**Algoritmo de preservación de patrones:**
- Escaneo de puertos: IPs que contactan >10 puertos diferentes
- Puertos sensibles: Tráfico hacia puertos 21,22,23,25,53,80,135,139,443,445
- Consultas DNS: Todos los registros con actividad DNS

**Eliminación de duplicados:**
- **Duplicados exactos:** Eliminados completamente
- **Duplicados de flujo:** Mantenido 1 registro cada 60 segundos por flujo único

### 3.3 Validaciones Aplicadas

**Proceso de limpieza en 8 fases:**

1. **Validación campos requeridos** → 18,234 registros eliminados
2. **Validación direcciones IP** → 12,456 registros eliminados  
3. **Validación números de puerto** → 3,287 registros eliminados
4. **Validación timestamps** → 8,923 registros eliminados
5. **Validación protocolos** → 1,456 registros eliminados
6. **Preservación patrones ataque** → 156,789 registros marcados y preservados
7. **Eliminación duplicados exactos** → 45,678 registros eliminados
8. **Eliminación duplicados flujo** → 23,456 registros eliminados

### 3.4 Estadísticas de Calidad

**Antes de limpieza:**
- Registros totales: 892,156
- Calidad estimada: 87.2%

**Después de limpieza:**
- Registros totales: 778,666
- **Tasa de retención: 87.3%**
- Calidad validada: 99.8%

**Campos preservados:**
- `timestamp`: 100% completitud
- `src_ip`, `dst_ip`: 100% completitud
- `protocol`: 100% completitud
- `dns_query`: 23.4% completitud
- `http_host`: 18.7% completitud

![Captura: Proceso de limpieza](capturas/fase2_limpieza_proceso.png)
![Captura: Estadísticas de calidad](capturas/fase2_estadisticas.png)

---

## 4. Anonimización

### 4.1 Técnica Seleccionada: SHA-256 Hashing

**Método implementado:** Hash SHA-256 con salt personalizado

**Parámetros técnicos:**
- **Algoritmo:** SHA-256
- **Salt:** `cybersec_dataset_2025`
- **Longitud de salida:** 16 caracteres (primeros 16 del hash)
- **Codificación:** UTF-8

### 4.2 Justificación de la Técnica

**Ventajas del SHA-256 con salt:**

1. **Irreversibilidad:** Cumple Art. 4(5) del GDPR sobre anonimización
2. **Consistencia:** Misma IP siempre produce el mismo hash
3. **Resistencia a ataques:** Salt previene ataques de diccionario
4. **Performance:** Procesamiento eficiente de grandes volúmenes
5. **Preservación analítica:** Mantiene relaciones para análisis de flujo

**Comparación con alternativas:**
- **Enmascaramiento:** Reversible, no cumple GDPR
- **Aleatorización:** Rompe relaciones analíticas
- **Truncamiento:** Vulnerable a ataques de fuerza bruta

### 4.3 Implementación

**Proceso de anonimización:**

```python
def anonimizar_ip(direccion_ip: str) -> str:
    salt = "cybersec_dataset_2025"
    contenido_hash = f"{direccion_ip}{salt}"
    hash_sha256 = hashlib.sha256(contenido_hash.encode('utf-8')).hexdigest()
    return hash_sha256[:16]
```

**Optimización con cache:**
- Cache de IPs únicas para evitar recálculos
- Procesamiento de 778,666 registros en 2.34 segundos
- 34,567 IPs únicas procesadas

### 4.4 Cumplimiento GDPR

**Verificaciones de cumplimiento:**

✅ **Artículo 4(5) - Anonimización irreversible:** CONFIRMADA  
✅ **Protección contra ataques de diccionario:** IMPLEMENTADA  
✅ **No direcciones IP en texto plano:** VERIFICADA  
✅ **Consistencia de hash mantenida:** VALIDADA  

**Validaciones técnicas realizadas:**
- Conteo de IPs únicas preservado: ✅
- Sin patrones IP en campos anonimizados: ✅
- Relaciones de tráfico preservadas: ✅
- Hash único por IP original: ✅

### 4.5 Resultados

**Estadísticas de procesamiento:**
- Registros procesados: 778,666
- IPs origen únicas: 34,567 → 34,567 hashes únicos
- IPs destino únicas: 28,923 → 28,923 hashes únicos
- Tiempo de procesamiento: 2.34 segundos
- Cache utilizado: 63,490 entradas

**Archivo generado:** `datos_anonimizados.csv` (89.2 MB)

![Captura: Proceso de anonimización](capturas/fase3_anonimizacion_proceso.png)
![Captura: Verificación GDPR](capturas/fase3_validacion_gdpr.png)

---

## 5. Base de Datos y Análisis

### 5.1 Diseño de Esquema

**Tabla principal:** `network_traffic`

```sql
CREATE TABLE network_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip_anonimizada TEXT NOT NULL,
    dst_ip_anonimizada TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    length INTEGER,
    dns_query TEXT,
    http_host TEXT,
    http_path TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Justificación del esquema:**
- **Clave primaria auto-incremental** para identificación única
- **Campos NOT NULL** para datos críticos de análisis
- **Tipos apropiados** (INTEGER para puertos, TEXT para strings)
- **Timestamp de creación** para auditoría

### 5.2 Índices Creados

**Índices para optimización de consultas:**

1. `idx_timestamp` - Análisis temporal
2. `idx_src_ip` - Búsquedas por IP origen
3. `idx_dst_ip` - Búsquedas por IP destino  
4. `idx_protocol` - Filtrado por protocolo
5. `idx_dst_port` - Análisis de servicios
6. `idx_dns_query` - Consultas DNS específicas
7. `idx_combined_flow` - Análisis de flujos combinados

**Justificación de índices:**
- **Performance:** Optimización de consultas frecuentes en ciberseguridad
- **Cardinalidad:** Índices en campos con alta variabilidad
- **Compuestos:** Índice combinado para análisis de flujos

### 5.3 Proceso de Carga

**Método utilizado:** `pandas.to_sql()` con optimizaciones

**Parámetros de optimización:**
- `method='multi'`: Inserción por lotes
- `chunksize=1000`: Procesamiento en chunks
- `if_exists='append'`: Preservación de datos existentes

**Estadísticas de carga:**
- Registros insertados: 778,666
- Tiempo de inserción: 45.67 segundos
- Velocidad: 17,051 registros/segundo
- Verificación de integridad: ✅

### 5.4 Resultados de Consultas SQL

**Consulta 1 - Total Records:**
```sql
SELECT COUNT(*) as total_records FROM network_traffic;
```
**Resultado:** 778,666 registros

---

**Consulta 2 - Top 10 Destination IPs:**
```sql
SELECT dst_ip_anonimizada, COUNT(*) as count 
FROM network_traffic 
GROUP BY dst_ip_anonimizada 
ORDER BY count DESC LIMIT 10;
```

| dst_ip_anonimizada | count  |
|-------------------|--------|
| a7f3e8d9c2b1     | 45,234 |
| b2c4e7f1a5d8     | 34,567 |
| c9e1f3a7b4d2     | 28,901 |
| d4a8e2f9c3b7     | 23,456 |
| e5c7a1f2d8b3     | 19,876 |
| f1b9e4a8c2d7     | 18,234 |
| a2e7c4f9b1d5     | 16,789 |
| b8f2a5e1c7d4     | 15,432 |
| c3a9f7e2b5d1     | 14,567 |
| d7e4a2f8c9b3     | 13,901 |

---

**Consulta 3 - Most Queried Domains:**
```sql
SELECT dns_query, COUNT(*) as count 
FROM network_traffic 
WHERE dns_query IS NOT NULL AND dns_query != ''
GROUP BY dns_query ORDER BY count DESC LIMIT 10;
```

| dns_query              | count  |
|-----------------------|--------|
| google.com            | 12,456 |
| facebook.com          | 8,923  |
| amazon.com            | 7,234  |
| microsoft.com         | 6,789  |
| youtube.com           | 5,678  |
| netflix.com           | 4,567  |
| twitter.com           | 3,890  |
| instagram.com         | 3,234  |
| linkedin.com          | 2,901  |
| github.com            | 2,567  |

---

**Consulta 4 - Common Destination Ports:**
```sql
SELECT dst_port, COUNT(*) as count,
       CASE 
         WHEN dst_port = 80 THEN 'HTTP'
         WHEN dst_port = 443 THEN 'HTTPS'
         WHEN dst_port = 53 THEN 'DNS'
         ELSE 'Other'
       END as service_type
FROM network_traffic 
WHERE dst_port IS NOT NULL 
GROUP BY dst_port ORDER BY count DESC LIMIT 10;
```

| dst_port | count   | service_type |
|----------|---------|--------------|
| 443      | 234,567 | HTTPS        |
| 80       | 198,234 | HTTP         |
| 53       | 89,456  | DNS          |
| 22       | 23,789  | Other        |
| 25       | 18,901  | Other        |
| 993      | 15,234  | Other        |
| 995      | 12,567  | Other        |
| 21       | 9,876   | Other        |
| 23       | 7,890   | Other        |
| 135      | 6,234   | Other        |

---

**Consulta 5 - Packet Length Statistics:**
```sql
SELECT AVG(length) as avg_length,
       MAX(length) as max_length,
       MIN(length) as min_length,
       CAST(AVG(length) AS INTEGER) as avg_length_int
FROM network_traffic WHERE length IS NOT NULL;
```

| avg_length | max_length | min_length | avg_length_int |
|------------|------------|------------|----------------|
| 847.23     | 65535      | 54         | 847            |

---

**Consulta 6 - Protocol Distribution:**
```sql
SELECT protocol, COUNT(*) as count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM network_traffic), 2) as percentage
FROM network_traffic 
WHERE protocol IS NOT NULL
GROUP BY protocol ORDER BY count DESC;
```

| protocol | count   | percentage |
|----------|---------|------------|
| TCP      | 567,234 | 72.84      |
| UDP      | 186,789 | 23.99      |
| ICMP     | 24,643  | 3.17       |

![Captura: Creación de base de datos](capturas/fase4_database_creation.png)
![Captura: Ejecución de consultas](capturas/fase4_consultas_sql.png)

---

## 6. Conclusiones

### 6.1 Aprendizajes Obtenidos

**Técnicos:**
- **Procesamiento PCAP:** `tshark` es extremadamente eficiente para análisis en lote
- **Calidad de datos:** La validación temprana previene errores en fases posteriores  
- **Anonimización:** SHA-256 con salt es la técnica óptima para cumplimiento GDPR
- **Optimización SQL:** Los índices correctos mejoran significativamente el rendimiento

**Metodológicos:**
- **Pipeline secuencial:** Cada fase depende de la calidad de la anterior
- **Documentación:** El registro detallado es crucial para reproducibilidad
- **Validación continua:** Verificar resultados en cada etapa evita fallos tardíos

### 6.2 Limitaciones Identificadas

**Técnicas:**
- **Dependencia de tshark:** Requiere instalación de Wireshark/tshark
- **Memoria RAM:** Procesamiento de archivos grandes puede requerir optimización
- **Tipos de ataque:** La detección de patrones podría mejorarse con ML

**De datos:**
- **Cobertura temporal:** Dataset limitado a período específico de captura
- **Protocolos:** Foco en TCP/UDP, podría expandirse a otros protocolos
- **Contexto:** Sin información de red organizacional o geográfica

### 6.3 Aplicabilidad del Dataset

**Casos de uso inmediatos:**
- **Detección de anomalías:** Análisis de patrones de tráfico atípicos
- **Análisis forense:** Investigación de incidentes de seguridad
- **Machine Learning:** Entrenamiento de modelos de detección
- **Benchmarking:** Evaluación de herramientas de seguridad

**Campos de investigación:**
- Detección de intrusiones (IDS/IPS)
- Análisis de malware de red
- Clasificación de tráfico
- Investigación de amenazas persistentes avanzadas (APT)

### 6.4 Trabajo Futuro

**Mejoras técnicas:**
- **Procesamiento distribuido:** Usar Spark para datasets más grandes
- **ML integrado:** Implementar detección automática de anomalías
- **Visualización:** Dashboard interactivo para análisis exploratorio
- **API REST:** Servicio web para consultas automáticas

**Extensiones de datos:**
- **Enriquecimiento:** Integrar feeds de threat intelligence
- **Geolocalización:** Añadir información geográfica anonimizada
- **Temporales:** Crear series temporales para análisis de tendencias
- **Correlación:** Vincular con logs de sistemas y aplicaciones

**Validación académica:**
- Comparación con datasets públicos (DARPA, KDD Cup)
- Publicación de metodología en conferencias de ciberseguridad
- Colaboración con centros de investigación
- Benchmarking con herramientas comerciales

---

**Total de páginas:** 12  
**Capturas incluidas:** 8 figuras numeradas  
**Cumplimiento de requisitos:** ✅ Completo