# Fase 4: Creación de Base de Datos y Análisis

## 🎯 **Objetivo**
Crear una base de datos SQLite, cargar los datos anonimizados y ejecutar las consultas de análisis requeridas.

## 🤖 **Agente Principal**
```
Use sql-database-creator to create database schema, load data, and execute analytical queries for cybersecurity traffic analysis
```

## 🗄️ **Esquema de Base de Datos**

### **Tabla: network_traffic**
```sql
CREATE TABLE network_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    src_ip_anon TEXT NOT NULL,
    dst_ip_anon TEXT NOT NULL, 
    protocol TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    length INTEGER NOT NULL,
    dns_query TEXT,
    http_host TEXT,
    http_path TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Índices para performance
CREATE INDEX idx_timestamp ON network_traffic(timestamp);
CREATE INDEX idx_src_ip ON network_traffic(src_ip_anon);
CREATE INDEX idx_dst_ip ON network_traffic(dst_ip_anon);
CREATE INDEX idx_protocol ON network_traffic(protocol);
CREATE INDEX idx_dst_port ON network_traffic(dst_port);
```

## 📊 **Carga de Datos**
```python
import sqlite3
import pandas as pd

# Conectar a SQLite
conn = sqlite3.connect('cybersecurity_dataset.db')

# Cargar datos desde CSV
df = pd.read_csv('datos_anonimizados.csv')

# Insertar en base de datos
df.to_sql('network_traffic', conn, if_exists='replace', index=False)

conn.close()
```

## 📈 **Consultas Obligatorias**
Ejecutar EXACTAMENTE estas 6 consultas:

### 1. **Total de Registros**
```sql
SELECT COUNT(*) as total_records FROM network_traffic;
```

### 2. **Top 10 Direcciones IP de Destino**
```sql
SELECT dst_ip_anon, COUNT(*) as count 
FROM network_traffic 
GROUP BY dst_ip_anon 
ORDER BY count DESC 
LIMIT 10;
```

### 3. **Dominios Más Consultados**
```sql
SELECT dns_query, COUNT(*) as count 
FROM network_traffic 
WHERE dns_query IS NOT NULL AND dns_query != ''
GROUP BY dns_query 
ORDER BY count DESC 
LIMIT 10;
```

### 4. **Puertos de Destino Más Comunes**
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
GROUP BY dst_port 
ORDER BY count DESC 
LIMIT 10;
```

### 5. **Estadísticas de Longitud de Paquete**
```sql
SELECT 
    AVG(length) as avg_length,
    MAX(length) as max_length,
    MIN(length) as min_length,
    CAST(AVG(length) AS INTEGER) as avg_length_int
FROM network_traffic 
WHERE length IS NOT NULL;
```

### 6. **Distribución de Protocolos**
```sql
SELECT protocol, 
       COUNT(*) as count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM network_traffic), 2) as percentage
FROM network_traffic 
WHERE protocol IS NOT NULL
GROUP BY protocol 
ORDER BY count DESC;
```

## 🛠️ **Tecnología**
- **Base de datos**: SQLite (archivo local)
- **Conexión**: `sqlite3` (librería estándar de Python)
- **Visualización**: `pandas` para mostrar resultados

## 📋 **Entregable**
- Archivo `cybersecurity_dataset.db` (base de datos SQLite)
- Archivo `resultados_consultas.txt` con salida de las 6 consultas
- Capturas de pantalla de cada consulta ejecutada

## 📊 **Formato de Resultados**
```python
# Ejecutar y guardar todas las consultas
queries = {
    "total_records": "SELECT COUNT(*) as total_records FROM network_traffic;",
    "top_dst_ips": "SELECT dst_ip_anon, COUNT(*) as count FROM network_traffic GROUP BY dst_ip_anon ORDER BY count DESC LIMIT 10;",
    # ... resto de consultas
}

results = {}
for name, query in queries.items():
    results[name] = pd.read_sql_query(query, conn)
    print(f"\n=== {name.upper()} ===")
    print(results[name].to_string(index=False))
```

## ⏱️ **Tiempo Estimado**: 10-15 minutos