# Fase 2: Limpieza y Preprocesamiento

## 🎯 **Objetivo**
Limpiar los datos extraídos eliminando duplicados, manejando valores nulos y detectando outliers, preservando señales de ataques legítimos.

## 🤖 **Agente Principal**
```
Use cybersecurity-data-cleaner to clean and preprocess the extracted network traffic data
```

## 🧹 **Tareas de Limpieza**

### 1. **Valores Nulos y Vacíos**
- **IPs malformadas**: Eliminar registros con IPs inválidas
- **Timestamps faltantes**: Eliminar registros sin tiempo
- **Puertos vacíos**: Rellenar con 0 o mantener NULL
- **Campos opcionales**: dns_query, http_host, http_path, user_agent pueden ser NULL

### 2. **Validación de Formatos**
```python
# Validar IPs
import ipaddress
def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except:
        return False

# Validar puertos (0-65535)
def validate_port(port):
    return 0 <= int(port) <= 65535 if port else True
```

### 3. **Detección de Outliers**
**IMPORTANTE**: En ciberseguridad, los outliers pueden ser ataques legítimos
- **Mantener**: Conexiones muy frecuentes (posible fuerza bruta)
- **Mantener**: Puertos no estándar (posible C2)
- **Mantener**: Paquetes muy grandes o muy pequeños
- **Eliminar**: Solo si son errores técnicos evidentes

### 4. **Eliminación de Duplicados**
```python
# Duplicados exactos (todas las columnas)
df = df.drop_duplicates()

# Duplicados de flujo (mismo src_ip, dst_ip, src_port, dst_port en ventana de 1 segundo)
df = df.drop_duplicates(subset=['src_ip', 'dst_ip', 'src_port', 'dst_port'], 
                       keep='first')
```

## 🛠️ **Tecnología**
- **Librería principal**: `pandas` para manipulación de datos
- **Validación**: `ipaddress` para validar IPs
- **Detección outliers**: `scipy.stats` para z-score, IQR

## ⚠️ **Reglas de Negocio**
1. **NO eliminar** tráfico sospechoso que pueda ser malware
2. **Preservar** orden cronológico de eventos
3. **Documentar** todas las decisiones de limpieza
4. **Mantener** al menos 80% de los datos originales

## 📊 **Métricas de Calidad**
```python
# Reporte de limpieza
print(f"Registros originales: {original_count}")
print(f"Registros después de limpieza: {clean_count}")
print(f"Porcentaje conservado: {clean_count/original_count*100:.1f}%")
print(f"Valores nulos por columna:")
print(df.isnull().sum())
```

## 📋 **Entregable**
- Archivo `datos_limpios.csv` con datos preprocesados
- Reporte de limpieza con estadísticas de calidad
- Log de decisiones tomadas (qué se eliminó y por qué)

## ⏱️ **Tiempo Estimado**: 10-15 minutos