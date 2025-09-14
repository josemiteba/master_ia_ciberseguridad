# Fase 3: Anonimización de Datos

## 🎯 **Objetivo**
Aplicar técnicas de anonimización a direcciones IP (src_ip y dst_ip) cumpliendo con GDPR mientras se preserva la utilidad analítica para ciberseguridad.

## 🤖 **Agente Principal**
```
Use privacy-anonymizer to apply anonymization techniques to IP addresses while preserving cybersecurity analysis capability
```

## 🔒 **Técnica Requerida: Hashing SHA-256**
Aplicar hashing irreversible usando SHA-256 a las columnas src_ip y dst_ip.

### **Implementación**
```python
import hashlib
import pandas as pd

def hash_ip(ip):
    """Aplica hash SHA-256 a una IP manteniendo consistencia"""
    if pd.isna(ip) or ip == '':
        return None
    # Añadir salt para mayor seguridad
    salt = "cybersec_dataset_2025"
    return hashlib.sha256(f"{salt}{ip}".encode()).hexdigest()[:16]

# Aplicar anonimización
df['src_ip_anon'] = df['src_ip'].apply(hash_ip)
df['dst_ip_anon'] = df['dst_ip'].apply(hash_ip)
```

## 📋 **Campos a Anonimizar**
| Campo Original | Campo Anonimizado | Técnica |
|---------------|------------------|---------|
| `src_ip` | `src_ip_anon` | SHA-256 Hash (16 chars) |
| `dst_ip` | `dst_ip_anon` | SHA-256 Hash (16 chars) |

## 🚫 **Campos NO Anonimizar**
- `timestamp` - No es identificador personal
- `protocol` - Información técnica
- `src_port`, `dst_port` - No identifican personas
- `length` - Información técnica
- `dns_query`, `http_host`, `http_path` - Pueden contener IOCs valiosos
- `user_agent` - Información de análisis de malware

## ✅ **Propiedades Preservadas**
- **Consistencia**: Misma IP siempre produce el mismo hash
- **Relaciones**: Comunicaciones entre IPs se mantienen
- **Distribución**: Patrones de tráfico se conservan
- **Irreversibilidad**: No se puede recuperar IP original

## 🛠️ **Tecnología**
- **Librería**: `hashlib` (incluida en Python estándar)
- **Algoritmo**: SHA-256 con salt personalizado
- **Formato salida**: Primeros 16 caracteres del hash (suficiente para unicidad)

## 📊 **Validación**
```python
# Verificar que la anonimización fue exitosa
assert df['src_ip_anon'].nunique() == df['src_ip'].nunique()
assert df['dst_ip_anon'].nunique() == df['dst_ip'].nunique()
assert not df['src_ip_anon'].str.contains(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}').any()
```

## 📋 **Entregable**
- Archivo `datos_anonimizados.csv` con columnas IP anonimizadas
- Reporte de anonimización confirmando:
  - Número de IPs únicas antes/después
  - Verificación de que no quedan IPs en texto plano
  - Confirmación de preservación de relaciones

## ⚠️ **Consideraciones GDPR**
- Técnica cumple con Art. 4(5) - datos anonimizados
- Hash irreversible sin posibilidad de re-identificación
- Salt personalizado previene ataques de diccionario

## ⏱️ **Tiempo Estimado**: 5-10 minutos