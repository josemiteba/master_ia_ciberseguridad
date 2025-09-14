# Fase 1: Extracción de Datos PCAP

## 🎯 **Objetivo**
Extraer datos estructurados de archivos PCAP reales de malware desde `pcaps/pcaps_eval/`, filtrando ruido de red y enfocándose en tráfico relevante para ciberseguridad.

## 📂 **Ubicación de Archivos**
- **Archivos PCAP origen**: `pcaps/pcaps_eval/*.pcapng`
- **Archivo de salida**: `datos_extraidos.csv` (en directorio raíz del proyecto)
- **Log de proceso**: `extraccion_log.txt`

## 🤖 **Agente Principal**
```
Use pcap-analyst to extract network traffic data from PCAP files in pcaps/pcaps_eval/ directory
```

## 📊 **Campos Requeridos**
Extraer EXACTAMENTE estos campos (no más, no menos):
```
timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length, dns_query, http_host, http_path, user_agent
```

## 🛠️ **Tecnología**
- **Herramienta primaria**: `tshark` (línea de comandos de Wireshark)
- **Formato de salida**: CSV con cabeceras
- **Librería Python**: `subprocess` para ejecutar tshark

## ⚡ **Comando tshark Adaptado**
```python
import subprocess
import os
import glob

# Buscar todos los archivos .pcapng en pcaps/pcaps_eval/
pcap_files = glob.glob("pcaps/pcaps_eval/*.pcapng")

for pcap_file in pcap_files:
    base_name = os.path.basename(pcap_file).replace('.pcapng', '')
    output_file = f"datos_raw_{base_name}.csv"
    
    cmd = [
        'tshark', '-r', pcap_file, '-T', 'fields',
        '-e', 'frame.time',
        '-e', 'ip.src', '-e', 'ip.dst', '-e', 'ip.proto',
        '-e', 'tcp.srcport', '-e', 'tcp.dstport',
        '-e', 'udp.srcport', '-e', 'udp.dstport',
        '-e', 'frame.len', '-e', 'dns.qry.name',
        '-e', 'http.host', '-e', 'http.request.uri',
        '-e', 'http.user_agent',
        '-E', 'header=y', '-E', 'separator=,', '-E', 'occurrence=f'
    ]
    
    with open(output_file, 'w') as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)
```

## 🚫 **Filtrado de Ruido**
Eliminar estos protocolos NO relevantes para análisis de malware:
- ARP (Address Resolution Protocol)
- SSDP (Simple Service Discovery Protocol) 
- LLMNR (Link-Local Multicast Name Resolution)
- MDNS (Multicast DNS)
- DHCP
- ICMPv6

## ✅ **Mantener Tráfico**
SOLO conservar:
- HTTP/HTTPS (puertos 80, 443, 8080, 8443)
- DNS (puerto 53)
- TCP/UDP con puertos no estándar (posible C2)
- Cualquier tráfico hacia IPs externas

## 📋 **Entregable**
- Archivo consolidado `datos_extraidos.csv` (combinando todos los PCAPs)
- Archivo `extraccion_log.txt` con estadísticas por cada PCAP procesado
- Validación de que todos los campos obligatorios están presentes

## 🔍 **Validación**
```python
# Verificar que el CSV tiene las columnas correctas
required_columns = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 
                   'src_port', 'dst_port', 'length', 'dns_query', 
                   'http_host', 'http_path', 'user_agent']

import pandas as pd
df = pd.read_csv('datos_extraidos.csv')
assert all(col in df.columns for col in required_columns)
print(f"✅ Todos los campos requeridos presentes")
print(f"📊 Total registros extraídos: {len(df)}")
```

## ⏱️ **Tiempo Estimado**: 15-20 minutos