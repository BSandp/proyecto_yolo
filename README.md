# Guía de ejecución paso a paso

## Paso 1 — Instalar dependencias
```bash
pip install -r requirements.txt
```

## Paso 2 — Etiquetar tus imágenes
Usa Roboflow (más fácil):
1. Crea cuenta en roboflow.com
2. Sube tus imágenes (CAMARA_IP, ROUTER, FIREWALL, SWITCH)
3. Etiqueta con bounding boxes
4. Exporta en formato "YOLOv8"
5. Descarga el dataset (incluye dataset.yaml)

O usa labelImg:
```bash
pip install labelImg
labelImg ./imagenes
```
Exporta en formato YOLO.

## Paso 3 — Entrenar el modelo
```python
from ultralytics import YOLO
model = YOLO("yolov8n.pt")           # modelo base (se descarga automático)
model.train(data="dataset.yaml", epochs=50, imgsz=640)
# El modelo entrenado queda en: runs/detect/train/weights/best.pt
```
Copia best.pt a la carpeta raíz del proyecto.

## Paso 4 — Ejecutar el sistema completo
```bash
# 1. Pon tus imágenes en la carpeta ./imagenes/
# 2. Ejecuta:
python sistema_inventario.py
```

El sistema:
- Detecta activos con YOLO (o modo simulado si no hay modelo)
- Cifra cada imagen con AES-256
- Protege la clave AES con RSA (Control A.10 ISO 27001)
- Calcula SHA-256 para integridad
- Guarda todo en inventario.db

## Estructura de archivos generados
```
proyecto/
├── sistema_inventario.py   ← código principal
├── imagenes/               ← pon aquí tus imágenes
├── inventario.db           ← base de datos SQLite
├── clave_privada.pem       ← ¡NUNCA subas esto a GitHub!
├── clave_publica.pem       ← esta sí puede subirse
└── best.pt                 ← tu modelo YOLO entrenado
```

## ⚠️ Importante para GitHub
Agrega al .gitignore:
```
clave_privada.pem
inventario.db
*.pt
```
