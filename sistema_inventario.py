"""
Sistema de Inventario Visual y Auditoría de Seguridad - Módulos 1 y 2
Telecomunicaciones - ISO 27001

Flujo:
  1. Lee imágenes de una carpeta
  2. Detecta activos con YOLO (o modo simulado si no hay modelo entrenado)
  3. Cifra la imagen con AES-256
  4. Protege la clave AES con RSA (cifrado híbrido)
  5. Calcula hash SHA-256 para integridad
  6. Guarda todo en SQLite
"""

import os
import json
import hashlib
import sqlite3
import base64
from datetime import datetime
from pathlib import Path

# --- Criptografía ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# --- YOLO (solo si hay modelo entrenado) ---
try:
    from ultralytics import YOLO
    YOLO_DISPONIBLE = True
except ImportError:
    YOLO_DISPONIBLE = False
    print("[AVISO] ultralytics no instalado. Usando modo simulado.")

# ──────────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────────
CARPETA_IMAGENES = "./imagenes"       # Pon tus imágenes aquí
MODELO_YOLO      = "best.pt"          # Resultado de tu entrenamiento
DB_PATH          = "inventario.db"
CLASES = ["CAMARA_IP", "ROUTER", "FIREWALL", "SWITCH"]


# ──────────────────────────────────────────────
# MÓDULO 2A: Generación de claves RSA
# ──────────────────────────────────────────────
def generar_claves_rsa():
    """Genera par de claves RSA 2048 bits y las guarda en disco."""
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    clave_publica = clave_privada.public_key()

    with open("clave_privada.pem", "wb") as f:
        f.write(clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("clave_publica.pem", "wb") as f:
        f.write(clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("[RSA] Par de claves generado: clave_privada.pem / clave_publica.pem")
    return clave_privada, clave_publica


def cargar_claves_rsa():
    """Carga claves RSA existentes o las genera si no existen."""
    if not os.path.exists("clave_publica.pem"):
        return generar_claves_rsa()

    with open("clave_privada.pem", "rb") as f:
        privada = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    with open("clave_publica.pem", "rb") as f:
        publica = serialization.load_pem_public_key(f.read(), backend=default_backend())

    return privada, publica


# ──────────────────────────────────────────────
# MÓDULO 2B: Cifrado híbrido AES + RSA
# ──────────────────────────────────────────────
def cifrar_imagen(ruta_imagen: str, clave_publica_rsa) -> dict:
    """
    Cifra una imagen con AES-256-CBC.
    Cifra la clave AES con RSA (cifrado híbrido → Control A.10 ISO 27001).
    Calcula SHA-256 de la imagen original.
    Retorna diccionario con todo el paquete cifrado.
    """
    with open(ruta_imagen, "rb") as f:
        datos_originales = f.read()

    # 1. Hash SHA-256 para integridad
    hash_sha256 = hashlib.sha256(datos_originales).hexdigest()

    # 2. Generar clave AES aleatoria (32 bytes = 256 bits) + IV
    clave_aes = os.urandom(32)
    iv = os.urandom(16)

    # 3. Cifrar imagen con AES-256-CBC
    cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding manual para que sea múltiplo de 16
    padding_len = 16 - (len(datos_originales) % 16)
    datos_padded = datos_originales + bytes([padding_len] * padding_len)
    imagen_cifrada = encryptor.update(datos_padded) + encryptor.finalize()

    # 4. Cifrar clave AES con RSA (cifrado híbrido)
    clave_aes_cifrada = clave_publica_rsa.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "imagen_cifrada_b64": base64.b64encode(imagen_cifrada).decode(),
        "iv_b64": base64.b64encode(iv).decode(),
        "clave_aes_cifrada_b64": base64.b64encode(clave_aes_cifrada).decode(),
        "hash_sha256": hash_sha256,
        "tamaño_original_bytes": len(datos_originales)
    }


def descifrar_imagen(paquete: dict, clave_privada_rsa, ruta_salida: str):
    """
    Descifra una imagen usando la clave privada RSA para recuperar la clave AES.
    Verifica la integridad con SHA-256.
    """
    # 1. Descifrar clave AES con RSA privada
    clave_aes = clave_privada_rsa.decrypt(
        base64.b64decode(paquete["clave_aes_cifrada_b64"]),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 2. Descifrar imagen con AES
    iv = base64.b64decode(paquete["iv_b64"])
    imagen_cifrada = base64.b64decode(paquete["imagen_cifrada_b64"])

    cipher = Cipher(algorithms.AES(clave_aes), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    datos_padded = decryptor.update(imagen_cifrada) + decryptor.finalize()

    # Remover padding
    padding_len = datos_padded[-1]
    datos_originales = datos_padded[:-padding_len]

    # 3. Verificar integridad SHA-256
    hash_verificacion = hashlib.sha256(datos_originales).hexdigest()
    if hash_verificacion != paquete["hash_sha256"]:
        raise ValueError("¡ALERTA DE INTEGRIDAD! El hash no coincide. Imagen posiblemente alterada.")

    with open(ruta_salida, "wb") as f:
        f.write(datos_originales)

    print(f"[OK] Imagen descifrada y verificada: {ruta_salida}")
    return True


# ──────────────────────────────────────────────
# MÓDULO 1: Detección con YOLO
# ──────────────────────────────────────────────
def detectar_activos(ruta_imagen: str, modelo=None) -> list:
    """
    Detecta activos de telecomunicaciones en la imagen.
    Si no hay modelo entrenado, usa modo simulado para pruebas.
    """
    if modelo is not None:
        resultados = modelo(ruta_imagen)
        detecciones = []
        for r in resultados:
            for box in r.boxes:
                clase_idx = int(box.cls[0])
                confianza = float(box.conf[0])
                coords = box.xyxy[0].tolist()
                detecciones.append({
                    "clase": CLASES[clase_idx] if clase_idx < len(CLASES) else f"CLASE_{clase_idx}",
                    "confianza": round(confianza, 4),
                    "bbox": [round(c, 1) for c in coords]
                })
        return detecciones
    else:
        # Modo simulado (para cuando el modelo aún no está entrenado)
        import random
        random.seed(hash(ruta_imagen))
        n = random.randint(1, 3)
        return [
            {
                "clase": random.choice(CLASES),
                "confianza": round(random.uniform(0.75, 0.98), 4),
                "bbox": [random.randint(10,100), random.randint(10,100),
                         random.randint(200,400), random.randint(200,400)]
            }
            for _ in range(n)
        ]


# ──────────────────────────────────────────────
# BASE DE DATOS
# ──────────────────────────────────────────────
def inicializar_bd():
    """Crea la base de datos SQLite con las tablas necesarias."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_archivo TEXT NOT NULL,
            fecha_deteccion TEXT NOT NULL,
            hash_sha256 TEXT NOT NULL,
            detecciones_json TEXT NOT NULL,
            imagen_cifrada_b64 TEXT NOT NULL,
            iv_b64 TEXT NOT NULL,
            clave_aes_cifrada_b64 TEXT NOT NULL,
            tamaño_bytes INTEGER,
            estado_integridad TEXT DEFAULT 'OK'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS log_auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fecha TEXT NOT NULL,
            accion TEXT NOT NULL,
            archivo TEXT,
            resultado TEXT,
            usuario TEXT DEFAULT 'tecnico_campo'
        )
    """)

    conn.commit()
    conn.close()
    print(f"[BD] Base de datos inicializada: {DB_PATH}")


def guardar_activo(nombre_archivo: str, detecciones: list, paquete_cifrado: dict):
    """Guarda el activo detectado y cifrado en la BD."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO activos
        (nombre_archivo, fecha_deteccion, hash_sha256, detecciones_json,
         imagen_cifrada_b64, iv_b64, clave_aes_cifrada_b64, tamaño_bytes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        nombre_archivo,
        datetime.now().isoformat(),
        paquete_cifrado["hash_sha256"],
        json.dumps(detecciones, ensure_ascii=False),
        paquete_cifrado["imagen_cifrada_b64"],
        paquete_cifrado["iv_b64"],
        paquete_cifrado["clave_aes_cifrada_b64"],
        paquete_cifrado["tamaño_original_bytes"]
    ))

    # Log de auditoría (ISO 27001 - trazabilidad)
    cursor.execute("""
        INSERT INTO log_auditoria (fecha, accion, archivo, resultado)
        VALUES (?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        "DETECCION_Y_CIFRADO",
        nombre_archivo,
        f"Detectados: {len(detecciones)} activos | Hash: {paquete_cifrado['hash_sha256'][:16]}..."
    ))

    conn.commit()
    conn.close()


def listar_inventario():
    """Muestra todos los activos registrados en la BD."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, nombre_archivo, fecha_deteccion, hash_sha256, detecciones_json, tamaño_bytes FROM activos ORDER BY id DESC")
    filas = cursor.fetchall()
    conn.close()

    print("\n" + "="*70)
    print(f"{'INVENTARIO DE ACTIVOS DE TELECOMUNICACIONES':^70}")
    print("="*70)
    for fila in filas:
        id_, nombre, fecha, hash_, det_json, tamaño = fila
        detecciones = json.loads(det_json)
        print(f"\n  ID: {id_} | Archivo: {nombre}")
        print(f"  Fecha: {fecha}")
        print(f"  SHA-256: {hash_}")
        print(f"  Tamaño original: {tamaño} bytes")
        print(f"  Activos detectados:")
        for d in detecciones:
            print(f"    → {d['clase']} (confianza: {d['confianza']:.0%}) | bbox: {d['bbox']}")
    print("="*70)
    return filas


# ──────────────────────────────────────────────
# PIPELINE PRINCIPAL
# ──────────────────────────────────────────────
def procesar_imagen(ruta_imagen: str, clave_publica, modelo=None):
    """Pipeline completo para una imagen: detectar → cifrar → guardar."""
    nombre = Path(ruta_imagen).name
    print(f"\n[PROCESANDO] {nombre}")

    # Paso 1: Detectar activos
    print("  → Detectando activos...")
    detecciones = detectar_activos(ruta_imagen, modelo)
    for d in detecciones:
        print(f"     {d['clase']} ({d['confianza']:.0%})")

    # Paso 2: Cifrar imagen (AES + RSA + SHA-256)
    print("  → Cifrando imagen (AES-256 + RSA)...")
    paquete = cifrar_imagen(ruta_imagen, clave_publica)
    print(f"     SHA-256: {paquete['hash_sha256'][:32]}...")

    # Paso 3: Guardar en BD
    print("  → Guardando en base de datos...")
    guardar_activo(nombre, detecciones, paquete)
    print(f"  [OK] {nombre} procesada y almacenada de forma segura.")

    return detecciones, paquete


def main():
    print("\n" + "="*60)
    print("  SISTEMA DE INVENTARIO VISUAL - TELECOMUNICACIONES")
    print("  ISO 27001 | AES-256 + RSA | YOLO v8")
    print("="*60)

    # Inicializar
    inicializar_bd()
    clave_privada, clave_publica = cargar_claves_rsa()

    # Cargar modelo YOLO si existe
    modelo = None
    if YOLO_DISPONIBLE and os.path.exists(MODELO_YOLO):
        print(f"[YOLO] Cargando modelo: {MODELO_YOLO}")
        modelo = YOLO(MODELO_YOLO)
    else:
        print("[YOLO] Modelo no encontrado. Usando modo simulado.")
        print("       Entrena primero con: model.train(data='dataset.yaml', epochs=50)")

    # Procesar todas las imágenes de la carpeta
    carpeta = Path(CARPETA_IMAGENES)
    if not carpeta.exists():
        carpeta.mkdir(parents=True)
        print(f"\n[AVISO] Carpeta '{CARPETA_IMAGENES}' creada. Agrega tus imágenes ahí.")
        return

    extensiones = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
    imagenes = [f for f in carpeta.iterdir() if f.suffix.lower() in extensiones]

    if not imagenes:
        print(f"\n[AVISO] No se encontraron imágenes en '{CARPETA_IMAGENES}'.")
        return

    print(f"\n[INFO] Se encontraron {len(imagenes)} imagen(es) para procesar.")

    for ruta in imagenes:
        try:
            procesar_imagen(str(ruta), clave_publica, modelo)
        except Exception as e:
            print(f"  [ERROR] {ruta.name}: {e}")

    # Mostrar inventario final
    listar_inventario()

    print("\n[LISTO] Todas las imágenes procesadas.")
    print(f"  Base de datos: {DB_PATH}")
    print(f"  Para descifrar una imagen usa: descifrar_imagen(paquete, clave_privada, 'salida.jpg')")


if __name__ == "__main__":
    main()
