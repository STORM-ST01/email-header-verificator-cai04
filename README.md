# Email Header Verificator (cai04)

## Descripción
**Email Header Verificator (cai04)** es una herramienta en Python que analiza las cabeceras de un correo electrónico para calcular un porcentaje de confianza y ayudar en la detección de ataques de *spear phishing*.

El sistema evalúa factores clave como autenticación SPF, firma DKIM, consistencia de dominios en *From* y *Return-Path*, retrasos en los servidores intermedios y coincidencias en *Reply-To* para determinar la legitimidad del email.

---

## Instalación y Configuración
### 1. Crear un entorno virtual
Antes de ejecutar el script, se recomienda crear un entorno virtual de Python para gestionar las dependencias:

#### **Windows (CMD o PowerShell)**
```sh
python -m venv mi_entorno
mi_entorno\Scripts\activate
```

#### **Mac / Linux (Terminal)**
```sh
python3 -m venv mi_entorno
source mi_entorno/bin/activate
```

### 2. Instalar dependencias
Si cuentas con un archivo `requirements.txt`, instálalas con:
```sh
pip install -r requirements.txt
```

Si no tienes un archivo `requirements.txt`, puedes generarlo ejecutando:
```sh
pip freeze > requirements.txt
```

---

## Uso
### 1. Ejecutar el script de análisis
Guarda un correo en formato *raw* y pásalo a la función de análisis:

```python
from email_header_verificator import analyze_email_headers

raw_email = """MIME-Version: 1.0
Received-SPF: pass (domain.com)
DKIM-Signature: v=1; a=rsa-sha256; d=domain.com; s=selector
From: user@domain.com
Return-Path: user@domain.com
Reply-To: user@domain.com
Received: from mail.domain.com by server.com; Mon, 24 Mar 2025 10:00:00 +0000
Subject: Test Email"""

confidence_score = analyze_email_headers(raw_email)
print(f"Confianza: {confidence_score}% - {'Legítimo' if confidence_score >= 50 else 'Falso'}")
```

---

## Criterios de Evaluación
El script calcula el porcentaje de confianza basándose en los siguientes factores:

| **Regla**                          | **Impacto en la confianza** |
|-----------------------------------|--------------------------|
| **Validación SPF** (pass/fail)    | +30 / -25                |
| **Presencia de DKIM**             | +30 / -10                |
| **Coincidencia From/Return-Path** | +20 / -15                |
| **Retrasos en servidores (Received)** | +10 si <5 min, -10 si >60 min |
| **Coincidencia Reply-To**         | +10 / -10                |

El puntaje final se limita a un rango entre **0% y 100%**, donde valores altos indican un email más confiable.

---

## Desactivación del Entorno Virtual
Cuando termines de trabajar, puedes desactivar el entorno virtual con:
```sh
deactivate
```

---

## Contribuciones
Si deseas mejorar este proyecto, puedes hacer un *fork* y enviar un *pull request* con mejoras o reportar problemas en la sección de *Issues*.



