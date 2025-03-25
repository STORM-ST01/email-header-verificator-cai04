import email
from email import policy
import re
from datetime import datetime
from email.parser import BytesParser

def parse_email(raw_email):
    """Parsea el correo en formato raw."""
    return BytesParser(policy=policy.default).parsebytes(raw_email.encode())

def check_spf(msg):
    """Evalúa la validez del SPF y ajusta el puntaje."""
    spf = msg.get('Received-SPF', '').lower()
    if 'pass' in spf:
        return 30
    elif 'fail' in spf:
        return -25
    return -5  # Penalización leve si no hay SPF definido

def check_dkim(msg):
    """Verifica si DKIM está presente y contiene un dominio."""
    dkim = msg.get('DKIM-Signature', '')
    return 30 if 'd=' in dkim else -10

def check_from_return_path(msg):
    """Compara los dominios de From y Return-Path."""
    from_addr = msg.get('From', '').split('@')[-1]
    return_path = msg.get('Return-Path', '').split('@')[-1]
    return 20 if from_addr == return_path else -15

def check_received_delay(msg):
    """Evalúa el retraso en los servidores intermedios analizando los Received headers."""
    received_headers = msg.get_all('Received', [])
    delays = []

    for header in received_headers:
        match = re.search(r'(\d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2})', header)
        if match:
            timestamp = datetime.strptime(match.group(1), '%d %b %Y %H:%M:%S')
            now = datetime.utcnow()
            delay = (now - timestamp).total_seconds() / 60
            delays.append(delay)

    if not delays:
        return -5  # Penalización leve si no hay timestamps detectables

    avg_delay = sum(delays) / len(delays)
    if avg_delay < 5:
        return 10
    elif avg_delay < 60:
        return 0
    return -10  # Penalizar retrasos excesivos

def check_reply_to(msg):
    """Evalúa si Reply-To coincide con From."""
    from_addr = msg.get('From', '').split('@')[-1]
    reply_to = msg.get('Reply-To', msg.get('From', '')).split('@')[-1]
    return 10 if reply_to == from_addr else -10

def analyze_email_headers(raw_email):
    """Calcula el puntaje de confianza del correo basándose en los encabezados."""
    msg = parse_email(raw_email)
    confidence = (
        check_spf(msg) +
        check_dkim(msg) +
        check_from_return_path(msg) +
        check_received_delay(msg) +
        check_reply_to(msg)
    )
    return max(0, min(100, confidence))  # Limitar entre 0 y 100

# **Ejemplo de uso**
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
