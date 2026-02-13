import pyotp
import qrcode
from io import BytesIO
from django.core.files.base import ContentFile
import secrets
from .models import MFABackupCodes

def generate_totp_uri(user,secret):
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(
        name=user.username,
        issuer_name='MyMFAApp'
    )

def generate_backup_codes(user):
    codes = []
    for _ in range(10):
        c = secrets.token_hex(4)
        MFABackupCodes.objects.create(user=user,code = c)
        codes.append(c)
    return codes