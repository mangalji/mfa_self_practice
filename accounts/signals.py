from django.db.models.signals import post_save
from django.dispatch import receiver
import pyotp
from django.contrib.auth.models import User
from .models import UserMFA

@receiver(post_save,sender=User)
def create_mfa(sender,instance,created,*args, **kwargs):
    if created:
        UserMFA.objects.create(user=instance,totp_secret = pyotp.random_base32())
