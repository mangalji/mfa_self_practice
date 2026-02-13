from django.db import models
from django.contrib.auth.models import User

class UserMFA(models.Model):
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    totp_secret = models.CharField(max_length=100)
    is_mfa_enabled = models.BooleanField(default=False)
    otp_fail_count = models.IntegerField(default=0)
    otp_locked_until = models.DateTimeField(null=True,blank=True)

    def __str__(self):
        return self.user.username
    
class MFAAuditLog(models.Model):
    user  = models.ForeignKey(User,on_delete=models.CASCADE)
    ip = models.GenericIPAddressField()
    success = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)


class MFABackupCodes(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    code = models.CharField(max_length=100)
    used = models.BooleanField(default=False)