from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from .models import UserMFA, MFAAuditLog, MFABackupCodes
from .utils import generate_totp_uri, generate_backup_codes
import qrcode
import base64
from io import BytesIO
import pyotp
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import LoginSerializer
from rest_framework import status
from datetime import timedelta
from django.utils import timezone


def get_client_ip(request):
    x = request.META.get("HTTP_X_FORWARDED_FOR")
    if x:
        return x.split(",")[0]
    return request.META.get("REMOTE_ADDR")

class MFASetupView(APIView):
    def get(self,request):
        mfa = get_object_or_404(UserMFA,user=request.user)
        uri = generate_totp_uri(request.user,mfa.totp_secret)

        qr = qrcode.make(uri)
        buffer = BytesIO()
        qr.save(buffer,format="PNG")

        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        return Response({
            "qr_code":qr_base64
        })
    
class MFAVerifyView(APIView):

    permission_classes = [IsAuthenticated]

    def post(self,request):
        code = request.data.get('otp')
        if not code:
            return Response({"error":"OTP required"},status=status.HTTP_400_BAD_REQUEST)
        
        mfa = UserMFA.objects.get(user=request.user)
        totp = pyotp.TOTP(mfa.totp_secret)

        if totp.verify(code,valid_window=1):
            mfa.is_mfa_enabled = True
            mfa.save()
            codes = generate_backup_codes(request.user)
            return Response({"status":"MFA enabled","backup_codes":codes})
        
        return Response({"error":"Invalid code"},status=400)
    
class MFALoginVerifyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self,request):
        code = request.data.get("otp")
        if not code:
            return Response({"error":"OTP required"},status=400)
        
        user = request.user

        mfa = UserMFA.objects.get(user=user)


        # here we check the lock 
        if mfa.otp_locked_until and timezone.now() < mfa.otp_locked_until:
            return Response(
                {"error": "OTP locked. Try after 5 minutes"},
                status=403
            )
        totp = pyotp.TOTP(mfa.totp_secret)

        backup = MFABackupCodes.objects.filter(
            user=user,
            code=code,
            used=False
        ).first()
        if backup:
            backup.used = True
            backup.save()
            otp_valid = True
        else:
            otp_valid = totp.verify(code,valid_window=1)

        if not otp_valid:
        
            mfa.otp_fail_count += 1

            if mfa.otp_fail_count >= 5:
                mfa.otp_locked_until = timezone.now() + timedelta(minutes=5)
                mfa.otp_fail_count = 0

            mfa.save()

            MFAAuditLog.objects.create(
                user=user,
                ip=get_client_ip(request),
                success = False
            )


            return Response({"error": "Invalid OTP"}, status=401)


        mfa.otp_fail_count = 0
        mfa.save()

        token = request.auth

        if "mfa" not in token.payload:  #safer version
            return Response({"error":"Not mfa temp token"},status=403)
        
        MFAAuditLog.objects.create(
            user=user,
            ip=get_client_ip(request),
            success = True
        )
        refresh = RefreshToken.for_user(user)

        return Response({
            "login":"success",
            "refresh":str(refresh),
            "access":str(refresh.access_token)
        })
        


class LoginView(APIView):
    
    def post(self,request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        user = authenticate(username=username,password=password)

        if not user:
            return Response({"error":"Invalid credentials"},status=status.HTTP_401_UNAUTHORIZED)
        
        mfa, _ = UserMFA.objects.get_or_create(user=user) 
        
        if (user.is_superuser or user.is_staff) and not mfa.is_mfa_enabled:
            return Response({"error":"Admin must enable mfa first"},status=status.HTTP_403_FORBIDDEN)
        


        if mfa.is_mfa_enabled:
            
            temp_token = AccessToken.for_user(user) # its not a final login token, we only use it for mfa verify
            temp_token['mfa'] = True
            temp_token.set_exp(lifetime=timedelta(minutes=4))
            return Response({
                "mfa_required":True,
                "temp_token":str(temp_token)
            })
 
        refresh = RefreshToken.for_user(user)
        return Response({"refresh":str(refresh),"access":str(refresh.access_token)})
        

class TestAuthView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request):
        return Response({"msg":"You are authenticated"})
    

