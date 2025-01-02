import hashlib
from rest_framework import status
from django.db import transaction
from .utils import send_code_to_user
from rest_framework import exceptions
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from django.utils.http import urlsafe_base64_decode
from rest_framework.permissions import IsAuthenticated
from .models import OneTimePassword, User, PasswordResetToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from .serilaizers import (
    UserRegisterSerializer, 
    LoginSerializer, 
    PasswordResetRequestSerializer, 
    SetNewPasswordSerializer, 
    LogoutSerializer,
)


# Create your views here.
class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    @transaction.atomic
    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)

        if serializer.is_valid(raise_exception=True):
            try:
                user = serializer.save()   # Save user to the database
                
                # send email function to user['email']
                try:
                    send_code_to_user(user.email)  # Pass the user's email address
                except Exception as e:
                    transaction.set_rollback(True)
                    # If email sending fails, raise an exception to rollback the transaction
                    raise Exception(f"Error sending email: {str(e)}")

                # If everything is successful, return the response
                return Response(
                    {
                        "data": serializer.data,
                        "message": f"Hi, {user.first_name}. Thanks for signing up a passcode has been sent ",
                    },
                    status=status.HTTP_201_CREATED,
                )
            except Exception as e:
                
                raise exceptions.ValidationError(
                    {"message": "An error occurred while saving and sending email. Try again."}
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyUserEmail(GenericAPIView):

    def post(self, request, otpcode):

        try:
            user_code_obj = OneTimePassword.objects.get(code=otpcode)
            
            # Check if the code is expired
            if user_code_obj.is_expired():  # Now using 15 minutes as expiration time
                user_code_obj.delete()  # Delete expired code
                return Response(
                    {"message": "This code has expired. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            
            user = user_code_obj.user
            if not user.is_verified:
                user.is_verified = True
                user.save()

                # delete the otp code after being verified
                user_code_obj.delete()

                return Response(
                    {"message": "Account email verified successfully"},
                    status=status.HTTP_200_OK,
                )
            return Response(
                {"message": "User is already verified"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        except OneTimePassword.DoesNotExist:
            return Response(
                {"message": "Passcode does not exist"}, status=status.HTTP_404_NOT_FOUND
            )


class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TestAuthenticationView(GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        data = {
            "message": "Hello, authenticated user!"
        }

        return Response(data, status=status.HTTP_200_OK)
    


class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request": request.data})
        serializer.is_valid(raise_exception=True)

        return Response({
            "message": "If an account with this email exists, a password reset email has been sent."
        }, status=status.HTTP_200_OK)
    

class PasswordResetConfirm(GenericAPIView):

    def get(self, request, uidb64, token):
        try:
            # Decode the UID
            user_id = smart_str(urlsafe_base64_decode(uidb64))

            # Ensure the user ID is numeric
            if not user_id.isdigit():
                return Response({"message": "Invalid user ID in the reset link."}, status=status.HTTP_400_BAD_REQUEST)
            
            # Retrieve the user
            user = User.objects.get(id=user_id)

            # Hash the received token
            hashed_token = hashlib.sha256(token.encode()).hexdigest()
            
            # Validate the hashed token against the database
            try:
                reset_token = PasswordResetToken.objects.get(user=user)
                if reset_token.token != hashed_token:
                    return Response(
                        {"message": "Password reset link is invalid or has expired and not found. Please request a new one."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except PasswordResetToken.DoesNotExist:
                return Response(
                    {"message": "Password reset link is invalid or has expired and not found. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            
            # Validate the token
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({"message": "Password reset link is invalid or has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({
                "success": True,
                "message": "Valid token, please reset your password",
            }, status=status.HTTP_200_OK)
        
        except User.DoesNotExist:
            return Response({"message": "Invalid user"}, status=status.HTTP_400_BAD_REQUEST)
        
        except (DjangoUnicodeDecodeError, ValueError):
            return Response({"message": "Invalid token or UID in the reset link."}, status=status.HTTP_400_BAD_REQUEST)
        

class SetNewPassword(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"message": "Your password has been reset. You can now log in with your new password."}, status=status.HTTP_200_OK)


class LogoutView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
