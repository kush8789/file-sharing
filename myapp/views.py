from django.shortcuts import render
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_str
from .models import User, FileUpload
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.contrib import messages
from .tokens import account_activation_token
import threading
from rest_framework.views import APIView
from .serializers import (
    LoginSerializer,
    SignupSerializer,
    FileSerializer,
)
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import permission_classes, authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from django.urls import reverse
from .tokens import download_url_token


def Home(request):
    return render(request, "home.html")


def LoginUser(request):
    if request.user.is_authenticated:
        messages.warning(
            request,
            "You're already loggedin!",
            extra_tags="alert alert-warning alert-dismissible fade show",
        )
        return redirect("myapp:home")
    return render(request, "login.html")


def LogoutUser(request):
    if request.user.is_authenticated:
        logout(request)
        return redirect("myapp:home")
    return redirect("myapp:home")


def UserSignup(request):
    # If loggedin->Home
    if request.user.is_authenticated:
        messages.warning(
            request,
            "You're already loggedin!",
            extra_tags="alert alert-warning alert-dismissible fade show",
        )
        return redirect("myapp:home")
    return render(request, "signup.html")


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(id=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    try:
        if myuser is not None and account_activation_token.check_token(myuser, token):
            myuser.is_active = True
            myuser.save()
            login(request, myuser)
            messages.success(
                request,
                "Account activated successfully!!",
                extra_tags="alert alert-success alert-dismissible fade show",
            )
            return redirect("myapp:home")
        else:
            messages.error(
                request,
                " Activation failed, Please try again!",
                extra_tags="alert alert-warning alert-dismissible fade show",
            )
            return redirect("myapp:signup")
    except Exception as e:
        messages.error(
            request,
            "Some error occured, please try again!!",
            extra_tags="alert alert-danger alert-dismissible fade show",
        )
        print(e)


class UserLoginView(APIView):
    @authentication_classes([])
    @permission_classes([AllowAny])
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data["username"]
            # print(username)
            password = serializer.validated_data["password"]
            # print(password)
            user = authenticate(username=username, password=password)
            # print(user)
            if user:
                login(request, user)
                return Response({"message": "success"}, status=status.HTTP_200_OK)
            else:
                messages.warning(
                    request,
                    "Please enter correct credential details.",
                    extra_tags="alert alert-warning alert-dismissible fade show",
                )
                return Response(
                    {"error": "Invalid credentials"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        else:
            print(serializer.error_messages)
            messages.error(
                request,
                "Some error occured, please try again!",
                extra_tags="alert alert-danger alert-dismissible fade show",
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_serializer(self, *args, **kwargs):
        return LoginSerializer(*args, **kwargs)


class UserSignupView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = SignupSerializer(data=request.data)

        if serializer.is_valid():
            # Server-side password validation
            password = serializer.validated_data.get("password")
            password2 = serializer.validated_data.get("password2")

            if password != password2:
                messages.warning(
                    request,
                    "password and confirm password should be same!",
                    extra_tags="alert alert-warning alert-dismissible fade show",
                )
                return Response(
                    {"detail": "Passwords do not match."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = serializer.save()
            user.is_active = False
            user.save()

            messages.success(
                request,
                "Successfully registered, Please check your registered mail and verify",
                extra_tags="alert alert-success alert-dismissible fade show",
            )
            email = serializer.validated_data.get("email")
            username = serializer.validated_data.get("username")
            # print(email)
            # print(username)
            # print(user)
            # print(user.id)

            try:
                email_subject = "Confirm your email"
                email_from = settings.EMAIL_HOST_USER
                to_email = email
                current_site = get_current_site(request)
                # Render HTML content from a template
                html_content = render_to_string(
                    "email_confirmation.html",
                    {
                        "username": username,
                        "domain": current_site.domain,
                        "uid": urlsafe_base64_encode(force_bytes(user.id)),
                        "token": account_activation_token.make_token(user),
                    },
                )
                # Create the plaintext version of the email
                text_content = strip_tags(html_content)
                # Create the email object
                email = EmailMultiAlternatives(
                    email_subject,
                    text_content,
                    email_from,
                    to=[to_email],
                )
                # Attach the HTML content to the email
                email.attach_alternative(html_content, "text/html")
                # Send email
                email.send()
            except Exception as e:
                # print(e)
                messages.error(
                    request,
                    "Some error occured.",
                    extra_tags="alert alert-danger alert-dismissible fade show",
                )
                print("Some error occured")

            return Response({"user_id": user.id}, status=status.HTTP_201_CREATED)
        else:
            messages.error(
                request,
                "Some error occured.",
                extra_tags="alert alert-danger alert-dismissible fade show",
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_serializer(self, *args, **kwargs):
        return SignupSerializer(*args, **kwargs)


def UploadFile(request):
    if request.user.is_authenticated:
        if request.user.role == 1:
            return render(request, "uploadfile.html")
        else:
            # messages.warning(
            #     request,
            #     "You're not authorized to upload file.",
            #     extra_tags="alert alert-warning alert-dismissible fade show",
            # )
            return redirect("myapp:home")
    else:
        messages.warning(
            request,
            "Login to upload files.",
            extra_tags="alert alert-warning alert-dismissible fade show",
        )
        return redirect("myapp:login")


class FileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def get(self, request, *args, **kwargs):
        serializer = self.get_serializer()
        return Response(serializer.data)

    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated and request.user.role == 1:
            serializer = FileSerializer(data=request.data)

            if serializer.is_valid():
                serializer.save()
                messages.success(
                    request,
                    "File uploaded successfully",
                    extra_tags="alert alert-success alert-dismissible fade show",
                )
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                messages.warning(
                    request,
                    serializer.error_messages,
                    extra_tags="alert alert-warning alert-dismissible fade show",
                )
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        elif request.user.is_authenticated:
            redirect_url = reverse("myapp:home")
            return Response(
                {
                    "detail": "Authentication failed. Redirecting...",
                    "redirect_url": redirect_url,
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        else:
            messages.warning(
                request,
                "Login to upload files.",
                extra_tags="alert alert-warning alert-dismissible fade show",
            )
            redirect_url = reverse("myapp:login")
            return Response(
                {
                    "detail": "Authentication failed. Redirecting...",
                    "redirect_url": redirect_url,
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

    def get_serializer(self):
        return FileSerializer()


# class FileDownloadView(APIView):
#     def get(self, request, file_id):
#         file_object = get_object_or_404(FileUpload, id=file_id)


#         file_path = file_object.name.path
#         with open(file_path, 'rb') as file:
#             response = HttpResponse(file.read(), content_type='application/octet-stream')
#             response['Content-Disposition'] = f'attachment; filename="{file_object.name.name}"'
#             return response


# class FileDownloadView(APIView):
#     def get(self, request, file_id, token):
#         # Validate the token
#         user = request.user
#         file_object = get_object_or_404(FileUpload, id=file_id)

#         if download_url_token.check_token(user, file_id, token):
#             # Provide the file for download
#             file_path = file_object.file.path
#             with open(file_path, "rb") as file:
#                 response = HttpResponse(
#                     file.read(), content_type="application/octet-stream"
#                 )
#                 response["Content-Disposition"] = (
#                     f"attachment; filename={file_object.name}"
#                 )
#                 return response
#         else:
#             return HttpResponse("Invalid token", status=400)


class FileListView(APIView):
    # authentication_classes = [TokenAuthentication]
    # permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            files = FileUpload.objects.all()
            serializer = FileSerializer(files, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(
                {"message": "login to access files"},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class DownloadTokenGenerateView(APIView):
    def get(self, request, file_id):
        user = request.user
        file_object = get_object_or_404(FileUpload, id=file_id)

        # Generate download token
        user_id = user.pk if user else None
        token = download_url_token.make_token((user_id, file_id))
        return Response({"token": token})


class FileDownloadView(APIView):
    def get(self, request, file_id, token):
        # Validate the token
        user = request.user
        file_object = get_object_or_404(FileUpload, id=file_id)

        # Extract user_id and file_id from token
        try:
            decoded_token = download_url_token.check_token((user, file_id), token)
            print(decoded_token)
            user_id, decoded_file_id = decoded_token[:2]
        except:
            return HttpResponse("Invalid", status=400)

        # Ensure that the decoded file_id matches the requested file_id
        if decoded_file_id != file_id:
            return HttpResponse("Invalid token", status=400)

        # Ensure that the user matches the decoded user_id
        if user and user.pk != user_id:
            return HttpResponse("Invalid token", status=400)

        # Provide the file for download
        file_path = file_object.file.path
        with open(file_path, "rb") as file:
            response = HttpResponse(
                file.read(), content_type="application/octet-stream"
            )
            response["Content-Disposition"] = f"attachment; filename={file_object.name}"
            return response
