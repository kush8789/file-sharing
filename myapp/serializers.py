from rest_framework import serializers
from .models import User, FileUpload
from django.contrib.auth.hashers import make_password


class SignupSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "username",
            "email",
            "password",
            "password2",
        ]

    def validate(self, data):
        # Check if the passwords match
        if data["password"] != data["password2"]:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        # Remove password2 from validated_data before creating the user
        validated_data.pop("password2", None)

        # Hash the password before saving the user
        validated_data["password"] = make_password(validated_data["password"])

        return super().create(validated_data)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(style={"input_type": "password"})


class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileUpload
        fields = ["id", "title", "name"]
