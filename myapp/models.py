from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator


# Create your models here.

class User(AbstractUser):
    role = models.IntegerField(default=0, null=False)
    def __str__(self):
        return self.username


class FileUpload(models.Model):
    title = models.CharField(max_length=50, null=False, blank=False, default="")
    name = models.FileField(upload_to="uploads/", null=False, blank=False, default=None, validators=[FileExtensionValidator(allowed_extensions=['pptx', 'docx', 'xlsx'])])

    def __str__(self):
        return f"{self.title:10}-{self.name:10}"

    