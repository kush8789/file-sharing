from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type
import secrets


class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            text_type(user.pk) + text_type(timestamp) +
            text_type(user.is_active)
        )

account_activation_token = TokenGenerator()


class DownloadUrlTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user_and_file_id, timestamp):
        user_id, file_id = user_and_file_id
        return (
            text_type(user_id) + text_type(file_id) + text_type(timestamp)
        )

download_url_token = DownloadUrlTokenGenerator()
