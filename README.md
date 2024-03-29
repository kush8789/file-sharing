# File Sharing Application with Django REST Framework

## Introduction

This is a file sharing application built with Django and Django REST Framework. The application has two types of users: opsuser and clientuser. opsuser can log in, upload files, while clientuser can sign up, log in, verify email, and download files.

## Setup Instructions

### Prerequisites

- Python 3.x
- Django
- Django REST Framework

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/kush8789/file-sharing.git
    ```
2. Navigate to the project directory:
    ```bash
    cd file-sharing
    ```

3. Activate the virtual environment:
   - On Windows: ```bash venv\Scripts\activate```

   - On macOS and Linux: ```bash source venv/bin/activate```

4. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

5. Run migrations:
    ```bash
    python manage.py migrate
    ```
6. Run the development server:
    ```bash
    python manage.py runserver
    ```

The application will be accessible at `http://localhost:8000`.

## Note

- To access admin panel:
    - username: admin
    - password: Admin

- To upload files:
    - username: opsuser
    - password: Opsuser@1234

- User credential:
    - username: users
    - password: User@1234

