release: python manage.py makemigrations --no-input
release: python manage.py migrate --no-input

web: gunicorn Master_GL_INSTA.wsgi