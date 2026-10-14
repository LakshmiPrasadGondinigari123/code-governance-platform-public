FROM python:3.12-slim
WORKDIR /srv
COPY serve.py .
COPY detail.html .
COPY site ./site
COPY html ./html
ENV PYTHONUNBUFFERED=1
CMD ["python", "serve.py"]
