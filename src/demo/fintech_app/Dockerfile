FROM python:3.10-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn pydantic

COPY app.py .

EXPOSE 8080

CMD ["python", "app.py"]
