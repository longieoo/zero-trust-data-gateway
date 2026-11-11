FROM python:3.12.10-slim
WORKDIR /project
COPY requirements-lock.txt .
RUN pip install --no-cache-dir -r requirements-lock.txt
COPY . .
RUN pip install --no-cache-dir --no-deps .
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
