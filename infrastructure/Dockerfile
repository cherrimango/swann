# RAQEEB server image. Includes Chromium (for deep scans) and Tesseract with English + Arabic (for screenshot OCR).
# Status: written for deployment; not built in the hackathon environment (no Docker daemon there).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-ara libgomp1 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /srv/raqeeb
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt playwright pytesseract \
    && python -m playwright install --with-deps chromium
COPY . .
RUN useradd --create-home raqeeb && mkdir -p data evidence && chown -R raqeeb data evidence
USER raqeeb
EXPOSE 8000
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000"]
