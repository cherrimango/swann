# SAWNN sandbox worker image: Playwright Chromium in a locked-down, disposable container.
# Status: IMPLEMENTED BUT NOT TESTED (the build environment had no Docker daemon).
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy
RUN useradd --create-home --uid 10001 sandbox
WORKDIR /opt/sawnn
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY raqeeb ./raqeeb
COPY models ./models
USER sandbox
ENV SAWNN_SANDBOX_ENABLED=true PYTHONDONTWRITEBYTECODE=1
# one URL per container run; prints the JSON evidence and exits
ENTRYPOINT ["python", "-I", "-c", "import json,sys; from raqeeb.link import sandbox; print(json.dumps(sandbox.analyse(sys.argv[1]), default=str))"]
