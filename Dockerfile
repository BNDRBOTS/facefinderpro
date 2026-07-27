# FaceHunter PRO — reproducible, pinned, non-root deployment.
# Playwright + InsightFace need system libs; this image bundles them.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FACEHUNTER_DATA_DIR=/data/face_data \
    FACEHUNTER_SKIP_INSTALL=1

# System libraries for Playwright/Chromium and ONNXRuntime/OpenCV.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libglib2.0-0 libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
        libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
        libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 libatspi2.0-0 \
        libgl1 libglib2.0-0 fonts-liberation ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt \
    && python -m playwright install chromium

COPY . .

# Run as a non-root user; give it ownership of the data volume.
RUN useradd -m -u 10001 facehunter \
    && mkdir -p /data/face_data \
    && chown -R facehunter:facehunter /app /data
USER facehunter

EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8501/_stcore/health').read()==b'ok' else 1)" || exit 1

VOLUME ["/data/face_data"]
CMD ["streamlit", "run", "FaceFinderPRO.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
