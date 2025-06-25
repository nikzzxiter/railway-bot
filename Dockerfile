# Gunakan base image Python resmi
FROM python:3.10-slim

# Install library OS yang dibutuhkan
RUN apt-get update && apt-get install -y \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    libmagic1 \
    libmagic-dev \
    && rm -rf /var/lib/apt/lists/*

# Atur direktori kerja
WORKDIR /app

# Copy semua file ke container
COPY . .

# Install semua module Python
RUN pip install --upgrade pip && pip install -r requirements.txt

# Jalankan file utama
CMD ["python", "start.py"]
