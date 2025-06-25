# Gunakan Python slim (ringan)
FROM python:3.10-slim

# Install libmagic dan library sistem lain yang dibutuhkan
RUN apt-get update && apt-get install -y \
    libmagic-dev \
    gcc \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# Set direktori kerja
WORKDIR /app

# Copy semua file
COPY . .

# Install dependencies Python
RUN pip install --no-cache-dir -r requirements.txt

# Jalankan bot
CMD ["python", "start.py"]
