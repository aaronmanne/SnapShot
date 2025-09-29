# SAST Microservice Dockerfile
FROM python:3.9-slim

# Install git for semgrep rules
RUN apt-get update && apt-get install -y git curl git && apt-get clean

# Create app directory
WORKDIR /app

# Install app dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bundle app source
COPY app/ .

# Environment variables
ENV PYTHONUNBUFFERED=1
# Default port inside the image
ENV PORT=5002

# Expose default port
EXPOSE 5002

# Run as a non-root user for better security
#RUN useradd -m sastuser
#USER sastuser

# Run the application
CMD ["python", "app.py"]