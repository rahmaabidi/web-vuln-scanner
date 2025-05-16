# Base image with Python
FROM python:3.10-slim

# Set working directory in container
WORKDIR /app

# Copy everything into the container
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the default Flask port
EXPOSE 5000

# Run the Flask app
CMD ["python", "app.py"]
