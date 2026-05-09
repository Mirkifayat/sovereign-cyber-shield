# Use a lightweight Python image
FROM python:3.9-slim

# --> ADDED 'whois' HERE <--
RUN apt-get update && apt-get install -y nmap whois && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

EXPOSE 10000

# Start with a high timeout to allow Nmap scans to finish
CMD ["gunicorn", "--bind", "0.0.0.0:10000", "--timeout", "150", "app:app"]
