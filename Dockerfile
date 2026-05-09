# Use a lightweight, official Python image to keep the app fast
FROM python:3.9-slim

# Install Nmap (Crucial for the Infrastructure scanning module)
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install the Python dependencies (Flask, gunicorn, requests)
RUN pip install --no-cache-dir -r requirements.txt

# Copy all the rest of the application files into the container
COPY . .

# Expose the port that Render uses by default
EXPOSE 10000

# Start the app using Gunicorn. 
# We set the timeout to 200 seconds so the heavy Nmap vulnerability scans have time to finish!
CMD ["gunicorn", "--timeout", "200", "app:app"]