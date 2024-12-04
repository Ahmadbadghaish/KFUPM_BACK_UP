# Use an official Python image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install Python dependencies
RUN pip install -r requirements.txt

# Run the database setup script to initialize the database
RUN python setup_db.py

# Expose the port that Flask will run on
EXPOSE 5000

# Command to run the Flask app
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
