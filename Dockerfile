# Use Python 3.10 as base
FROM python:3.10

# Create user with UID 1000
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy the rest of the application
COPY --chown=user . .

# Expose the port Hugging Face expects
EXPOSE 7860

# Run the application
# We use app.py as the entry point
CMD ["python", "app.py"]
