FROM python:3.13-slim

# Set the working directory inside the container
WORKDIR /app

# Install uv, the package manager
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Copy only the dependency files to leverage Docker's cache
COPY pyproject.toml uv.lock ./

# Install dependencies into the container's own virtual environment
RUN uv sync --frozen --no-cache

# Copy the rest of your application's source code
COPY . .

# This default command is for production and will be overridden by docker-compose
CMD ["uv", "run", "fastapi", "run", "src/main.py", "--port", "80", "--host", "0.0.0.0"]