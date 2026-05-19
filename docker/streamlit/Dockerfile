FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir \
    streamlit==1.35.0 \
    elasticsearch==8.14.0 \
    plotly==5.22.0 \
    pandas==2.2.2

# src/ is bind-mounted at runtime (see docker-compose.yml)
EXPOSE 8501

CMD ["streamlit", "run", "src/dashboard/app.py", \
     "--server.port=8501", "--server.address=0.0.0.0"]
