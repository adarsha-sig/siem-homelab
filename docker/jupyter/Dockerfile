FROM jupyter/scipy-notebook:python-3.11

# Install as root so pip can write to site-packages; the base image
# handles dropping back to the unprivileged 'jovyan' user.
USER root

COPY requirements.txt /tmp/jupyter-requirements.txt
RUN pip install --no-cache-dir -r /tmp/jupyter-requirements.txt

# Mount point hints — actual mounts are declared in docker-compose.yml
WORKDIR /home/jovyan/work

USER ${NB_UID}
