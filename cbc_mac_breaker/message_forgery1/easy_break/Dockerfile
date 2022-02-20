# syntax=docker/dockerfile:1
FROM python:3.9
WORKDIR /app
RUN mkdir -p /app/frontend
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY break.py break.py
ENTRYPOINT ["python","./break.py"]
#CMD [ "python3", "sample_client.py"]
