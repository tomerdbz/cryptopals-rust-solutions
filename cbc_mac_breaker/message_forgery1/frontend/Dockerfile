# syntax=docker/dockerfile:1
FROM python:3.9
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY sample_client.py sample_client.py
ENTRYPOINT ["python","./sample_client.py"]
#CMD [ "python3", "sample_client.py"]
