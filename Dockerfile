FROM python:slim

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py signer.py ./

ENV CA_CRT /certs/ca.crt
ENV CA_KEY /certs/ca.key
ENV SUBJ "/O=org"
ENV KEY_LEN 4096
ENV DAYS 3650

EXPOSE 80
RUN mkdir /certs

CMD python app.py