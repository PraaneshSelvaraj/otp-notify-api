FROM python:3.8-slim-buster
WORKDIR /otp-api
COPY . /otp-api
RUN pip install -r requirements.txt
EXPOSE 5000
CMD python main.py