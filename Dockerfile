FROM python:3.9.1

RUN pip install --upgrade pip

WORKDIR /app

COPY . .

RUN pip --no-cache-dir install -r requirements.txt

EXPOSE 5000

ENTRYPOINT ["python"]

CMD ["app.py"]