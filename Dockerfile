FROM python:latest

COPY test.py test.py
COPY zone_file_example zone_file

EXPOSE 53/udp

CMD ["python", "test.py", "zone_file"]