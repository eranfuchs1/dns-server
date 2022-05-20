FROM python:latest

COPY mydns.py mydns.py
COPY zone_file_example zone_file

EXPOSE 53/udp

CMD ["python", "mydns.py", "zone_file"]