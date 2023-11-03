FROM python:latest

RUN apt update && \
      apt install -y git && \
      useradd -m cloudgrep && \
      chown -R cloudgrep: /home/cloudgrep

USER cloudgrep
WORKDIR /home/cloudgrep

RUN cd /home/cloudgrep && \
      git clone https://github.com/cado-security/cloudgrep.git && \
      cd cloudgrep && \
      pip install -r requirements.txt

ENTRYPOINT ["python3", "/home/cloudgrep/cloudgrep/cloudgrep.py"]
