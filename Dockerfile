FROM registry.access.redhat.com/ubi7

RUN yum install -y rh-python36 rh-python36-python-pip

ENV PATH="/opt/rh/rh-python36/root/usr/bin:${PATH}"

WORKDIR /src
COPY . .

RUN pip3 install -r requirements.txt
CMD python3 main.py

