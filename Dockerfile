#FROM python:3.7-buster
#RUN apt-get update
#RUN apt-get install python-dev -y
#RUN apt-get install freetds-dev -y
#RUN pip install pymssql


#RUN apt-get update && apt-get install -y \
#  freetds-dev \
#  python-dev \
#  build-essential \
#  && rm -rf /var/lib/apt/lists/*



FROM python:3

WORKDIR /app
ADD requirements.txt .
ADD core.py .
#Optional
#ENV https_proxy=http://[proxy]:[port]
#ENV http_proxy=http://[proxy]:[port]
# install FreeTDS and dependencies
RUN apt-get update \
 && apt-get install unixodbc -y \
 && apt-get install unixodbc-dev -y \
 && apt-get install freetds-dev -y \
 && apt-get install freetds-bin -y \
 && apt-get install tdsodbc -y \
 && apt-get install --reinstall build-essential -y
# populate "ocbcinst.ini" as this is where ODBC driver config sits
RUN echo "[FreeTDS]\n\
Description = FreeTDS Driver\n\
Driver = /usr/lib/x86_64-linux-gnu/odbc/libtdsodbc.so\n\
Setup = /usr/lib/x86_64-linux-gnu/odbc/libtdsS.so" >> /etc/odbcinst.ini
#Pip command without proxy setting
RUN pip install -r requirements.txt
#Use this one if you have proxy setting
#RUN pip --proxy http://[proxy:port] install -r requirements.txt
CMD ["python","-u","core.py"]


#RUN apt-get install freetds
#RUN apt-get install freetds-dev -y
#RUN pip install pymssql --upgrade
#RUN apt-get install gcc
#RUN pip install --upgrade cython
#RUN apt-get install freetds-dev -y
#RUN export PYMSSQL_BUILD_WITH_BUNDLED_FREETDS=1
#RUN apt-get install python3-dev -y
#RUN apt-get install libevent-dev
#RUN apt-get install unixodbc-dev -y
#RUN apt-get install unixodbc -y
#RUN apt-get install --reinstall build-essential
#ADD odbcinst.ini /etc/odbcinst.ini
#ADD odbc.ini /usr/local/etc

#WORKDIR /app
#ADD requirements.txt .
#ADD core.py .
#Optional
#ENV https_proxy=http://[proxy]:[port]
#ENV http_proxy=http://[proxy]:[port]
# install FreeTDS and dependencies

#RUN apt-get update \
#&& apt-get install unixodbc -y \
# && apt-get install unixodbc-dev -y \
# && apt-get install freetds-dev -y \
# && apt-get install freetds-bin -y \
# && apt-get install tdsodbc -y \
# && apt-get install --reinstall build-essential -y
# populate "ocbcinst.ini" as this is where ODBC driver config sits
#RUN echo "[FreeTDS]\n\
#Description = FreeTDS Driver\n\
#Driver = /usr/lib/x86_64-linux-gnu/odbc/libtdsodbc.so\n\
#Setup = /usr/lib/x86_64-linux-gnu/odbc/libtdsS.so" >> /etc/odbcinst.ini

#RUN apt-get update
#RUN apt-get install -y tdsodbc unixodbc-dev
#RUN apt install unixodbc-bin -y
#RUN apt-get clean -y


#Pip command without proxy setting
#RUN pip install -r requirements.txt
#RUN export CFLAGS="-fPIC" 
#Use this one if you have proxy setting
#RUN pip --proxy http://[proxy:port] install -r requirements.txt
#CMD ["python","core.py"]
