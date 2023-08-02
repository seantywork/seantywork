FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update

RUN apt install -y git

RUN apt install -y vim

RUN apt install -y curl

RUN apt install -y gnupg

RUN apt install -y python3-pip

RUN pip3 install jupyterlab==3.5.1
RUN pip3 install gekko==1.0.5
RUN pip3 install beautifulsoup4==4.11.2
RUN pip3 install keras==2.11.0
RUN pip3 install matplotlib==3.6.2
RUN pip3 install numpy==1.23.5
RUN pip3 install opencv-python==4.6.0.66
RUN pip3 install pandas==1.5.2
RUN pip3 install plotly==5.11.0
RUN pip3 install torch==1.13.1
RUN pip3 install torchvision==0.14.1
RUN pip3 install scikit-learn==1.1.3
RUN pip3 install scipy==1.9.3
RUN pip3 install seaborn==0.12.1
RUN pip3 install statsmodels==0.13.5
RUN pip3 install tensorflow==2.11.0
RUN pip3 install xgboost==1.7.1
RUN pip3 install requests==2.28.1
RUN pip3 install urllib3==1.26.13
RUN pip3 install selenium==4.7.2
RUN pip3 install mysql-connector-python==8.0.31
RUN pip3 install elasticsearch==8.5.2
RUN pip3 install kafka-python==2.0.2


CMD ["jupyter","lab","--ip","0.0.0.0","--no-browser","--port=8888","--allow-root"]
