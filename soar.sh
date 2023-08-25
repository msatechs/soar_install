#/bin/bash



RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
LOGFILE="/tmp/install.log"
OSRPM="fedora35 fedora37 rhel8.5"
OSDEB="ubuntu20.04 ubuntu22.04 debian11"
MINREQRAM="16000000"
MINREQCPU="4"
CHECKSAMESERVER=true
PROXYHOST=""
PROXYPORT=""
CACERT=""


log () {
  TYPE=$1
  MESSAGE=$2

  case $1 in
    "success" )
    TAG=""
    COLOR=${WHITE}
    ;;

    "ko" )
    TAG="[ERROR]: "
    COLOR=${RED}
    ;;

    "ok" )
    TAG="[INFO]: "
    COLOR=${BLUE}
    ;;

    "message" )
    TAG="[INFO]: "
    COLOR=${BLUE}
    ;;
    
  esac

  echo -e "${TAG}${MESSAGE}"
  echo -e "${COLOR}${TAG}${MESSAGE}${NC}"
}


alias yum="yum -yq"
alias dnf="dnf -yq"

pkg-install() {
  PACKAGENAME=$@
  sudo apt update -qq 
  sudo RUNLEVEL=1 apt install -yqq ${PACKAGENAME} 
}

# Start service, wait for it to be available and enable it
start-service() {
  SERVICENAME=$1
  
  log message  "* Starting service ${SERVICENAME}"
  [[ $(sudo systemctl is-active ${SERVICENAME}) ]] && \
      sudo systemctl -q restart ${SERVICENAME} || \
      sudo systemctl -q start ${SERVICENAME} 

  sudo systemctl -q enable ${SERVICENAME}
}

## REQUIRED PACKAGES
install-required-packages() {
  pkg-install wget gnupg apt-transport-https git ca-certificates curl jq software-properties-common lsb-release python3-pip iproute2
}

## INSTALL JAVA
install-java() {
  log message "Installing Java"
  apt update --allow-insecure-repositories
  apt-get install -y openjdk-8-jre-headless
  echo JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64" | sudo tee /etc/environment
  export JAVA_HOME="/usr/lib/jvm/java-8-openjdk-amd64"
}


## CASSANDRA INSTALLATION 
install-cassandra() {
  log message "Installing Cassandra"
  # Cassandra Install

  apt upgrade -y
  echo "deb https://debian.cassandra.apache.org 41x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
  curl https://downloads.apache.org/cassandra/KEYS | sudo apt-key add -
  apt update --allow-insecure-repositories --allow-unauthenticated
  pkg-install -y cassandra

  # Cassandra Config
  systemctl start cassandra
  sleep 10
  cqlsh localhost 9042 -e "UPDATE system.local SET cluster_name = 'thp' where key='local'"
  nodetool flush
}



## INSTALL ELASTICSEARCH
install-elasticsearch() {
  log message "Installing Elasticsearch"
  
  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list 

  pkg-install elasticsearch
}

## ELASTICSEARCH CONFIGURATION
configure-elasticsearch() {
  log message "Configuring elasticsearch"
  
  sudo systemctl stop elasticsearch
  sudo rm -rf /var/lib/elasticsearch/*
  
  cat << EOF |  sudo tee /etc/elasticsearch/elasticsearch.yml 
http.host: 127.0.0.1
transport.host: 127.0.0.1
cluster.name: hive
thread_pool.search.queue_size: 100000
path.logs: "/var/log/elasticsearch"
path.data: "/var/lib/elasticsearch"
xpack.security.enabled: false
script.allowed_types: "inline,stored"
EOF

  cat << EOF | sudo tee -a /etc/elasticsearch/jvm.options.d/jvm.options 
-Dlog4j2.formatMsgNoLookups=true
-Xms4g
-Xmx4g
EOF
}

## INSTALL THEHIVE 
install-thehive() {
  # The hive (Debian)
  curl https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY -k | sudo apt-key add -
  echo 'deb https://deb.thehive-project.org release main' | sudo tee -a /etc/apt/sources.list.d/thehive-project.list
  sudo apt-get update --allow-insecure-repositories --allow-unauthenticated
  sudo apt-get install thehive4 -y

  # index Engine
  mkdir /opt/thp/thehive/index
  chown thehive:thehive -R /opt/thp/thehive/index

  # File Storage
  mkdir -p /opt/thp/thehive/files
  chown -R thehive:thehive /opt/thp/thehive/files

  # Additional
  sudo addgroup thehive
  sudo adduser --system thehive
  #sudo cp /opt/thehive/package/thehive.service /usr/lib/systemd/system
  sudo chown -R thehive:thehive /opt/thehive
  sudo chgrp thehive /etc/thehive/application.conf
  sudo chmod 640 /etc/thehive/application.conf
  sudo systemctl enable thehive
  sudo service thehive start

  sudo mkdir -p /etc/thehive
  sudo echo "play.http.secret.key=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)" | sudo tee -a /etc/thehive/application.conf
}

## Install PYTHON LIBS
install-python-libs() {
  log message "Installing python libs"
  sudo pip3 install cortex4py cortexutils
}

## INSTALL CORTEX 
install-cortex() {
  wget -qO- "https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY"  | sudo apt-key add -
  wget -qO- https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY |  sudo gpg --dearmor -o /usr/share/keyrings/thehive-project.gpg
  echo 'deb https://deb.thehive-project.org release main' | sudo tee -a /etc/apt/sources.list.d/thehive-project.list
  pkg-install  cortex
}


## CONFIGURE CORTEX (using public neurons as Docker images)
configure-cortex() {
  log message "Configuring cortex"
  sudo usermod -G docker cortex  # DOCKER PERMISSIONS
  sudo mkdir -p /opt/Custom-Analyzers/{analyzers,responders}
  sudo chown -R cortex:cortex /opt/Custom-Analyzers

  sudo systemctl -q stop cortex
  if ! test -e /etc/cortex/secret.conf; then
      key=$(dd if=/dev/urandom bs=1024 count=1 | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)
      echo "play.http.secret.key=\"$key\"" | sudo tee -a /etc/cortex/secret.conf
      sudo sed -i  \
        -e 's_#play\.http\.secret\.key=.*$_include\ \"/etc/cortex/secret\.conf\"_' \
        -e 's/\(.*analyzers.json\"\)$/\1,/' \
        -e '/.*analyzers.json\",/a \\t\"/opt/Custom-Analyzers/analyzers\"' \
        -e 's/\(.*responders.json\"\)$/\1,/' \
        -e '/.*responders.json\",/a \\t\"/opt/Custom-Analyzers/responders\"' \
        /etc/cortex/application.conf
  fi
}

## INSTALL PUBLIC ANALYZERS/RESPONDERS AND THEIR DEPENDENCIES

install-neurons() {
  log message "Installing public Cortex neurons in /opt/Cortex-Analyzers and their dependencies"

  ## Install required packages
  log message "Installing Cortex neurons system packages dependencies"
  
  
  pkg-install unzip curl libimage-exiftool-perl wkhtmltopdf libboost-regex-dev  \
  libboost-program-options-dev libboost-system-dev libboost-filesystem-dev \
    libssl-dev build-essential cmake libfuzzy-dev clamav clamav-daemon

  
  ### Install specific programs required by some analyzers
  curl -SL https://github.com/mandiant/flare-floss/releases/download/v2.0.0/floss-v2.0.0-linux.zip  --output /tmp/floss.zip
  unzip /tmp/floss.zip -d /usr/bin

  log message "Installing Cortex neurons programs in /opt/Cortex-Analyzers"
  (cd /opt && sudo git clone https://github.com/TheHive-Project/Cortex-Analyzers.git)
  sudo chown -R cortex:cortex /opt/Cortex-Analyzers

  log message "Installing Cortex neurons dependencies"
  awk '{print $0}' /opt/Cortex-Analyzers/*/*/requirements.txt > /tmp/requirements.tmp
  cat /tmp/requirements.tmp | while read line ; do echo  -e "$line\n"  | \
   awk -F "[=]{2}|[<>~;]{1}" ' { print $1 } ' | \
   ## TODO: REMOVE AFTER Cortex-Analyzers 3.2 is released
   tr -d '\r' ; done | grep -v -E "enum|future" | \
   ## TODO: REMOVE AFTER Cortex-Analyzers 3.2 is released
   grep -v "git+https://github.com/fireeye/stringsifter.git@python3.7#egg=stringsifter" | \
   sort -u  > /tmp/requirements.txt
   ## TODO: REMOVE AFTER Cortex-Analyzers 3.2 is released
   echo "stringsifter" >> /tmp/requirements.txt
  pip3 install ${PIPPROXY} -r /tmp/requirements.txt
}

nginx-install(){
  pkg-install nginx
  rm /etc/nginx/sites-enabled/default
}

thehive-ssl(){

  mkdir /etc/nginx/ssl -p

  openssl genrsa 4096 > /etc/nginx/ssl/hive_key.pem
  openssl req -new -x509 -nodes -days 36500 -key /etc/nginx/ssl/hive_key.pem -out /etc/nginx/ssl/hive_ca.pem


  echo 'server {
      listen 9000 default_server;

      server_name _;

      return 301 https://$host$request_uri;
  }

  server {
    listen 443 ssl;
    server_name localhost;

    #ssl on;
    ssl_certificate       ssl/hive_ca.pem;
    ssl_certificate_key   ssl/hive_key.pem;

    proxy_connect_timeout   600;
    proxy_send_timeout      600;
    proxy_read_timeout      600;
    send_timeout            600;
    client_max_body_size    2G;
    proxy_buffering off;
    client_header_buffer_size 8k;

    location / {
      add_header              Strict-Transport-Security "max-age=31536000; includeSubDomains";
      proxy_pass              http://127.0.0.1:9000/;
      proxy_http_version      1.1;
    }
  }' | sudo tee /etc/nginx/sites-enabled/thehive.conf

  nginx -s reload
}

cortex-ssl(){

  mkdir /etc/nginx/ssl -p

  openssl genrsa 4096 > /etc/nginx/ssl/cortex_key.pem
  openssl req -new -x509 -nodes -days 365 -key /etc/nginx/ssl/cortex_key.pem -out /etc/nginx/ssl/cortex_ca.pem



  echo 'server {
    listen 5031 ssl;
    server_name localhost;

    #ssl on;
    ssl_certificate       ssl/cortex_ca.pem;
    ssl_certificate_key   ssl/cortex_key.pem;

    proxy_connect_timeout   600;
    proxy_send_timeout      600;
    proxy_read_timeout      600;
    send_timeout            600;
    client_max_body_size    2G;
    proxy_buffering off;
    client_header_buffer_size 8k;

    location / {
      add_header              Strict-Transport-Security "max-age=31536000; includeSubDomains";
      proxy_pass              http://127.0.0.1:9001/;
      proxy_http_version      1.1;
    }
  }

  ' | sudo tee /etc/nginx/sites-enabled/cortex.conf


  nginx -s reload

}

reload-services() {
  sudo systemctl daemon-reload
}

### START AND ENABLE ELASTICSEARCH
start-enable-elasticsearch(){
  start-service elasticsearch 9200
}

### START AND ENABLE THEHIVE
enable-thehive() {
  systemctl enable thehive
}

### START AND ENABLE CORTEX
start-enable-cortex() {
  start-service cortex 9001 
}

start-enable-nginx() {
  start-service nginx 
}

if ping -c 1 github.com &> /dev/null
then
  echo github.com OK
else
  echo github.com unreachable
  exit 1
fi


if ping -c 1 apache.org &> /dev/null
then
  echo apache.org OK
else
  echo apache.org unreachable
  exit 1
fi

if ping -c 1 elastic.co &> /dev/null
then
  echo elastic.co OK
else
  echo elastic.co unreachable
  exit 1
fi

if ping -c 1 thehive-project.org &> /dev/null
then
  echo thehive-project.org OK
else
  echo thehive-project.org unreachable
  exit 1
fi


install-required-packages
install-java
install-thehive
install-cassandra
install-elasticsearch
configure-elasticsearch
nginx-install

install-python-libs
install-cortex
configure-cortex
install-neurons
reload-services
enable-thehive
start-enable-elasticsearch
start-enable-cortex
thehive-ssl
cortex-ssl
start-enable-nginx
