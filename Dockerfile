FROM fabric8/java-alpine-openjdk8-jdk

MAINTAINER  lieber

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

EXPOSE 18700/tcp

ENV JAVA_OPTS="-server -Xmx512m -Xms512m -Xmn256m \
-Xloggc:/home/eureka/logs/nacos_gc.log -verbose:gc \
-XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+PrintGCTimeStamps \
-XX:+UseGCLogFileRotation -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=100M \
-Djava.security.egd=file:/dev/./urandom \
-Duser.timezone=Asia/Shanghai \
-Dspring.cloud.nacos.config.server-addr=47.108.85.187:8848 \
-Dspring.profiles.active=dev"

ENTRYPOINT java ${JAVA_OPTS} -jar /home/app/gateway-1.0.0-SNAPSHOT.jar


# docker build -t gateway:latest .
# ip=`/sbin/ifconfig eth0|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'` && docker run -d -p 18700:18700 -v /home/app/gateway/:/home/app/ --name gateway --restart=always -e HOST_IP=$ip -e WORK_ID=1 gateway:latest