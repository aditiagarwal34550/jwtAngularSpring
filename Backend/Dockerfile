FROM java:8
FROM maven:alpine

WORKDIR /app
 

RUN apk --no-cache add clamav-daemon freshclam clamav-libunrar supervisor

RUN sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/clamd.conf && \
    echo 'TCPSocket 3310' >> /etc/clamav/clamd.conf && \
    sed -i 's/^Foreground .*$/Foreground true/g' /etc/clamav/freshclam.conf
RUN freshclam

RUN mkdir /run/clamav && chown clamav:clamav /run/clamav
COPY Backend/etc /etc/

EXPOSE 3310/tcp
CMD ["supervisord", "-c", "/etc/supervisord.conf"]

EXPOSE 8080
COPY Backend/target/spring-boot-security-jwt-0.0.1-SNAPSHOT.jar .

ENTRYPOINT ["java", "-jar", "spring-boot-security-jwt-0.0.1-SNAPSHOT.jar"]