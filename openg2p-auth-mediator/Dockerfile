FROM openjdk:11-jre

ARG container_user=openg2p
ARG container_user_group=openg2p
ARG container_user_uid=1001
ARG container_user_gid=1001

RUN apt-get -y update \
&& apt-get install -y unzip \
&& groupadd -g ${container_user_gid} ${container_user_group} \
&& useradd -u ${container_user_uid} -g ${container_user_group} -s /bin/sh -m ${container_user}

WORKDIR /home/${container_user}
RUN chown -R ${container_user}:${container_user} /home/${container_user}

EXPOSE 8080

ADD --chown=${container_user}:${container_user} ./target/auth-mediator-*-spring-boot.jar openg2p-auth-mediator.jar

USER ${container_user_uid}:${container_user_gid}

CMD java -jar openg2p-auth-mediator.jar