FROM ubuntu
MAINTAINER Philipp C. Heckel <philipp.heckel@gmail.com>

COPY pcopy /usr/bin
RUN \
	   apt-get update \
	&& apt-get install -y ca-certificates --no-install-recommends \
	&& rm -rf /var/lib/apt/lists/*ubuntu.{org,net}* \
	&& apt-get purge -y --auto-remove \
	&& useradd -m -d/home/pcopy -s /bin/bash pcopy \
	&& echo 'pcopy ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
	&& ln -s /usr/bin/pcopy /usr/bin/pcp \
	&& ln -s /usr/bin/pcopy /usr/bin/ppaste

EXPOSE 2586/tcp
ENTRYPOINT ["pcopy"]
