FROM openjdk:8-alpine

RUN printf 'cd  /opt \nmkdir -m 777 workspace \ncd workspace \nmkdir -m 777 complianceServer \nchmod 777 complianceServer \ncd complianceServer \nmkdir -m 777 ComplianceFiscal \ncd ComplianceFiscal \nmkdir -m 777 logs \ncd /opt \nmkdir -m 777 csfconfig \ncd csfconfig \nmkdir -m 777 properties \ncd / \nls -la /opt/workspace/* \nls -la /opt/csfconfig/* \njava -version \ncd /opt/workspace' >> create_workspace.sh \
	&& apk add tzdata 

CMD ["sh", "create_workspace.sh"]

COPY maven/cst-jwt-token.jar /opt/workspace/complianceServer/ComplianceFiscal/cst-jwt-token.jar

RUN sh -c 'touch /opt/workspace/complianceServer/ComplianceFiscal/cst-jwt-token.jar'

VOLUME /tmp

WORKDIR /

RUN printf 'cd /opt/workspace/complianceServer/ComplianceFiscal/ \njava -Xmx1024m -XX:MaxPermSize=1024m -jar cst-jwt-token.jar' >> docker-entrypoint.sh

ENTRYPOINT ["sh", "docker-entrypoint.sh"]