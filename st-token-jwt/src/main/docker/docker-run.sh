#HML
docker network create compliance && \
docker stop cst-jwt-token && \
docker rm cst-jwt-token && \ 
docker run --name cst-jwt-token --network compliance \
-e SECRET=WTNObUxYTmxZM0psZEMxaFkyVnpjeTFyWlhrdFoyVjBMWFpoYkhWbGN5MTJhV1YzY3c9PQ== \
-e JDBC_DRIVER=oracle.jdbc.OracleDriver \
-e SERVICE_PROVIDER=YnIuY29tLmNvbXBsaWFuY2VpdC4q \
-e TZ=America/Bahia \
-e MONGO_DB_HOST=mongodb \
-e EUREKA_ZONE=csf-discovery \
-d compliancefiscal/csfapis:cst-jwt-tokenv1	


#PRD
docker network create compliance && \
docker stop cst-jwt-token && \
docker rm cst-jwt-token && \
docker run --name cst-jwt-token --network compliance \
-e SECRET=WTNObUxYTmxZM0psZEMxaFkyVnpjeTFyWlhrdFoyVjBMWFpoYkhWbGN5MTJhV1YzY3c9PQ== \
-e JDBC_DRIVER=oracle.jdbc.OracleDriver \
-e SERVICE_PROVIDER=YnIuY29tLmNvbXBsaWFuY2VpdC4q \
-e TZ=America/Sao_Paulo \
-e MONGO_DB_HOST=mongodb \
-e EUREKA_ZONE=csf-discovery \
-d compliancefiscal/csfapis:cst-jwt-tokenv1