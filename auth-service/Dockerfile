FROM maven:3.9.9-eclipse-temurin-21 AS builder

ENV MAVEN_OPTS="-Dhttps.protocols=TLSv1.2 -Djava.net.preferIPv4Stack=true -Dmaven.repo.local=/root/.m2/repository"
ENV MAVEN_CONFIG="/root/.m2"

WORKDIR /app

COPY settings.xml /root/.m2/settings.xml

COPY pom.xml .

RUN mvn dependency:go-offline -B -DretryFailed=true -Dmaven.wagon.http.retryHandler.count=3 -Dmaven.wagon.httpconnectionManager.ttlSeconds=120 -Dmaven.wagon.http.timeout=30000

COPY src ./src

RUN mvn clean package -DskipTests


FROM eclipse-temurin:21-jre-jammy AS runner

WORKDIR /app

RUN groupadd --system appgroup && useradd --system -g appgroup appuser

USER appuser

COPY --from=builder /app/target/*.jar ./app.jar

EXPOSE 8081

# SARAN 4 (Opsional): Tambahkan flag JVM untuk manajemen memori di kontainer.
ENTRYPOINT ["java", "-jar", "-XX:+UseG1GC", "-Xms256m", "-Xmx512m", "app.jar"]