FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml ./
RUN mvn -B dependency:go-offline
COPY src src
RUN mvn -B package -DskipTests

# Ubuntu-based rather than Alpine: Semgrep ships glibc wheels, and it runs the
# rule pack for every language that is not Java.
FROM eclipse-temurin:17-jre
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.183.0 \
    && /opt/semgrep/bin/semgrep --version
COPY --from=build /app/target/*.jar app.jar
RUN useradd -m -u 10001 codelens
USER codelens
ENV PORT=8082 \
    CODELENS_SEMGREP_COMMAND=/opt/semgrep/bin/semgrep \
    SEMGREP_SEND_METRICS=off
EXPOSE 8082
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "app.jar"]
