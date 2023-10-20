# docker-multi-stage-build-buysell:1.0-SNAPSHOT
FROM maven:3.6.3-openjdk-17-slim AS MAVEN_BUILD
COPY ./ ./
RUN mvn clean package
FROM openjdk:17-jdk-slim
COPY --from=MAVEN_BUILD /target/buysell-0.0.1-SNAPSHOT.jar /buysell.jar
CMD ["java", "-jar", "/buysell.jar"]
