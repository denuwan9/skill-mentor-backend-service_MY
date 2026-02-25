FROM maven:3.9.6-eclipse-temurin-17 AS build

WORKDIR /app

# Copy the entire project and build
COPY . .

RUN mvn clean package -DskipTests

# Stage 2: Run the application
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

# Copy the built jar file from the build stage

COPY --from=build /app/target/*.jar app.jar

EXPOSE 8081

ENTRYPOINT ["java", "-jar", "app.jar"]
