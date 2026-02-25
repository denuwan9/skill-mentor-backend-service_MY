FROM maven:3.9.6-eclipse-temurin-17
WORKDIR /app

# Copy the entire project
COPY . .

# Build the application
RUN mvn package -DskipTests

# Expose the port Render injects via the PORT env var
EXPOSE ${PORT:-8081}

# Run the application directly from the target folder
ENTRYPOINT ["java", "-jar", "target/skillmentor-0.0.1-SNAPSHOT.jar"]
