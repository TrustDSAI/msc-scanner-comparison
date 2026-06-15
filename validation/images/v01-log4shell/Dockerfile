# v01-log4shell
# Target: CVE-2021-44228 (Log4Shell)
# Incident: Dec 2021 — mass global exploitation of Log4j JNDI lookup
# Expected gate outcome: BLOCK (KEV catalog entry, fix available in 2.15.0)
#
# log4j-core-2.14.1.jar contains the vulnerable JNDI MessageLookup.
# Both Trivy and Grype detect Java JARs by reading the embedded manifest
# (Implementation-Title, Implementation-Version) and matching against
# their vulnerability databases.

FROM eclipse-temurin:11-jre-focal

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Download log4j-core 2.14.1 directly from Maven Central.
# The JAR manifest declares log4j-core:2.14.1; both scanners pick this up.
RUN curl -fSL \
    "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar" \
    -o log4j-core-2.14.1.jar

# Also include log4j-api (companion JAR; needed for runtime, also scanned)
RUN curl -fSL \
    "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar" \
    -o log4j-api-2.14.1.jar

CMD ["java", "-cp", "/app/*", "-version"]
