# v03-text4shell
# Target: CVE-2022-42889 (Text4Shell)
# Incident: Oct 2022 — RCE via ${script:...} / ${url:...} interpolation in
#            Apache Commons Text 1.5–1.9. Disclosed 2022-10-13.
# Expected gate outcome: BLOCK (KEV catalog entry, fix in commons-text 1.10.0)
#
# commons-text-1.9.jar triggers detection via its JAR manifest
# (Implementation-Version: 1.9, Bundle-SymbolicName: org.apache.commons.text).

FROM eclipse-temurin:11-jre-focal

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Download commons-text 1.9 (vulnerable) from Maven Central.
RUN curl -fSL \
    "https://repo1.maven.org/maven2/org/apache/commons/commons-text/1.9/commons-text-1.9.jar" \
    -o commons-text-1.9.jar

# commons-lang3 is a required runtime dependency; also present in real deployments.
RUN curl -fSL \
    "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.jar" \
    -o commons-lang3-3.12.0.jar

CMD ["java", "-version"]
