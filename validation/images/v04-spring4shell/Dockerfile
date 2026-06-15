# v04-spring4shell
# Target: CVE-2022-22965 (Spring4Shell)
# Incident: Mar-Apr 2022 — RCE in Spring MVC via data-binding on JDK 9+;
#            exploited within 24 hours of disclosure.
# Expected gate outcome: BLOCK (KEV catalog entry, fix in Spring 5.3.18 / 5.2.20)
#
# The CVE affects spring-webmvc and spring-beans. Both JARs are included
# so both scanners can attribute the finding. On JDK 9+ (which is what
# eclipse-temurin:11 provides), the ClassLoader exposure is present.

FROM eclipse-temurin:11-jre-focal

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# spring-webmvc 5.3.17 — the primary affected artifact for CVE-2022-22965
RUN curl -fSL \
    "https://repo1.maven.org/maven2/org/springframework/spring-webmvc/5.3.17/spring-webmvc-5.3.17.jar" \
    -o spring-webmvc-5.3.17.jar

# spring-beans 5.3.17 — also flagged; data-binding entry point
RUN curl -fSL \
    "https://repo1.maven.org/maven2/org/springframework/spring-beans/5.3.17/spring-beans-5.3.17.jar" \
    -o spring-beans-5.3.17.jar

# spring-core needed at runtime; same version, not independently flagged
RUN curl -fSL \
    "https://repo1.maven.org/maven2/org/springframework/spring-core/5.3.17/spring-core-5.3.17.jar" \
    -o spring-core-5.3.17.jar

CMD ["java", "-version"]
