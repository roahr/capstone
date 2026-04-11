# Report Generation Service

Automated report generation service built with Spring Boot. Supports template-based document creation with enterprise directory integration for user metadata enrichment.

## Features

- Template-driven report generation
- LDAP directory integration for user details
- Persistent report state with snapshot/restore
- Configurable template directory

## Running

```bash
mvn spring-boot:run
```

Starts on port `8081` by default.

## Endpoints

| Method | Path                    | Description                  |
|--------|-------------------------|------------------------------|
| POST   | /api/reports/generate   | Generate report from template |
| GET    | /api/reports/user-info  | Fetch user metadata via LDAP  |
| POST   | /api/reports/restore    | Restore saved report state    |

## Configuration

LDAP server and template directory are configured in `application.properties`:

```properties
ldap.url=ldap://directory.corp.local:389
ldap.base=dc=corp,dc=local
report.template.dir=/opt/reportgen/templates
```

## Build

```bash
mvn clean package
java -jar target/reportgen-2.0.1.jar
```
