# Inventory API

Warehouse management REST API built with Spring Boot. Provides endpoints for item search, stock tracking, and bulk data import via XML.

## Features

- Full-text item search across warehouse catalog
- XML-based bulk inventory import
- Cache management for frequently accessed stock data
- RESTful endpoints with JSON responses

## Running

```bash
mvn spring-boot:run
```

The API starts on port `8080` by default.

## Endpoints

| Method | Path               | Description               |
|--------|--------------------|---------------------------|
| GET    | /api/items/search  | Search items by name       |
| POST   | /api/items/import  | Import inventory from XML  |
| POST   | /api/items/cache   | Restore cached stock data  |

## Configuration

Database connection is configured in `application.properties`. Default setup uses an embedded H2 instance for development.

## Build

```bash
mvn clean package
java -jar target/inventoryapi-1.2.0.jar
```
