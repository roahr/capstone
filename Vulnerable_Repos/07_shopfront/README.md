# ShopFront

Modern e-commerce platform built with Express and EJS templating.

## Features

- Product catalog with full-text search
- Dynamic pricing with discount expressions
- Admin configuration panel
- Server-side rendered templates with EJS

## Getting Started

```bash
npm install
npm run dev
```

## Stack

- **Runtime**: Node.js 18+
- **Framework**: Express 4
- **Database**: SQLite via better-sqlite3
- **Templating**: EJS
- **Assets**: Static file serving with compression

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /products | List all products |
| GET | /products/search | Search catalog |
| GET | /products/:id | Product detail |
| POST | /products/:id/price | Calculate discounted price |
| PUT | /admin/config | Update platform config |

## License

ISC
