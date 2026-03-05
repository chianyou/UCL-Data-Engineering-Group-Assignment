# Dashboard

This folder contains a static dashboard prototype intended for GitHub Pages deployment.

## Files

- `index.html`
- `style.css`
- `app.js`

## Data Source

Default mode reads CSV files from:

- `../data/curated/transformation_summaries/`

API mode reads from FastAPI endpoints when `api_base` is set in the URL, for example:

- `http://localhost:8000/dashboard/?api_base=http://localhost:8001`

Expected API endpoints:

- `GET /api/agg/daily-new-cves`
- `GET /api/agg/cvss-severity-distribution`
- `GET /api/agg/kev-hit-rate`
- `GET /api/agg/epss-vendor-product`
- `GET /api/agg/cwe-vendor-product`

## Suggested GitHub Pages Setup

Serve the repository root or the `dashboard/` directory as a static site, depending on your Pages configuration.
