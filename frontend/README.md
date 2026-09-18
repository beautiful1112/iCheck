# iCheck dashboard

The dashboard is the operations surface for the iCheck API. It shows alert state,
service-path health, current endpoint identity, wired attachments, and Wi-Fi client
associations.

## Requirements

- Node.js 22.13 or newer
- A running iCheck API for live data (the UI falls back to representative demo data)

## Development

```bash
npm ci
NEXT_PUBLIC_ICHECK_API_URL=http://localhost:8000/api/v1 npm run dev
```

## Production build

```bash
npm run build
```

The dashboard registers one optional WebMCP action in browsers that support the
proposal: `acknowledge_alert`. It uses the same acknowledgement function as the
visible alert control.

