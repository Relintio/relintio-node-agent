import express from 'express';

// Zero-code option (preload):
//   UP_LICENSE_KEY=... UP_API_URL=http://localhost:8000/api NODE_OPTIONS="--require ../../src/preload.cjs" node server.js
// Standard option (middleware): uncomment below.
// import { ultimateProtectorExpress } from '../../src/express.js';

const app = express();

// app.use(ultimateProtectorExpress({
//   licenseKey: process.env.UP_LICENSE_KEY || 'UP_LIVE_...',
//   apiUrl: process.env.UP_API_URL || 'http://localhost:8000/api',
// }));

app.get('/', (req, res) => {
  res.type('text/html').send('<html><body><h1>OK</h1></body></html>');
});

app.get('/checkout', (req, res) => {
  res.type('text/html').send('<html><body><h1>Checkout</h1></body></html>');
});

app.listen(3000, () => {
  // eslint-disable-next-line no-console
  console.log('Demo on http://localhost:3000');
});
