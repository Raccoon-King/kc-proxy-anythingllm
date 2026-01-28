require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

const PORT = process.env.PORT || 8080;
const TARGET_URL = process.env.TARGET_URL || 'http://anythingllm:3001';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan(LOG_LEVEL === 'debug' ? 'dev' : 'combined'));

app.get('/healthz', (_, res) => {
  res.json({ status: 'ok', upstream: TARGET_URL });
});

// TODO: Insert Keycloak token validation middleware here once realm details are provided.
app.use((req, res, next) => next());

const proxy = createProxyMiddleware({
  target: TARGET_URL,
  changeOrigin: true,
  ws: true,
  logLevel: LOG_LEVEL,
  onProxyReq: (proxyReq, req) => {
    proxyReq.setHeader('x-forwarded-host', req.headers.host || '');
    proxyReq.setHeader('x-forwarded-proto', req.protocol);
  },
});

app.use('/', proxy);

const server = app.listen(PORT, () => {
  console.log(`Proxy listening on ${PORT}, forwarding to ${TARGET_URL}`);
});

// Forward websockets
server.on('upgrade', proxy.upgrade);