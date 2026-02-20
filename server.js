const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const dotenv = require('dotenv');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Supabase configuration
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
    console.error('❌ CRITICAL ERROR: Missing SUPABASE_URL or SUPABASE_ANON_KEY in .env');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseAnonKey);

/**
 * 1. Security Headers (Helmet)
 * Mirroring enterprise gateway security standards
 */
app.use(helmet());

/**
 * 2. Detailed Logging (Morgan)
 * Using 'combined' format for Apache-style logs
 */
app.use(morgan(':method :url :status :res[content-length] - :response-time ms'));

/**
 * 3. CORS Configuration
 * Restricting access to the gateway
 */
app.use(cors({
    origin: '*', // In production, replace with your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'apikey', 'x-client-info']
}));

app.use(express.json());

/**
 * 4. Rate Limiting
 * WSO2-style traffic management
 */
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests from this IP, please try again after 15 minutes' }
});
app.use(limiter);

/**
 * 5. Health Check Endpoint
 */
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'UP', gateway: 'WSO2-style Proxy', timestamp: new Date() });
});

/**
 * 6. Auth Filter / Middleware
 * Replicates Spring's filter logic to validate user status before proxying
 */
const authFilter = async (req, res, next) => {
    // Skip filter for non-authenticated paths (like auth flow)
    if (req.url.includes('/auth/v1/')) {
        return next();
    }

    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return next(); // Let Supabase handle the missing auth for public tables if any
    }

    try {
        const token = authHeader.replace('Bearer ', '');
        const { data: { user }, error } = await supabase.auth.getUser(token);

        if (error || !user) {
            return res.status(401).json({ error: 'Unauthorized: Invalid session token' });
        }

        // Enterprise-grade Status Check (Spring Logic Replicated)
        const { data: status, error: statusError } = await supabase.rpc('validate_user_status', {
            user_uuid: user.id
        });

        if (statusError || !status || !status.valid) {
            console.warn(`[Gateway Filter] Access BLOCKED for user ${user.id}: ${status?.message || 'Account Status Invalid'}`);
            return res.status(403).json({
                error: 'Account Restricted',
                message: status?.message || 'Your account is inactive or expired. Please contact administration.',
                code: status?.error_code || 'GATEWAY_AUTH_FAIL'
            });
        }

        console.log(`[Gateway Filter] Access GRANTED for user ${user.id}`);
        next();
    } catch (err) {
        console.error('[Gateway Filter] Internal Error:', err);
        return res.status(500).json({ error: 'Gateway Processing Error' });
    }
};

/**
 * 7. Transparent Proxy to Supabase
 * Enforces the Gateway as the single point of entry
 */
app.use('/', authFilter, createProxyMiddleware({
    target: supabaseUrl,
    changeOrigin: true,
    logLevel: 'debug',
    onProxyReq: (proxyReq, req, res) => {
        // Enforce apikey header if missing
        if (!req.headers['apikey']) {
            proxyReq.setHeader('apikey', supabaseAnonKey);
        }
    },
    onProxyRes: (proxyRes, req, res) => {
        // Add Gateway identification header
        res.setHeader('X-Powered-By', 'WSO2-style-Gateway');
    }
}));

/** 
 * SERVICE 1: Supabase
 * Entry Point: http://localhost:3001/supabase/...
 */
// app.use('/supabase', authFilter, createProxyMiddleware({
//     target: process.env.SUPABASE_URL,
//     pathRewrite: { '^/supabase': '' }, // Remove /supabase from the URL before sending to target
//     changeOrigin: true,
//     onProxyReq: (proxyReq) => {
//         proxyReq.setHeader('apikey', process.env.SUPABASE_ANON_KEY);
//     }
// }));
/** 
 * SERVICE 2: Payment API (e.g., Stripe or a Custom Service)
 * Entry Point: http://localhost:3001/payments/...
 */
// app.use('/payments', authFilter, createProxyMiddleware({
//     target: 'https://api.paymentservice.com',
//     pathRewrite: { '^/payments': '' },
//     changeOrigin: true,
//     onProxyReq: (proxyReq) => {
//         // You can add different headers here for the other API
//         proxyReq.setHeader('X-Payment-Secret', process.env.PAYMENT_API_KEY);
//     }
// }));

// Graceful Start
app.listen(PORT, () => {
    console.log('\n======================================================');
    console.log('🚀 ENTERPRISE GATEWAY STARTING');
    console.log(`📍 URL: http://localhost:${PORT}`);
    console.log(`🎯 TARGET: ${supabaseUrl}`);
    console.log(`🛡️  SECURITY: Helmet + RateLimit + JWT Filter`);
    console.log('======================================================\n');
});
