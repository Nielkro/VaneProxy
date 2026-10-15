-- Example Vane Lua Backend (OpenResty/Nginx-style)
-- Demonstrates dynamic routing, header manipulation, shared state counters,
-- authentication checks via vane.exit(), and JSON response generation.

local uri = vane.req.get_uri()
local method = vane.req.get_method()

-- Global shared dictionary for stats
local stats = vane.shared.STATS

-- Route 1: Root welcome endpoint (HTML)
if uri == "/" then
    vane.header["Content-Type"] = "text/html; charset=utf-8"
    vane.header["X-Powered-By"] = "Vane-Lua-Core"
    vane.status(200)
    vane.say("<h1>Welcome to Vane Lua Backend!</h1><p>High performance proxy & scripting engine.</p>")
    return
end

-- Route 2: Real-time Stats & Counter (JSON)
if uri == "/api/stats" then
    local hits = stats:incr("total_requests", 1)
    local ip = vane.req.get_client_ip()
    local now = vane.now()

    vane.header["Content-Type"] = "application/json"
    vane.header["X-Total-Hits"] = tostring(hits)
    vane.status(200)

    -- Format JSON response string
    local body = string.format('{"status":"ok","total_requests":%d,"client_ip":"%s","timestamp":%.3f}', hits, ip, now)
    vane.say(body)
    return
end

-- Route 3: Protected Auth Endpoint
if uri == "/api/protected" then
    local auth_header = vane.req.get_header("Authorization")

    -- Guard check: reject unauthorized requests immediately
    if not auth_header or auth_header ~= "Bearer secret-token-42" then
        vane.header["Content-Type"] = "application/json"
        vane.header["WWW-Authenticate"] = "Bearer"
        vane.exit(401, '{"error":"Unauthorized","message":"Valid Bearer token required"}')
    end

    -- Authorized user response
    vane.header["Content-Type"] = "application/json"
    vane.header["X-User-Role"] = "administrator"
    vane.status(200)
    vane.say('{"status":"authenticated","user":"admin","permissions":["read","write","admin"]}')
    return
end

-- Route 4: Asynchronous Delay Endpoint
if uri == "/api/delay" then
    vane.sleep(0.005) -- non-blocking Tokio async sleep
    vane.header["Content-Type"] = "application/json"
    vane.status(200)
    vane.say('{"status":"delayed","delay_seconds":0.005}')
    return
end

-- Default fallback: 404 Not Found
vane.header["Content-Type"] = "application/json"
vane.exit(404, string.format('{"error":"NotFound","path":"%s"}', uri))
