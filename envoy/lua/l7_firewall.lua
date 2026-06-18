-- Firewall L7 locale in Envoy (Corretto per la sintassi dei pattern Lua)
local blocked_patterns = {
    "%$where",       -- Cerca letteralmente "$where"
    "%$function",    -- Cerca letteralmente "$function"
    "%$gt",          -- Cerca letteralmente "$gt"
    "%$ne",          -- Cerca letteralmente "$ne"
    "%$regex",       -- Cerca letteralmente "$regex"
    "%$nin",         -- Cerca letteralmente "$nin"
    "%$or",          -- Cerca letteralmente "$or"
    "sleep%(",       -- % escape per la parentesi tonda aperta
    "while%s*%(",    -- %s* zero o più spazi seguiti da (
    "settimeout%("
}

function envoy_on_request(request_handle)
    local method = request_handle:headers():get(":method")
    if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then
        return
    end

    local body = request_handle:body()
    if not body or body:length() == 0 then
        return
    end

    -- Prevenzione BSON/JSON Oversized locale (max 16MB)
    if body:length() > 16777216 then
        request_handle:logWarn("L7 Local WAF Blocked: Payload too large (" .. tostring(body:length()) .. " bytes)")
        request_handle:respond(
            {
                [":status"] = "413",
                ["x-l7-decision"] = "deny",
                ["x-l7-reason"] = "payload_too_large"
            },
            '{"error": "Payload troppo grande (Max 16MB)", "code": 413}'
        )
        return
    end

    -- Estrazione del payload sicuro convertito in stringa
    local payload = body:getBytes(0, body:length()):lower()
    
    for _, pattern in ipairs(blocked_patterns) do
        -- Usiamo string.find (o payload:find) che interpreta i pattern sopra definiti
        if payload:find(pattern) then
            request_handle:logWarn("L7 Local WAF Blocked: Rilevato pattern " .. pattern)
            request_handle:respond(
                {
                    [":status"] = "403",
                    ["x-l7-decision"] = "deny",
                    ["x-l7-reason"] = "nosql_injection"
                },
                '{"error":"Richiesta bloccata - Rilevato pattern NoSQL sospetto","code":403}'
            )
            return
        end
    end
end