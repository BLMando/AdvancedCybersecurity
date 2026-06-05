-- Firewall L7 locale in Envoy: rileva NoSQL injection e query dannose in-memory
local blocked_patterns = {
    "%$where",
    "%$function",
    "%$gt",
    "%$ne",
    "%$regex",
    "%$nin",
    "%$or",
    "sleep%(",
    "while%s*%(",
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

    local payload = body:getBytes(0, body:length()):lower()
    for _, pattern in ipairs(blocked_patterns) do
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
