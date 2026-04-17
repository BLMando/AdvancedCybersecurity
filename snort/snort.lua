-- Snort 3 Configuration
-- Network Intrusion Detection System (NIDS)

-- ─── Inspection Modules ───────────────────────────
stream = {}
http_inspect = {}
telnet_decode = {}
ftp_client = {}
ftp_server = {}
rpc_decode = {}
ssh_decode = {}

-- ─── Port Scanning Detection ──────────────────────
stream_user = {
	tcp_ackr_init_zero = false,
	tcp_client_timeout = 300,
	tcp_server_timeout = 300,
	tcp_overlap_limit = 0,
}

-- ─── Output Module ────────────────────────────────
alert_json = {
	file = true,
	limit = 100,
	fields = "timestamp msg src_port dst_port src_ip dst_ip proto"
}

-- ─── Packet Decoder Settings ──────────────────────
decode = {
	snaplen = 65535,
}

-- ─── Alerting Settings ────────────────────────────
cooked_headers = true
max_payload_inline = 4096

-- ─── Default rule action ──────────────────────────
--# alert tcp any any -> any any (msg:"Default Alert"; content:""; sid:1;)

print("Snort configuration loaded successfully")
