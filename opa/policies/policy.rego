package envoy.authz.policy

import future.keywords
import data.envoy.authz.identity

# Pattern bloccati per la prevenzione NoSQL Injection
blocked_patterns := {
	"$where",
	"$function",
	"$regex",
	"$ne",
	"$gt",
	"sleep(",
	"while("
}

# La regola is_malicious scansiona ricorsivamente la query di MongoDB
default is_malicious := false

is_malicious if {
	# walk analizza ricorsivamente l'oggetto query_doc in coppie [path, value]
	walk(identity.query_doc, [path, value])

	# Caso 1: Una chiave all'interno del path corrisponde a uno dei pattern NoSQL Injection
	some segment in path
	is_string(segment)
	segment in {"$where", "$function", "$regex", "$ne", "$gt"}
}

is_malicious if {
	# walk analizza ricorsivamente l'oggetto query_doc
	walk(identity.query_doc, [path, value])

	# Caso 2: Il valore stesso (se stringa) è un operatore bloccato
	is_string(value)
	value in {"$where", "$function", "$regex", "$ne", "$gt"}
}

is_malicious if {
	# walk analizza ricorsivamente l'oggetto query_doc
	walk(identity.query_doc, [path, value])

	# Caso 3: Il valore contiene espressioni dannose come sleep( o while(
	is_string(value)
	some pattern in {"sleep(", "while("}
	contains(lower(value), pattern)
}
