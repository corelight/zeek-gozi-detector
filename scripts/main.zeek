module Gozi;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The notice when the C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed, };

	## An option to enable detailed logs
	const enable_detailed_logs = T &redef;

	## Record type containing the column fields of the log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## The Gozi C2 HTTP method.
		http_method: string &log &optional;
		## The Gozi C2 command, still encoded and encrypted.
		payload: string &log &optional;
	};

	## Default hook into Gozi logging.
	global log_gozi: event(rec: Info);

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Indicator of a request related to GOZI
	redef enum HTTP::Tags += { URI_GOZI_C2, };
}

redef record connection += {
	# Will be set to T when conn is Gozi.
	gozi: bool &default=F;
};

# Regex - make them globals so they are compiled only once!
global rar_regex = /.*\/(stilak|cook|vnc)(32|64)\.rar$/i;
global b64_regex = /^\/[^[:blank:]]+\/([a-zA-Z0-9\/]|_\/?2\/?F|_\/?2\/?B|_\/?0\/?A|_\/?0\/?D){200,}\.[a-zA-Z0-9]+$/;

function log_gozi_detected(c: connection, http_method: string, payload: string)
	{
	local msg = fmt("Potential Gozi banking malware activity between source %s and dest %s with method %s with payload in the sub field",
	    c$id$orig_h, c$id$resp_h, http_method);

	# tag this HTTP session as matching the pattern of Gozi C2 traffic
	add c$http$tags[URI_GOZI_C2];

	# Mark connection as Gozi.
	c$gozi = T;

	if ( enable_detailed_logs )
		{
		local info = Info($ts=network_time(), $uid=c$uid, $id=c$id,
		    $http_method=http_method, $payload=payload);

		Log::write(Gozi::LOG, info);

		NOTICE([ $note=Gozi::C2_Traffic_Observed, $msg=msg, $sub=payload, $conn=c,
		    $identifier=cat(c$id$orig_h, c$id$resp_h) ]);
		}
	else
		{
		# Do not suppress notices.
		NOTICE([ $note=Gozi::C2_Traffic_Observed, $msg=msg, $sub=payload, $conn=c ]);
		}
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	local uri = original_URI;

	# If we already know, we already know.
	if ( c$gozi )
		{
		log_gozi_detected(c, method, uri);
		return;
		}

	# We use the entropy check below to throw out long "normal" URIs that might make it through our checks.
	# Since the underlying Gozi C2 data is encrypted, entropy should be higher than "normal".  I chose this threshold based upon empirical tests.
	if ( uri == rar_regex
	    || ( uri == b64_regex && count_substr(uri, "/") > 10 && find_entropy(uri)$entropy > 4 ) )
		{
		c$gozi = T;
		log_gozi_detected(c, method, uri);
		return;
		}
	}

event zeek_init() &priority=5
	{
	if ( enable_detailed_logs )
		Log::create_stream(Gozi::LOG, [ $columns=Info, $ev=log_gozi, $path="gozi",
		    $policy=Gozi::log_policy ]);
	}
