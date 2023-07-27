module GoziMalwareDetector;

export {
	## Log stream identifier.
	redef enum Log::ID += {
		LOG
	};

	## The notice when the C2 is observed.
	redef enum Notice::Type += {
		GoziActivity,
	};

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
}

global rar_rexex = /.*\/(stilak|cook|vnc)(32|64)\.rar$/;
global b64_regex = /^\/[^[:blank:]]+\/([a-zA-Z0-9\/]|_\/?2\/?F|_\/?2\/?B|_\/?0\/?A|_\/?0\/?D){200,}\.[a-zA-Z0-9]+$/;

redef record connection += {
	gozi: Info &optional;
};

# Initialize logging state.
hook set_session(c: connection)
{
	if ( c?$gozi )
		return;

	c$gozi = Info($ts=network_time(), $uid=c$uid, $id=c$id);
}

function log_gozi_detected(c: connection)
{
	if ( ! c?$gozi )
		return;

	Log::write(GoziMalwareDetector::LOG, c$gozi);

	NOTICE([
	    $note=GoziMalwareDetector::GoziActivity,
	    $msg=fmt("Potential Gozi banking malware activity between source %s and dest %s with method %s and URI %s", c$id$orig_h, c$id$resp_h, c$gozi$http_method, c$gozi$payload),
	    $conn=c,
	    $identifier=cat(c$id$orig_h, c$id$resp_h)]);

	delete c$gozi;
}

event http_request(c: connection, method: string, original_URI: string,
    unescaped_URI: string, version: string)
{
	hook set_session(c);

	local uri: string = to_lower(unescaped_URI);

	if ( uri == rar_rexex || ( unescaped_URI == b64_regex && count_substr(unescaped_URI, "/") > 10 ) ) {
		c$gozi$http_method = method;
		c$gozi$payload = unescaped_URI;
		log_gozi_detected(c);
		return;
	}
}

event zeek_init() &priority=5
{
	Log::create_stream(GoziMalwareDetector::LOG, [
	    $columns=Info,
	    $ev=log_gozi,
	    $path="gozi",
	    $policy=GoziMalwareDetector::log_policy]);
}
