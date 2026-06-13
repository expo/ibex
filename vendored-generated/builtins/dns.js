//#region src/builtins/dns.js
var Buffer = require("buffer").Buffer;
function lookup(hostname, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	options = options || {};
	var family = options.family || 0;
	try {
		var json = __exactDnsLookup(hostname, family);
		var results = JSON.parse(json);
		if (results.length === 0) {
			var err = /* @__PURE__ */ new Error("getaddrinfo ENOTFOUND " + hostname);
			err.code = "ENOTFOUND";
			err.hostname = hostname;
			if (callback) setTimeout(function() {
				callback(err);
			}, 0);
			return;
		}
		var result = results[0];
		if (options.all) {
			if (callback) setTimeout(function() {
				callback(null, results);
			}, 0);
		} else if (callback) setTimeout(function() {
			callback(null, result.address, result.family);
		}, 0);
	} catch (e) {
		var err = /* @__PURE__ */ new Error("getaddrinfo ENOTFOUND " + hostname);
		err.code = "ENOTFOUND";
		err.hostname = hostname;
		if (callback) setTimeout(function() {
			callback(err);
		}, 0);
	}
}
var _hasDnsResolve = typeof __exactDnsResolve === "function";
var _hasDnsReverse = typeof __exactDnsReverse === "function";
var _dnsRecordTypes = {
	A: 1,
	NS: 2,
	CNAME: 5,
	SOA: 6,
	PTR: 12,
	MX: 15,
	TXT: 16,
	AAAA: 28,
	SRV: 33,
	NAPTR: 35,
	ANY: 255,
	CAA: 257
};
var _dnsRecordTypeNames = {};
var _dnsNextMessageId = 1;
for (var _dnsRecordType in _dnsRecordTypes) _dnsRecordTypeNames[_dnsRecordTypes[_dnsRecordType]] = _dnsRecordType;
function _isValidIpAddress(value, family) {
	if (typeof value !== "string") return false;
	try {
		var net = require("net");
		if (!net || typeof net.isIP !== "function") return false;
		var detected = net.isIP(value);
		return family ? detected === family : detected !== 0;
	} catch (_) {
		return false;
	}
}
function _trackResolverCallback(resolver, callback) {
	if (!resolver || typeof callback !== "function") return callback;
	resolver._pendingQueries = (resolver._pendingQueries || 0) + 1;
	var called = false;
	return function() {
		if (!called) {
			called = true;
			resolver._pendingQueries = Math.max(0, (resolver._pendingQueries || 1) - 1);
		}
		return callback.apply(this, arguments);
	};
}
function _invalidArgTypeSuffix(value) {
	if (value == null) return " Received " + value;
	if (typeof value === "function") return " Received function " + value.name;
	if (typeof value === "object") {
		if (value.constructor && value.constructor.name) return " Received an instance of " + value.constructor.name;
		return " Received " + String(value);
	}
	return " Received type " + typeof value + " (" + String(value) + ")";
}
function _createDnsError(code, syscall, hostname, message) {
	var err = new Error(message || (syscall || "query") + " " + code + (hostname ? " " + hostname : ""));
	err.code = code;
	err.errno = code;
	if (syscall) err.syscall = syscall;
	if (hostname !== void 0) err.hostname = hostname;
	return err;
}
function _getResolverSyscall(rrtype, isReverseLookup) {
	if (isReverseLookup) return "getHostByAddr";
	if (rrtype === "AAAA") return "queryAaaa";
	if (rrtype === "ANY") return "queryAny";
	return "query" + rrtype;
}
function _nextDnsMessageId() {
	_dnsNextMessageId = _dnsNextMessageId + 1 & 65535;
	if (_dnsNextMessageId === 0) _dnsNextMessageId = 1;
	return _dnsNextMessageId;
}
function _encodeDnsName(name) {
	if (!name) return Buffer.from([0]);
	var labels = name.split(".");
	var parts = [];
	for (var i = 0; i < labels.length; i++) {
		var label = labels[i];
		parts.push(Buffer.from([label.length]));
		parts.push(Buffer.from(label, "ascii"));
	}
	parts.push(Buffer.from([0]));
	return Buffer.concat(parts);
}
function _readDnsName(buffer, offset, depth) {
	if (depth > 20) throw new Error("Too many DNS label pointers");
	var labels = [];
	var position = offset;
	var consumed = 0;
	while (position < buffer.length) {
		var length = buffer[position];
		if (length === 0) return {
			name: labels.join("."),
			nextOffset: offset + consumed + 1
		};
		if ((length & 192) === 192) {
			if (position + 1 >= buffer.length) throw new Error("Truncated DNS pointer");
			var pointed = _readDnsName(buffer, (length & 63) << 8 | buffer[position + 1], depth + 1);
			if (pointed.name) labels.push(pointed.name);
			return {
				name: labels.join("."),
				nextOffset: offset + consumed + 2
			};
		}
		position += 1;
		consumed += 1 + length;
		if (position + length > buffer.length) throw new Error("Truncated DNS label");
		labels.push(buffer.toString("ascii", position, position + length));
		position += length;
	}
	throw new Error("Truncated DNS name");
}
function _formatIPv6Address(buffer, offset) {
	var groups = [];
	var i;
	for (i = 0; i < 8; i++) groups.push(buffer.readUInt16BE(offset + i * 2).toString(16));
	var bestStart = -1;
	var bestLength = 0;
	var runStart = -1;
	var runLength = 0;
	for (i = 0; i <= groups.length; i++) {
		if (i < groups.length && groups[i] === "0") {
			if (runStart === -1) {
				runStart = i;
				runLength = 1;
			} else runLength += 1;
			continue;
		}
		if (runLength > bestLength) {
			bestStart = runStart;
			bestLength = runLength;
		}
		runStart = -1;
		runLength = 0;
	}
	if (bestLength > 1) {
		var parts = groups.slice(0, bestStart).concat([""]).concat(groups.slice(bestStart + bestLength));
		if (bestStart === 0) parts.unshift("");
		if (bestStart + bestLength === groups.length) parts.push("");
		return parts.join(":").replace(/:{3,}/, "::");
	}
	return groups.join(":");
}
function _parseServer(server) {
	var address = server;
	var port = 53;
	if (server.charAt(0) === "[") {
		var bracketIndex = server.indexOf("]");
		if (bracketIndex !== -1) {
			address = server.slice(1, bracketIndex);
			if (server.charAt(bracketIndex + 1) === ":") {
				var bracketPort = parseInt(server.slice(bracketIndex + 2), 10);
				if (!isNaN(bracketPort)) port = bracketPort;
			}
		}
	} else {
		var firstColon = server.indexOf(":");
		var lastColon = server.lastIndexOf(":");
		if (firstColon !== -1 && firstColon === lastColon) {
			var maybePort = parseInt(server.slice(lastColon + 1), 10);
			if (!isNaN(maybePort)) {
				address = server.slice(0, lastColon);
				port = maybePort;
			}
		}
	}
	return {
		address,
		port,
		family: _isValidIpAddress(address, 6) ? 6 : 4
	};
}
function _buildDnsQueryPacket(messageId, domain, rrtype) {
	var question = _encodeDnsName(domain);
	var packet = Buffer.alloc(12 + question.length + 4);
	packet.writeUInt16BE(messageId, 0);
	packet.writeUInt16BE(256, 2);
	packet.writeUInt16BE(1, 4);
	packet.writeUInt16BE(0, 6);
	packet.writeUInt16BE(0, 8);
	packet.writeUInt16BE(0, 10);
	question.copy(packet, 12);
	var offset = 12 + question.length;
	packet.writeUInt16BE(_dnsRecordTypes[rrtype] || _dnsRecordTypes.A, offset);
	packet.writeUInt16BE(1, offset + 2);
	return packet;
}
function _toReverseLookupName(ip) {
	if (_isValidIpAddress(ip, 4)) return ip.split(".").reverse().join(".") + ".in-addr.arpa";
	if (_isValidIpAddress(ip, 6)) {
		var expanded = [];
		var segments = ip.toLowerCase().split("::");
		var head = segments[0] ? segments[0].split(":") : [];
		var tail = segments[1] ? segments[1].split(":") : [];
		var missing = 8 - (head.length + tail.length);
		var i;
		for (i = 0; i < head.length; i++) expanded.push(("0000" + head[i]).slice(-4));
		for (i = 0; i < missing; i++) expanded.push("0000");
		for (i = 0; i < tail.length; i++) expanded.push(("0000" + tail[i]).slice(-4));
		return expanded.join("").split("").reverse().join(".") + ".ip6.arpa";
	}
	return ip;
}
function _parseTxtEntries(buffer, offset, end) {
	var entries = [];
	var position = offset;
	while (position < end) {
		var entryLength = buffer[position];
		position += 1;
		if (position + entryLength > end) throw new Error("Truncated TXT record");
		entries.push(buffer.toString("utf8", position, position + entryLength));
		position += entryLength;
	}
	if (position !== end) throw new Error("Invalid TXT record length");
	return entries;
}
function _parseDnsRecord(buffer, offset) {
	offset = _readDnsName(buffer, offset, 0).nextOffset;
	if (offset + 10 > buffer.length) throw new Error("Truncated DNS record header");
	var typeCode = buffer.readUInt16BE(offset);
	var ttl = buffer.readUInt32BE(offset + 4);
	var dataLength = buffer.readUInt16BE(offset + 8);
	var dataOffset = offset + 10;
	var dataEnd = dataOffset + dataLength;
	if (dataEnd > buffer.length) throw new Error("Truncated DNS record data");
	var record = {
		type: _dnsRecordTypeNames[typeCode] || String(typeCode),
		ttl
	};
	var info;
	switch (typeCode) {
		case 1:
			if (dataLength !== 4) throw new Error("Invalid A record length");
			record.address = buffer[dataOffset] + "." + buffer[dataOffset + 1] + "." + buffer[dataOffset + 2] + "." + buffer[dataOffset + 3];
			break;
		case 28:
			if (dataLength !== 16) throw new Error("Invalid AAAA record length");
			record.address = _formatIPv6Address(buffer, dataOffset);
			break;
		case 15:
			if (dataLength < 3) throw new Error("Invalid MX record length");
			record.priority = buffer.readUInt16BE(dataOffset);
			info = _readDnsName(buffer, dataOffset + 2, 0);
			if (info.nextOffset !== dataEnd) throw new Error("Invalid MX record payload");
			record.exchange = info.name;
			break;
		case 16:
			record.entries = _parseTxtEntries(buffer, dataOffset, dataEnd);
			break;
		case 2:
		case 5:
		case 12:
			info = _readDnsName(buffer, dataOffset, 0);
			if (info.nextOffset !== dataEnd) throw new Error("Invalid domain record payload");
			record.value = info.name;
			break;
		case 6:
			var mname = _readDnsName(buffer, dataOffset, 0);
			var rname = _readDnsName(buffer, mname.nextOffset, 0);
			if (rname.nextOffset + 20 !== dataEnd) throw new Error("Invalid SOA record length");
			record.nsname = mname.name;
			record.hostmaster = rname.name;
			record.serial = buffer.readUInt32BE(rname.nextOffset);
			record.refresh = buffer.readUInt32BE(rname.nextOffset + 4);
			record.retry = buffer.readUInt32BE(rname.nextOffset + 8);
			record.expire = buffer.readUInt32BE(rname.nextOffset + 12);
			record.minttl = buffer.readUInt32BE(rname.nextOffset + 16);
			break;
		case 33:
			if (dataLength < 7) throw new Error("Invalid SRV record length");
			record.priority = buffer.readUInt16BE(dataOffset);
			record.weight = buffer.readUInt16BE(dataOffset + 2);
			record.port = buffer.readUInt16BE(dataOffset + 4);
			info = _readDnsName(buffer, dataOffset + 6, 0);
			if (info.nextOffset !== dataEnd) throw new Error("Invalid SRV record payload");
			record.name = info.name;
			break;
		case 35:
			if (dataLength < 5) throw new Error("Invalid NAPTR record length");
			record.order = buffer.readUInt16BE(dataOffset);
			record.preference = buffer.readUInt16BE(dataOffset + 2);
			var flagsLength = buffer[dataOffset + 4];
			var flagsOffset = dataOffset + 5;
			var serviceLengthOffset = flagsOffset + flagsLength;
			if (serviceLengthOffset + 1 > dataEnd) throw new Error("Invalid NAPTR record flags");
			record.flags = buffer.toString("utf8", flagsOffset, flagsOffset + flagsLength);
			var serviceLength = buffer[serviceLengthOffset];
			var serviceOffset = serviceLengthOffset + 1;
			var regexpLengthOffset = serviceOffset + serviceLength;
			if (regexpLengthOffset + 1 > dataEnd) throw new Error("Invalid NAPTR record service");
			record.service = buffer.toString("utf8", serviceOffset, serviceOffset + serviceLength);
			var regexpLength = buffer[regexpLengthOffset];
			var regexpOffset = regexpLengthOffset + 1;
			var replacementOffset = regexpOffset + regexpLength;
			if (replacementOffset > dataEnd) throw new Error("Invalid NAPTR record regexp");
			record.regexp = buffer.toString("utf8", regexpOffset, regexpOffset + regexpLength);
			info = _readDnsName(buffer, replacementOffset, 0);
			if (info.nextOffset !== dataEnd) throw new Error("Invalid NAPTR record replacement");
			record.replacement = info.name;
			break;
		case 257:
			if (dataLength < 2) throw new Error("Invalid CAA record length");
			record.critical = buffer[dataOffset];
			var tagLength = buffer[dataOffset + 1];
			var valueOffset = dataOffset + 2 + tagLength;
			if (valueOffset > dataEnd) throw new Error("Invalid CAA record tag length");
			record.tag = buffer.toString("ascii", dataOffset + 2, dataOffset + 2 + tagLength);
			record.value = buffer.toString("utf8", valueOffset, dataEnd);
			if (record.tag === "issue") record.issue = record.value;
			break;
		default:
			record.data = buffer.slice(dataOffset, dataEnd);
			break;
	}
	return {
		record,
		nextOffset: dataEnd
	};
}
function _parseDnsResponsePacket(buffer, expectedMessageId) {
	if (!buffer || buffer.length < 12) throw new Error("Truncated DNS packet");
	if (buffer.readUInt16BE(0) !== expectedMessageId) return null;
	var rcode = buffer.readUInt16BE(2) & 15;
	if (rcode !== 0) throw new Error("DNS query failed with rcode " + rcode);
	var questionCount = buffer.readUInt16BE(4);
	var answerCount = buffer.readUInt16BE(6);
	var authorityCount = buffer.readUInt16BE(8);
	var additionalCount = buffer.readUInt16BE(10);
	var offset = 12;
	var i;
	for (i = 0; i < questionCount; i++) {
		offset = _readDnsName(buffer, offset, 0).nextOffset + 4;
		if (offset > buffer.length) throw new Error("Truncated DNS question");
	}
	var answers = [];
	for (i = 0; i < answerCount; i++) {
		var parsedAnswer = _parseDnsRecord(buffer, offset);
		answers.push(parsedAnswer.record);
		offset = parsedAnswer.nextOffset;
	}
	for (i = 0; i < authorityCount + additionalCount; i++) offset = _parseDnsRecord(buffer, offset).nextOffset;
	return { answers };
}
function _formatAnyRecord(record) {
	if (record.type === "A" || record.type === "AAAA") return {
		type: record.type,
		address: record.address,
		ttl: record.ttl
	};
	if (record.type === "MX") return {
		type: "MX",
		exchange: record.exchange,
		priority: record.priority
	};
	if (record.type === "TXT") return {
		type: "TXT",
		entries: record.entries
	};
	if (record.type === "NS" || record.type === "CNAME" || record.type === "PTR") return {
		type: record.type,
		value: record.value
	};
	if (record.type === "SOA") return {
		type: "SOA",
		nsname: record.nsname,
		hostmaster: record.hostmaster,
		serial: record.serial,
		refresh: record.refresh,
		retry: record.retry,
		expire: record.expire,
		minttl: record.minttl
	};
	if (record.type === "CAA") return {
		type: "CAA",
		critical: record.critical,
		issue: record.issue
	};
	if (record.type === "SRV") return {
		type: "SRV",
		name: record.name,
		port: record.port,
		priority: record.priority,
		weight: record.weight
	};
	if (record.type === "NAPTR") return {
		type: "NAPTR",
		flags: record.flags,
		service: record.service,
		regexp: record.regexp,
		replacement: record.replacement,
		order: record.order,
		preference: record.preference
	};
	return record;
}
function _extractResolverResult(rrtype, records, options, isReverseLookup) {
	var matches = [];
	var i;
	for (i = 0; i < records.length; i++) if (rrtype === "ANY" || records[i].type === rrtype) matches.push(records[i]);
	if (rrtype === "A" || rrtype === "AAAA") {
		var addresses = [];
		for (i = 0; i < matches.length; i++) if (options && options.ttl) addresses.push({
			address: matches[i].address,
			ttl: matches[i].ttl
		});
		else addresses.push(matches[i].address);
		return addresses;
	}
	if (rrtype === "MX") {
		var exchanges = [];
		for (i = 0; i < matches.length; i++) exchanges.push({
			exchange: matches[i].exchange,
			priority: matches[i].priority
		});
		return exchanges;
	}
	if (rrtype === "TXT") {
		var entries = [];
		for (i = 0; i < matches.length; i++) entries.push(matches[i].entries);
		return entries;
	}
	if (rrtype === "SOA") {
		if (matches.length === 0) return null;
		return {
			nsname: matches[0].nsname,
			hostmaster: matches[0].hostmaster,
			serial: matches[0].serial,
			refresh: matches[0].refresh,
			retry: matches[0].retry,
			expire: matches[0].expire,
			minttl: matches[0].minttl
		};
	}
	if (rrtype === "ANY") {
		var anyRecords = [];
		for (i = 0; i < matches.length; i++) anyRecords.push(_formatAnyRecord(matches[i]));
		return anyRecords;
	}
	if (rrtype === "SRV") {
		var services = [];
		for (i = 0; i < matches.length; i++) services.push({
			name: matches[i].name,
			port: matches[i].port,
			priority: matches[i].priority,
			weight: matches[i].weight
		});
		return services;
	}
	if (rrtype === "NAPTR") {
		var naptrRecords = [];
		for (i = 0; i < matches.length; i++) naptrRecords.push({
			flags: matches[i].flags,
			service: matches[i].service,
			regexp: matches[i].regexp,
			replacement: matches[i].replacement,
			order: matches[i].order,
			preference: matches[i].preference
		});
		return naptrRecords;
	}
	if (rrtype === "CAA") {
		var caaRecords = [];
		for (i = 0; i < matches.length; i++) caaRecords.push({
			critical: matches[i].critical,
			issue: matches[i].issue
		});
		return caaRecords;
	}
	var values = [];
	for (i = 0; i < matches.length; i++) if (matches[i].value !== void 0) values.push(matches[i].value);
	else if (matches[i].address !== void 0) values.push(matches[i].address);
	else values.push(matches[i]);
	if (isReverseLookup) return values;
	return values;
}
function _usesCustomResolverQueries(resolver) {
	return !!(resolver && resolver._usesCustomServers);
}
function _finishResolverQuery(query, err, result) {
	if (!query || query.finished) return;
	query.finished = true;
	if (query.timer) {
		clearTimeout(query.timer);
		query.timer = null;
	}
	if (query.socket) {
		query.socket.removeAllListeners("message");
		query.socket.removeAllListeners("error");
		try {
			query.socket.close();
		} catch (_) {}
		query.socket = null;
	}
	var resolver = query.resolver;
	if (resolver && resolver._activeQueries) {
		var index = resolver._activeQueries.indexOf(query);
		if (index !== -1) resolver._activeQueries.splice(index, 1);
		resolver._pendingQueries = Math.max(0, (resolver._pendingQueries || 1) - 1);
	}
	if (typeof query.callback === "function") setTimeout(function() {
		query.callback(err, result);
	}, 0);
}
function _getResolverAttemptTimeout(resolver, attemptIndex) {
	var timeout = typeof resolver._timeout === "number" && resolver._timeout >= 0 ? resolver._timeout : 5e3;
	timeout = timeout * Math.pow(2, attemptIndex);
	if (typeof resolver._maxTimeout === "number") timeout = Math.min(timeout, resolver._maxTimeout);
	return timeout;
}
function _sendResolverAttempt(query) {
	if (query.finished) return;
	query.attempt += 1;
	if (query.timer) clearTimeout(query.timer);
	var timeout = _getResolverAttemptTimeout(query.resolver, query.attempt - 1);
	query.timer = setTimeout(function() {
		if (query.finished) return;
		if (query.attempt < query.maxAttempts) {
			_sendResolverAttempt(query);
			return;
		}
		_finishResolverQuery(query, _createDnsError("ETIMEOUT", query.syscall, query.hostname));
	}, timeout);
	query.socket.send(query.packet, query.server.port, query.server.address, function(sendErr) {
		if (sendErr) _finishResolverQuery(query, _createDnsError(sendErr.code || "EBADRESP", query.syscall, query.hostname, sendErr.message));
	});
}
function _startResolverQuery(resolver, hostname, rrtype, options, callback, isReverseLookup) {
	var dgram = require("dgram");
	var server = _parseServer((resolver._servers && resolver._servers.length ? resolver._servers : _servers)[0]);
	var query = {
		resolver,
		hostname,
		rrtype,
		options: options || {},
		callback,
		server,
		syscall: _getResolverSyscall(rrtype, isReverseLookup),
		maxAttempts: typeof resolver._tries === "number" && resolver._tries > 0 ? resolver._tries : 1,
		attempt: 0,
		finished: false
	};
	var domain = isReverseLookup ? _toReverseLookupName(hostname) : hostname;
	query.id = _nextDnsMessageId();
	query.packet = _buildDnsQueryPacket(query.id, domain, rrtype);
	query.socket = dgram.createSocket(server.family === 6 ? "udp6" : "udp4");
	resolver._activeQueries.push(query);
	resolver._pendingQueries = (resolver._pendingQueries || 0) + 1;
	query.socket.on("message", function(msg) {
		if (query.finished) return;
		var parsed;
		try {
			parsed = _parseDnsResponsePacket(msg, query.id);
		} catch (_) {
			_finishResolverQuery(query, _createDnsError("EBADRESP", query.syscall, query.hostname));
			return;
		}
		if (!parsed) return;
		var result;
		try {
			result = _extractResolverResult(rrtype, parsed.answers, query.options, isReverseLookup);
		} catch (_) {
			_finishResolverQuery(query, _createDnsError("EBADRESP", query.syscall, query.hostname));
			return;
		}
		_finishResolverQuery(query, null, result);
	});
	query.socket.on("error", function(err) {
		if (query.finished) return;
		_finishResolverQuery(query, _createDnsError(err && err.code ? err.code : "EBADRESP", query.syscall, query.hostname, err && err.message ? err.message : String(err)));
	});
	var localAddress = server.family === 6 ? resolver._localAddressIPv6 : resolver._localAddressIPv4;
	if (localAddress) query.socket.bind(0, localAddress, function() {
		_sendResolverAttempt(query);
	});
	else _sendResolverAttempt(query);
}
function _cancelResolverQueries(resolver) {
	if (!resolver || !resolver._activeQueries || resolver._activeQueries.length === 0) return;
	var pending = resolver._activeQueries.slice();
	for (var i = 0; i < pending.length; i++) _finishResolverQuery(pending[i], _createDnsError("ECANCELLED", pending[i].syscall, pending[i].hostname));
}
function _resolveViaQuery(hostname, rrtype, callback) {
	if (!_hasDnsResolve) {
		var err = /* @__PURE__ */ new Error("DNS record type " + rrtype + " requires native resolver");
		err.code = "ENOTIMP";
		if (callback) setTimeout(function() {
			callback(err);
		}, 0);
		return;
	}
	try {
		var json = __exactDnsResolve(hostname, rrtype);
		var records = JSON.parse(json);
		if (callback) setTimeout(function() {
			callback(null, records);
		}, 0);
	} catch (e) {
		var err2 = /* @__PURE__ */ new Error("query" + rrtype + " " + (e.message || String(e)));
		err2.code = "ENOTFOUND";
		err2.hostname = hostname;
		if (callback) setTimeout(function() {
			callback(err2);
		}, 0);
	}
}
function resolve(hostname, rrtype, callback) {
	if (typeof rrtype === "function") {
		callback = rrtype;
		rrtype = "A";
	}
	if (rrtype === "A") lookup(hostname, {
		family: 4,
		all: true
	}, function(err, results) {
		if (err) {
			callback(err);
			return;
		}
		var addresses = [];
		for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
		callback(null, addresses);
	});
	else if (rrtype === "AAAA") lookup(hostname, {
		family: 6,
		all: true
	}, function(err, results) {
		if (err) {
			callback(err);
			return;
		}
		var addresses = [];
		for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
		callback(null, addresses);
	});
	else _resolveViaQuery(hostname, rrtype, callback);
}
function resolve4(hostname, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	lookup(hostname, {
		family: 4,
		all: true
	}, function(err, results) {
		if (err) {
			callback(err);
			return;
		}
		var addresses = [];
		for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
		callback(null, addresses);
	});
}
function resolve6(hostname, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	lookup(hostname, {
		family: 6,
		all: true
	}, function(err, results) {
		if (err) {
			callback(err);
			return;
		}
		var addresses = [];
		for (var i = 0; i < results.length; i++) addresses.push(results[i].address);
		callback(null, addresses);
	});
}
function resolveMx(hostname, callback) {
	_resolveViaQuery(hostname, "MX", callback);
}
function resolveTxt(hostname, callback) {
	_resolveViaQuery(hostname, "TXT", callback);
}
function resolveSrv(hostname, callback) {
	_resolveViaQuery(hostname, "SRV", callback);
}
function resolveNs(hostname, callback) {
	_resolveViaQuery(hostname, "NS", callback);
}
function resolveCname(hostname, callback) {
	_resolveViaQuery(hostname, "CNAME", callback);
}
function resolveSoa(hostname, callback) {
	_resolveViaQuery(hostname, "SOA", function(err, records) {
		if (err) {
			callback(err);
			return;
		}
		callback(null, records && records.length > 0 ? records[0] : null);
	});
}
function resolvePtr(hostname, callback) {
	_resolveViaQuery(hostname, "PTR", callback);
}
function resolveCaa(hostname, callback) {
	_resolveViaQuery(hostname, "CAA", callback);
}
function resolveNaptr(hostname, callback) {
	_resolveViaQuery(hostname, "NAPTR", callback);
}
function reverse(ip, callback) {
	if (!_hasDnsReverse) {
		var err = /* @__PURE__ */ new Error("dns.reverse requires native resolver");
		err.code = "ENOTIMP";
		if (callback) setTimeout(function() {
			callback(err);
		}, 0);
		return;
	}
	try {
		var json = __exactDnsReverse(ip);
		var hostnames = JSON.parse(json);
		if (callback) setTimeout(function() {
			callback(null, hostnames);
		}, 0);
	} catch (e) {
		var err2 = /* @__PURE__ */ new Error("getHostByAddr " + (e.message || String(e)));
		err2.code = "ENOTFOUND";
		if (callback) setTimeout(function() {
			callback(err2);
		}, 0);
	}
}
function _promisify1(fn) {
	return function(arg1) {
		return new Promise(function(res, reject) {
			fn(arg1, function(err, result) {
				if (err) reject(err);
				else res(result);
			});
		});
	};
}
var promises = {
	lookup: function(hostname, options) {
		return new Promise(function(resolve, reject) {
			lookup(hostname, options || {}, function(err, address, family) {
				if (err) reject(err);
				else if (options && options.all) resolve(address || []);
				else resolve({
					address,
					family
				});
			});
		});
	},
	resolve: function(hostname, rrtype) {
		return new Promise(function(res, reject) {
			resolve(hostname, rrtype || "A", function(err, addresses) {
				if (err) reject(err);
				else res(addresses);
			});
		});
	},
	resolve4: function(hostname, options) {
		return new Promise(function(res, reject) {
			resolve4(hostname, options || {}, function(err, addresses) {
				if (err) reject(err);
				else res(addresses);
			});
		});
	},
	resolve6: function(hostname, options) {
		return new Promise(function(res, reject) {
			resolve6(hostname, options || {}, function(err, addresses) {
				if (err) reject(err);
				else res(addresses);
			});
		});
	},
	resolveMx: _promisify1(resolveMx),
	resolveTxt: _promisify1(resolveTxt),
	resolveSrv: _promisify1(resolveSrv),
	resolveNs: _promisify1(resolveNs),
	resolveCname: _promisify1(resolveCname),
	resolveSoa: _promisify1(resolveSoa),
	resolvePtr: _promisify1(resolvePtr),
	resolveCaa: _promisify1(resolveCaa),
	resolveNaptr: _promisify1(resolveNaptr),
	resolveAny: _promisify1(resolveAny),
	reverse: _promisify1(reverse),
	lookupService: function(address, port) {
		return new Promise(function(res, reject) {
			lookupService(address, port, function(err, hostname, service) {
				if (err) reject(err);
				else res({
					hostname,
					service
				});
			});
		});
	},
	setDefaultResultOrder,
	getDefaultResultOrder,
	setServers,
	getServers,
	Resolver
};
var _defaultResultOrder = "verbatim";
function setDefaultResultOrder(order) {
	if (order !== "ipv4first" && order !== "ipv6first" && order !== "verbatim") {
		var err = /* @__PURE__ */ new TypeError("The argument 'order' must be one of: 'ipv4first', 'ipv6first', 'verbatim'. Received '" + order + "'");
		err.code = "ERR_INVALID_ARG_VALUE";
		throw err;
	}
	_defaultResultOrder = order;
}
function getDefaultResultOrder() {
	return _defaultResultOrder;
}
var _servers = ["127.0.0.1"];
function getServers() {
	return _servers.slice();
}
function setServers(servers) {
	if (!Array.isArray(servers)) {
		var err = /* @__PURE__ */ new TypeError("The \"servers\" argument must be an instance of Array." + _invalidArgTypeSuffix(servers));
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	for (var i = 0; i < servers.length; i++) if (typeof servers[i] !== "string") {
		var err = /* @__PURE__ */ new TypeError("The \"servers[" + i + "]\" argument must be of type string." + _invalidArgTypeSuffix(servers[i]));
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	_servers = servers.slice();
}
function lookupService(address, port, callback) {
	if (typeof address !== "string") {
		var err = /* @__PURE__ */ new TypeError("The \"address\" argument must be of type string. Received type " + typeof address);
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	if (typeof port !== "number") {
		var err = /* @__PURE__ */ new TypeError("The \"port\" argument must be of type number. Received type " + typeof port);
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	if (port < 0 || port > 65535 || port % 1 !== 0) {
		var err = /* @__PURE__ */ new RangeError("The value of \"port\" is out of range. It must be >= 0 && <= 65535. Received " + port);
		err.code = "ERR_SOCKET_BAD_PORT";
		throw err;
	}
	if (callback) setTimeout(function() {
		callback(null, address, String(port));
	}, 0);
}
function resolveAny(hostname, callback) {
	_resolveViaQuery(hostname, "ANY", callback);
}
function Resolver(options) {
	if (!(this instanceof Resolver)) return new Resolver(options);
	this._servers = _servers.slice();
	this._pendingQueries = 0;
	this._activeQueries = [];
	this._usesCustomServers = false;
	this._localAddressIPv4 = void 0;
	this._localAddressIPv6 = void 0;
	var self = this;
	this._handle = {
		getServers: function() {
			return self._servers.slice();
		},
		setServers: function(servers) {
			self._servers = servers.slice();
		},
		cancel: function() {
			_cancelResolverQueries(self);
		}
	};
	if (options && options.timeout !== void 0) {
		if (typeof options.timeout !== "number") {
			var err = /* @__PURE__ */ new TypeError("The \"options.timeout\" property must be of type number. Received type " + typeof options.timeout);
			err.code = "ERR_INVALID_ARG_TYPE";
			throw err;
		}
		if (options.timeout < -1 || options.timeout > 2147483647 || options.timeout % 1 !== 0) {
			var err = /* @__PURE__ */ new RangeError("The value of \"options.timeout\" is out of range. It must be >= -1 && <= 2147483647. Received " + options.timeout);
			err.code = "ERR_OUT_OF_RANGE";
			throw err;
		}
		this._timeout = options.timeout;
	}
	if (options && options.tries !== void 0) {
		if (typeof options.tries !== "number") {
			var err = /* @__PURE__ */ new TypeError("The \"options.tries\" property must be of type number. Received type " + typeof options.tries);
			err.code = "ERR_INVALID_ARG_TYPE";
			throw err;
		}
		this._tries = options.tries;
	}
	if (options && options.maxTimeout !== void 0) {
		if (typeof options.maxTimeout !== "number") {
			var maxTimeoutTypeErr = /* @__PURE__ */ new TypeError("The \"options.maxTimeout\" property must be of type number. Received type " + typeof options.maxTimeout);
			maxTimeoutTypeErr.code = "ERR_INVALID_ARG_TYPE";
			throw maxTimeoutTypeErr;
		}
		if (!isFinite(options.maxTimeout) || options.maxTimeout <= 0 || options.maxTimeout > 2147483647 || options.maxTimeout % 1 !== 0) {
			var maxTimeoutRangeErr = /* @__PURE__ */ new RangeError("The value of \"options.maxTimeout\" is out of range. It must be > 0 && <= 2147483647. Received " + options.maxTimeout);
			maxTimeoutRangeErr.code = "ERR_OUT_OF_RANGE";
			throw maxTimeoutRangeErr;
		}
		this._maxTimeout = options.maxTimeout;
	}
}
Resolver.prototype.getServers = function() {
	if (this._handle && typeof this._handle.getServers === "function") {
		var servers = this._handle.getServers();
		return Array.isArray(servers) ? servers.slice() : [];
	}
	return this._servers.slice();
};
Resolver.prototype.setServers = function(servers) {
	if (!Array.isArray(servers)) {
		var err = /* @__PURE__ */ new TypeError("The \"servers\" argument must be an instance of Array." + _invalidArgTypeSuffix(servers));
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	for (var i = 0; i < servers.length; i++) if (typeof servers[i] !== "string") {
		var err = /* @__PURE__ */ new TypeError("The \"servers[" + i + "]\" argument must be of type string." + _invalidArgTypeSuffix(servers[i]));
		err.code = "ERR_INVALID_ARG_TYPE";
		throw err;
	}
	if (this._pendingQueries > 0) {
		var pendingErr = /* @__PURE__ */ new Error("c-ares failed to set servers: \"There are pending queries.\" [" + servers.join(", ") + "]");
		pendingErr.code = "ERR_DNS_SET_SERVERS_FAILED";
		throw pendingErr;
	}
	this._servers = servers.slice();
	this._usesCustomServers = true;
	if (this._handle && typeof this._handle.setServers === "function") this._handle.setServers(this._servers);
};
Resolver.prototype.setLocalAddress = function(ipv4, ipv6) {
	if (arguments.length === 0) throw new Error("At least one local address is required");
	if (ipv4 !== void 0 && typeof ipv4 !== "string") {
		var ipv4TypeErr = /* @__PURE__ */ new TypeError("The \"ipv4\" argument must be of type string. Received type " + typeof ipv4);
		ipv4TypeErr.code = "ERR_INVALID_ARG_TYPE";
		throw ipv4TypeErr;
	}
	if (ipv6 !== void 0 && typeof ipv6 !== "string") {
		var ipv6TypeErr = /* @__PURE__ */ new TypeError("The \"ipv6\" argument must be of type string. Received type " + typeof ipv6);
		ipv6TypeErr.code = "ERR_INVALID_ARG_TYPE";
		throw ipv6TypeErr;
	}
	if (arguments.length === 1) {
		if (_isValidIpAddress(ipv4, 4)) {
			this._localAddressIPv4 = ipv4;
			return;
		}
		if (_isValidIpAddress(ipv4, 6)) {
			this._localAddressIPv6 = ipv4;
			return;
		}
		throw new Error("The \"ipv4\" argument must be a valid IP address");
	}
	if (ipv4 !== void 0 && !_isValidIpAddress(ipv4, 4)) throw new Error("The \"ipv4\" argument must be a valid IPv4 address");
	if (ipv6 !== void 0 && !_isValidIpAddress(ipv6, 6)) throw new Error("The \"ipv6\" argument must be a valid IPv6 address");
	if (ipv4 !== void 0) this._localAddressIPv4 = ipv4;
	if (ipv6 !== void 0) this._localAddressIPv6 = ipv6;
};
Resolver.prototype.resolve = function(hostname, rrtype, callback) {
	if (typeof rrtype === "function") {
		callback = rrtype;
		rrtype = void 0;
	}
	rrtype = rrtype || "A";
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, rrtype, {}, callback, false);
	resolve(hostname, rrtype, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolve4 = function(hostname, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "A", options || {}, callback, false);
	resolve4(hostname, options, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolve6 = function(hostname, options, callback) {
	if (typeof options === "function") {
		callback = options;
		options = {};
	}
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "AAAA", options || {}, callback, false);
	resolve6(hostname, options, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolveMx = function(hostname, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "MX", {}, callback, false);
	resolveMx(hostname, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolveTxt = function(hostname, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "TXT", {}, callback, false);
	resolveTxt(hostname, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolveSrv = function(hostname, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "SRV", {}, callback, false);
	resolveSrv(hostname, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolveNs = function(hostname, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "NS", {}, callback, false);
	resolveNs(hostname, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolveCname = function(hostname, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "CNAME", {}, callback, false);
	resolveCname(hostname, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolveSoa = function(hostname, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "SOA", {}, callback, false);
	resolveSoa(hostname, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolvePtr = function(hostname, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "PTR", {}, callback, false);
	resolvePtr(hostname, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolveCaa = function(hostname, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "CAA", {}, callback, false);
	resolveCaa(hostname, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolveNaptr = function(hostname, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "NAPTR", {}, callback, false);
	resolveNaptr(hostname, _trackResolverCallback(this, callback));
};
Resolver.prototype.resolveAny = function(hostname, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, hostname, "ANY", {}, callback, false);
	resolveAny(hostname, _trackResolverCallback(this, callback));
};
Resolver.prototype.reverse = function(ip, callback) {
	if (_usesCustomResolverQueries(this)) return _startResolverQuery(this, ip, "PTR", {}, callback, true);
	reverse(ip, _trackResolverCallback(this, callback));
};
Resolver.prototype.cancel = function() {
	_cancelResolverQueries(this);
	if (this._handle && typeof this._handle.cancel === "function") this._handle.cancel();
};
function PromiseResolver(options) {
	if (!(this instanceof PromiseResolver)) return new PromiseResolver(options);
	Resolver.call(this, options);
}
PromiseResolver.prototype = Object.create(Resolver.prototype);
PromiseResolver.prototype.constructor = PromiseResolver;
function _promiseResolverCall(ctx, method, args) {
	return new Promise(function(resolvePromise, rejectPromise) {
		var callArgs = args.slice();
		callArgs.push(function(err, result) {
			if (err) rejectPromise(err);
			else resolvePromise(result);
		});
		Resolver.prototype[method].apply(ctx, callArgs);
	});
}
PromiseResolver.prototype.resolve = function(hostname, rrtype) {
	return _promiseResolverCall(this, "resolve", [hostname, rrtype || "A"]);
};
PromiseResolver.prototype.resolve4 = function(hostname, options) {
	return _promiseResolverCall(this, "resolve4", [hostname, options || {}]);
};
PromiseResolver.prototype.resolve6 = function(hostname, options) {
	return _promiseResolverCall(this, "resolve6", [hostname, options || {}]);
};
PromiseResolver.prototype.resolveMx = function(hostname) {
	return _promiseResolverCall(this, "resolveMx", [hostname]);
};
PromiseResolver.prototype.resolveTxt = function(hostname) {
	return _promiseResolverCall(this, "resolveTxt", [hostname]);
};
PromiseResolver.prototype.resolveSrv = function(hostname) {
	return _promiseResolverCall(this, "resolveSrv", [hostname]);
};
PromiseResolver.prototype.resolveNs = function(hostname) {
	return _promiseResolverCall(this, "resolveNs", [hostname]);
};
PromiseResolver.prototype.resolveCname = function(hostname) {
	return _promiseResolverCall(this, "resolveCname", [hostname]);
};
PromiseResolver.prototype.resolveSoa = function(hostname) {
	return _promiseResolverCall(this, "resolveSoa", [hostname]);
};
PromiseResolver.prototype.resolvePtr = function(hostname) {
	return _promiseResolverCall(this, "resolvePtr", [hostname]);
};
PromiseResolver.prototype.resolveCaa = function(hostname) {
	return _promiseResolverCall(this, "resolveCaa", [hostname]);
};
PromiseResolver.prototype.resolveNaptr = function(hostname) {
	return _promiseResolverCall(this, "resolveNaptr", [hostname]);
};
PromiseResolver.prototype.resolveAny = function(hostname) {
	return _promiseResolverCall(this, "resolveAny", [hostname]);
};
PromiseResolver.prototype.reverse = function(ip) {
	return _promiseResolverCall(this, "reverse", [ip]);
};
var NODATA = "ENODATA";
var FORMERR = "EFORMERR";
var SERVFAIL = "ESERVFAIL";
var NOTFOUND = "ENOTFOUND";
var NOTIMP = "ENOTIMP";
var REFUSED = "EREFUSED";
var BADQUERY = "EBADQUERY";
var BADNAME = "EBADNAME";
var BADFAMILY = "EBADFAMILY";
var BADRESP = "EBADRESP";
var CONNREFUSED = "ECONNREFUSED";
var TIMEOUT = "ETIMEOUT";
var EOF = "EOF";
var FILE = "EFILE";
var NOMEM = "ENOMEM";
var DESTRUCTION = "EDESTRUCTION";
var BADSTR = "EBADSTR";
var BADFLAGS = "EBADFLAGS";
var NONAME = "ENONAME";
var BADHINTS = "EBADHINTS";
var NOTINITIALIZED = "ENOTINITIALIZED";
var LOADIPHLPAPI = "ELOADIPHLPAPI";
var ADDRGETNETWORKPARAMS = "EADDRGETNETWORKPARAMS";
var CANCELLED = "ECANCELLED";
promises.Resolver = PromiseResolver;
promises.NODATA = NODATA;
promises.FORMERR = FORMERR;
promises.SERVFAIL = SERVFAIL;
promises.NOTFOUND = NOTFOUND;
promises.NOTIMP = NOTIMP;
promises.REFUSED = REFUSED;
promises.BADQUERY = BADQUERY;
promises.BADNAME = BADNAME;
promises.BADFAMILY = BADFAMILY;
promises.BADRESP = BADRESP;
promises.CONNREFUSED = CONNREFUSED;
promises.TIMEOUT = TIMEOUT;
promises.EOF = EOF;
promises.FILE = FILE;
promises.NOMEM = NOMEM;
promises.DESTRUCTION = DESTRUCTION;
promises.BADSTR = BADSTR;
promises.BADFLAGS = BADFLAGS;
promises.NONAME = NONAME;
promises.BADHINTS = BADHINTS;
promises.NOTINITIALIZED = NOTINITIALIZED;
promises.LOADIPHLPAPI = LOADIPHLPAPI;
promises.ADDRGETNETWORKPARAMS = ADDRGETNETWORKPARAMS;
promises.CANCELLED = CANCELLED;
module.exports = {
	lookup,
	lookupService,
	resolve,
	resolve4,
	resolve6,
	resolveMx,
	resolveTxt,
	resolveSrv,
	resolveNs,
	resolveCname,
	resolveSoa,
	resolvePtr,
	resolveCaa,
	resolveNaptr,
	resolveAny,
	reverse,
	Resolver,
	setDefaultResultOrder,
	getDefaultResultOrder,
	setServers,
	getServers,
	promises,
	NODATA,
	FORMERR,
	SERVFAIL,
	NOTFOUND,
	NOTIMP,
	REFUSED,
	BADQUERY,
	BADNAME,
	BADFAMILY,
	BADRESP,
	CONNREFUSED,
	TIMEOUT,
	EOF,
	FILE,
	NOMEM,
	DESTRUCTION,
	BADSTR,
	BADFLAGS,
	NONAME,
	BADHINTS,
	NOTINITIALIZED,
	LOADIPHLPAPI,
	ADDRGETNETWORKPARAMS,
	CANCELLED
};
module.exports.default = module.exports;
//#endregion
