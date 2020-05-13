/**
 * Initializes 'addresses' dictionary and NativeFunctions.
 */

var addresses = {};
var resolver = new ApiResolver("module");

var exps = [
    ["*libssl*", ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id"]],
    [Process.platform == "darwin" ? "*libsystem*" : "*libc*", ["getpeername", "getsockname", "ntohs", "ntohl"]]
];

for (var i = 0; i < exps.length; i++) {
    var lib = exps[i][0];
    var names = exps[i][1];

    for (var j = 0; j < names.length; j++) {
        var name = names[j];
        var matches = resolver.enumerateMatchesSync("exports:" + lib + "!" +
            name);
        if (matches.length == 0) {
            throw "Could not find " + lib + "!" + name;
        } else if (matches.length != 1) {
            // Sometimes Frida returns duplicates.
            var address = 0;
            var s = "";
            var duplicates_only = true;
            for (var k = 0; k < matches.length; k++) {
                if (s.length != 0) {
                    s += ", ";
                }
                s += matches[k].name + "@" + matches[k].address;
                if (address == 0) {
                    address = matches[k].address;
                } else if (!address.equals(matches[k].address)) {
                    duplicates_only = false;
                }
            }
            if (!duplicates_only) {
            throw "More than one match found for " + lib + "!" + name + ": " +
                s;
            }
        }
        addresses[name] = matches[0].address;
    }
}

var SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int",
    ["pointer"]);
var SSL_get_session = new NativeFunction(addresses["SSL_get_session"],
    "pointer", ["pointer"]);
var SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"],
    "pointer", ["pointer", "pointer"]);
var getpeername = new NativeFunction(addresses["getpeername"], "int", ["int",
    "pointer", "pointer"]);
var getsockname = new NativeFunction(addresses["getsockname"], "int", ["int",
    "pointer", "pointer"]);
var ntohs = new NativeFunction(addresses["ntohs"], "uint16", ["uint16"]);	
var ntohl = new NativeFunction(addresses["ntohl"], "uint32", ["uint32"]);

console.log("Initialized functions needed globally...");

/**
 * Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
 * "dst_port".
 * @param {int} sockfd The file descriptor of the socket to inspect.
 * @param {boolean} isRead If true, the context is an SSL_read call. If
 *     false, the context is an SSL_write call.
 * @return {dict} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
 *     and "dst_port".
 */
function getPortsAndAddresses(sockfd, isRead) {
    var message = {};
    var message2 = {}

    // struct sockaddr_in {
    //     __kernel_sa_family_t sin_family; // first 2 bytes
    //     __be16 sin_port; // second two
    //     struct in_addr sin_addr; // Addr
    //     unsigned char __pad[__SOCK_SIZE__ - sizeof(short int) - sizeof(unsigned short int) - sizeof(struct in_addr)];
    //   };

    var addrlen = Memory.alloc(4);
    var addr = Memory.alloc(16);

    var src_dst = ["src", "dst"];
    for (var i = 0; i < src_dst.length; i++) {
        Memory.writeU32(addrlen, 16);
        var ret;
        if ((src_dst[i] == "src") ^ isRead) {
            ret = getsockname(sockfd, addr, addrlen);
        } else {
            ret = getpeername(sockfd, addr, addrlen);
        }
        if (ret != 0) {
            console.log("ret : ", ret);
        }
        console.log(hexdump(addr, {
            offset: 0,
            length: 16,
            header: true,
            ansi: true
          }));
        // TODO : this is incorrect
        message[src_dst[i] + "_port"] = Memory.readU16(addr.add(2));
        message[src_dst[i] + "_addr"] = Memory.readU32(addr.add(4));
        // message2[src_dst[i] + "_port"] = ntohs(Memory.readU16(addr.add(2)));	      message[src_dst[i] + "_port"] = Memory.readU16(addr.add(2));
        // message2[src_dst[i] + "_addr"] = ntohl(Memory.readU32(addr.add(4)));
    }
    // console.log("message : ", JSON.stringify(message))
    // console.log("message2 : ", JSON.stringify(message2))
    return message;
    // return message2;
}

/**
 * Get the session_id of SSL object and return it as a hex string.
 * @param {!NativePointer} ssl A pointer to an SSL object.
 * @return {dict} A string representing the session_id of the SSL object's
 *     SSL_SESSION. For example,
 *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
 */
function getSslSessionId(ssl) {
    var session = SSL_get_session(ssl);
    if (session == 0) {
        return 0;
    }
    var len = Memory.alloc(4);
    var p = SSL_SESSION_get_id(session, len);
    len = Memory.readU32(len);

    var session_id = "";
    for (var i = 0; i < len; i++) {
        // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
        // it to session_id.
        session_id += ("0" + Memory.readU8(p.add(i)).toString(16).toUpperCase()).substr(-2);
    }

    return session_id;
}

Interceptor.attach(addresses["SSL_read"], {
    onEnter: function (args) {
        var message = getPortsAndAddresses(SSL_get_fd(args[0]), true);
        message["ssl_session_id"] = getSslSessionId(args[0]);
        message["function"] = "SSL_read";
        this.message = message;
        this.buf = args[1];
    },
    onLeave: function (retval) {
        retval |= 0; // Cast retval to 32-bit integer.
        if (retval <= 0) {
            return;
        }
        send(this.message, Memory.readByteArray(this.buf, retval));
    }
});

Interceptor.attach(addresses["SSL_write"], {
    onEnter: function (args) {
        var message = getPortsAndAddresses(SSL_get_fd(args[0]), false);
        message["ssl_session_id"] = getSslSessionId(args[0]);
        message["function"] = "SSL_write";
        send(message, Memory.readByteArray(args[1], parseInt(args[2])));
    },
    onLeave: function (retval){ 
    }
});