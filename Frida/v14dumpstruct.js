// offset: 0x00 every func: +8 DECimal to the offset, basically: readStringReferance offset = (23*8).toHex and thats it the hex offset is 0xB8

const Config = {
    RedirectIP: false,
        ip: "77.124.100.111",
        port: "9339"
}

const libg = {
    init() {
        libg.module = Process.findModuleByName("libg.so")
        libg.base = libg.module.base
        libg.add = function(x) { return libg.base.add(x)}
    }
}
const libc = {
    init() {
        libc.module = Process.findModuleByName("libc.so")
        libc.base = libc.module.base
        libc.getExport = function(x) {return libc.module.getExportByName(x)}
    }    
}
libg.init()
libc.init()

const Offsets = {
    // offsets by segcent
    Debugger: {
        // warning: 0x58DD24,
        // error:  0x10F6FF0, 
    },
    Bytestream: {
        readVLong:              0x10F6888,
        readVInt:               0x10F6208,
        // readStringReference:    0x10F5114,
        readString:             0x10F4FE0,
        readShort:              0x10F5A30,
        // readPackedBoolean:      0x10F5530,
        readLongLong:           0x10F5A94,
        readInt:                0x10F5930,
        readBytes:              0x10F5DA8,
        readByte:               0x10F5A14,
        readBoolean:            0x10F5400
    }
}

// const RedirectHost = {
//     init() {
//         Interceptor.attach(libc.getExport("getaddrinfo"), {
//             onEnter(args) {
//                 this.i = Memory.allocUtf8String(Config.ip);
//                 args[0] = this.i
//                 this.p = Memory.allocUtf8String(Config.port);
//                 args[1] = this.p
//             }
//         }) we r dumping
//     }
// }

const Utils = {
    arrayBufferToArray: function(buffer) {
        return Array.from(new Uint8Array(buffer))
    },
    isBoolean: function(x) {return x ? true : false},
    decodeString: function(src) {
        let len = src.add(4).readInt();
        if (len >= 8) {
            return src.add(8).readPointer().readUtf8String(len);
        }
        return src.add(8).readUtf8String(len)
    },
    decodeBytes: function(src, len) { 
        return src.add(8).readByteArray(len)
    },
    decodeBoolean: function(src) { 
        return src.add(8).toInt32()
    },
    handleRetval: function(name, retval, bytesize) {
        try {
            if (retval.isNull()) return null;
            if (name === ("readStringReference")) {
                return Utils.decodeString(retval)
            } else if (name === ("readString")) {
                return Utils.decodeString(retval)
            } else if (name === ("readBytes")) {
                const bytes = Utils.decodeBytes(retval, bytesize.toInt32()) 
                return Utils.arrayBufferToArray(bytes)
            } else if (name.includes("Long")) {
                return [retval.toInt32(), retval.add(4).toInt32()]
            } else if (name === "readBoolean") {
                return Utils.decodeBoolean(retval)
            } else {
                return retval.toInt32();
            }
        } catch (e) {
            console.error(`There was an error decoding [Bytestream::${name}]. Error message: ${e.message}`)
        }
    }
};

const Logger = {
    print(x) {
        console.log(x)
    },
    warning(x) {
        console.warn(x)
    },
    error(x) {
        console.error(x)
    }
}

const SetupDebugger = {
    init() {
        for (const logoffset in Offsets.Debugger) {
            Interceptor.attach(libg.add(Offsets.Debugger[logoffset]), {
                onEnter(args) {
                    let msg = args[0].readUtf8String()
                    Logger[logoffset](`[Debugger::${logoffset}]>> ${msg}`)
                }
            })
        }
    }
}

const SetupReadFunctions = {
    init() {
        for (const [funcName, offset] of Object.entries(Offsets.Bytestream)) {
            Interceptor.attach(libg.add(Offsets.Bytestream[funcName]), {
                onEnter(args) {
                    if (funcName === "readBytes") {
                        this.len = args[1];
                    }
                },
                onLeave(retval) {
                    const needsSize = funcName === "readBytes"
                    const val = needsSize
                        ? Utils.handleRetval(funcName, retval, this.len)
                        : Utils.handleRetval(funcName, retval);

                    const bytestreamLog = function(name, msg) {
                        console.log(`this.${name}(${msg})`)
                    }

                    if (funcName === "readBoolean") {
                        bytestreamLog(funcName, Utils.isBoolean(val));
                        return;
                    }

                    bytestreamLog(funcName, val)
                }
            });
        }
    }
}

libg.init()
libc.init()

// RedirectHost.init()

SetupDebugger.init()
SetupReadFunctions.init()
