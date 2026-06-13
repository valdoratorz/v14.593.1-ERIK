
'use strict';

let base = null;
let currentMessageId = -1;

// ------------------------------------------------------------------------
// Utility functions
// ------------------------------------------------------------------------

function WaitForLib(lib) {
    return new Promise(resolve => {
        const timer = setInterval(() => {
            const m = Process.findModuleByName(lib);
            if (m) {
                clearInterval(timer);
                resolve(m);
            }
        }, 50);
    });
}

// Safely read a u32, return 0 on failure
function safeReadU32(ptr) {
    try { return ptr.readU32(); } catch { return 0; }
}

// Safely read a pointer, return NULL on failure
function safeReadPtr(ptr) {
    try { return ptr.readPointer(); } catch { return ptr(0); }
}

// ------------------------------------------------------------------------
// Game‑specific string decoder (adjust based on actual string class)
// ------------------------------------------------------------------------
function readGameString(retval) {
	try {
		return retval.readUtf8String();
	}catch{
		if (retval.isNull()) return 'null';

		// Many game engines return a pointer to a String object.
		// Common layout: offset 0 = vtable, 4 = length, 8 = data (either inline or pointer)
		const length = retval.add(4).readS32(); // signed length? usually int
		if (length < 0 || length > 0x100000)    // sanity check
			return '[invalid length]';

		// If length <= 8, string is stored inline at offset 8
		if (length <= 8) {
			return retval.add(8).readUtf8String(length);
		} else {
			// Otherwise offset 8 is a pointer to external buffer
			const dataPtr = retval.add(8).readPointer();
			return dataPtr.readUtf8String(length);
		}
	}
}

// ------------------------------------------------------------------------
// Byte array dumper (produces hex string for writeHex2)
// ------------------------------------------------------------------------
function dumpByteArray(ptr, length) {
    try {
        if (ptr.isNull() || length <= 0 || length > 0x100000) return;

        const arrayBuffer = ptr.readByteArray(length);
        const bytes = new Uint8Array(arrayBuffer);
        
        let hex = '';
        for (let i = 0; i < bytes.length; i++) {
            const byte = bytes[i];
            hex += (byte < 0x10 ? '0' : '') + byte.toString(16);
        }
        
        console.log(`this.writeHex2("${hex}");`);
    } catch (e) {
        console.log("[readBytes error]", e);
    }
}

// ------------------------------------------------------------------------
// Main hooking logic
// ------------------------------------------------------------------------
async function main() {
    const lib = await WaitForLib('libg.so');
    base = lib.base;

    console.log(`[FRIDA] libg.so loaded @ ${base}`);

    const offsets = {
        readVInt:            0x10F6208,
        readInt:             0x10F5930,
        readBoolean:         0x10F5400,
		//packetboolean 10F5530
        readString:          0x10F4FE0,
        readBytes:           0x10F5DA8,
        readVLong:           0x10F6888,
        readShort:           0x10F5A30,
        readByte:            0x10F5A14,
        readLongLong:        0x10F5A94,
        readStringReference: 0x10F5114,

        OwnHomeDataMessage_Decode:      0xE2110C,
        LogicClientHome_LogicClientHome:0xD77A00,
        LogicClientHome_decode:         0xD79E40,
        LogicClientAvatar_LogicClientAvatar: 0xB1532C
    };

    // Detect message ID by hooking the factory that creates messages
    Interceptor.attach(base.add(0xF21658), {
        onEnter(args) {
            const messageId = args[0].toInt32();
            currentMessageId = messageId;
            console.log(`[MessageFactory] Creating message ID: ${messageId} (0x${messageId.toString(16)})`);
        }
    });
	
	function getMessageType(Message) { 
        return (new NativeFunction(Message.readPointer().add(40).readPointer(), "int", ["pointer"]))(Message); 
    }
	
	Interceptor.attach(base.add(0xA20100), { // MessageManager::receiveMessage
		onEnter(args) {
			this.message = args[1];
			this.type = getMessageType(this.message);


			console.log(`[MessageManager] Creating message ID: ${this.type} (0x${this.type.toString(16)})`);
			
		}
	});

    // Helper to attach hooks with a filter on currentMessageId
    function hookRead(name, offset, formatter) {
        Interceptor.attach(base.add(offset), {
            onLeave(retval) {
                if (currentMessageId !== 25865) {   // <-- change target ID here
                    try {
                        console.log(formatter(retval));
                    } catch (e) {
                        console.log(`[${name}] error:`, e);
                    }
                }
            }
        });
    }

    // For readBytes we need the length from onEnter
    Interceptor.attach(base.add(offsets.readBytes), {
        onEnter(args) {
            this.length = args[1].toInt32();
        },
        onLeave(retval) {
            if (currentMessageId !== 25865 && !retval.isNull()) {
                dumpByteArray(retval, this.length);
            }
        }
    });

    // Simple value readers
    hookRead('readInt', offsets.readInt,        retval => `this.writeInt(${retval.toInt32()});`);
    hookRead('readVInt', offsets.readVInt,      retval => `this.writeVInt(${retval.toInt32()});`);
    hookRead('readByte', offsets.readByte,      retval => `this.writeByte(0x${retval.toInt32().toString(16)});`);
    hookRead('readLongLong', offsets.readLongLong, retval => `this.writeLong(${retval.toInt32()});`); // adjust if 64‑bit
    hookRead('readShort', offsets.readShort,    retval => `this.writeShort(${retval.toInt32()});`);
    hookRead('readVLong', offsets.readVLong,    retval => `this.writeVLong(${retval.toInt32()});`); // adjust if 64‑bit
    hookRead('readBoolean', offsets.readBoolean, retval => `this.writeBoolean(${retval.toInt32() ? 'true' : 'false'});`);

    // String readers
    hookRead('readString', offsets.readString,  retval => `this.writeString("${readGameString(retval)}");`);
    hookRead('readStringReference', offsets.readStringReference, retval => {
        const str = retval.readUtf8String() || '';
        return `this.writeStringReference("${str}");`;
    });
	
	
	/*const fMessaging_Send = new NativeFunction(base.add(0x1108514), 'void', ['pointer', 'pointer']);
	let sendPepperAuthentication = new NativeFunction(base.add(0x1109630), 'pointer', ['pointer', 'pointer']);

	Interceptor.replace(base.add(0x1109180), new NativeCallback(function() {
		console.warn("[+][PepperCrypto::secretbox_open] Skipped decryption");
		return 1;
	}, 'int', []));

	Interceptor.replace(base.add(0x1109630), new NativeCallback(function(a1, a2) {
		a1.add(24).writeU8(5);
		fMessaging_Send(a1, a2);
	}, 'pointer', ['pointer', 'pointer']));

	const cmpAddress = base.add(0x110A18C);

	Interceptor.attach(cmpAddress, {
		onEnter(args) {
			// Force the message ID to 10100 before the comparison
			this.context.x0 = ptr(10100);
			console.log("[*] Forced message ID to 10100 at cmp instruction");
		}
	});
	
	
	const libc = Process.getModuleByName("libc.so");
	const getaddrinfo = libc.findExportByName('getaddrinfo');
	Interceptor.attach(getaddrinfo, {
		onEnter(args) {
			this.c = Memory.allocUtf8String('192.168.0.39');
			args[0] = this.c;
			args[1].writeUtf8String("9330");
		}
	});*/
}

main().catch(console.error);

const module = Process.findModuleByName("libg.so");
const base = module.base;
const libc = Process.getModuleByName("libc.so");
const getaddrinfo = libc.findExportByName('getaddrinfo');

class LogicMath 
{
    static max(valueA, valueB) {
        if (valueA >= valueB) {
            return valueA;
        }
        return valueB;
    }
}

class PiranhaMessage {
    static encode(Message) { 
        return (new NativeFunction(Message.readPointer().add(16).readPointer(), "int", ["pointer"]))(Message); 
    }

    static decode(Message) { 
        return (new NativeFunction(Message.readPointer().add(24).readPointer(), "int", ["pointer"]))(Message); 
    }

    static getServiceNodeType(Message) { 
        return (new NativeFunction(Message.readPointer().add(32).readPointer(), "int", ["pointer"]))(Message); 
    }

    static getMessageType(Message) { 
        return (new NativeFunction(Message.readPointer().add(40).readPointer(), "int", ["pointer"]))(Message); 
    }

    static getMessageTypeName(Message) { 
        return (new NativeFunction(Message.readPointer().add(48).readPointer(), "pointer", ["pointer"]))(Message); 
    }

    static getEncodingLength(Message) {
        return PiranhaMessage.getByteStream(Message).add(24).readInt();
    }

    static isClientToServerMessage(Message) {
        return (PiranhaMessage.getMessageType(Message) >= 10000 && PiranhaMessage.getMessageType(Message) < 20000) || PiranhaMessage.getMessageType(Message) === 30000;
    }

    static destruct(Message) { 
        return (new NativeFunction(Message.readPointer().add(56).readPointer(), "int", ["pointer"]))(Message); 
    }

    static getByteStream(Message) { 
        return Message.add(8);
    }
}

function toRawHex(byteArray) {
    if (byteArray === null) return "";

    const u8 = new Uint8Array(byteArray);
    let hex = "";
    for (let i = 0; i < u8.length; i++) {
        hex += u8[i].toString(16).padStart(2, "0");
    }
    return hex;
}


//sub_E239D0 = clan list decode?


const addr = base.add(0xFC21F0);

Interceptor.attach(addr, {
  onEnter() {
    const caller = this.returnAddress;
    console.log('[+] sub_FC21F0 called from:', caller.sub(base));
  }
});


Interceptor.attach(base.add(0xA20100), { // MessageManager::receiveMessage
    onEnter(args) {
        this.message = args[1];
        this.type = PiranhaMessage.getMessageType(this.message);
        this.length = PiranhaMessage.getEncodingLength(this.message);
        console.log("[MessageManager::receiveMessage] Received message with type:", this.type);
        let PayloadPtr = PiranhaMessage.getByteStream(this.message).add(56).readPointer();
        let payload = PayloadPtr.readByteArray(this.length);


		//if (![20103, 20108, 20100, 21435, 25865].includes(this.type)) {
			console.log("\n\n\n\n----------");
			console.log("Stream dump of " + this.type + " (raw hex):",
				toRawHex(payload)
			);
		//}

		
        console.log("Stream size:", this.length);
    }
});
