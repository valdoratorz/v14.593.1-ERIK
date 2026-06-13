let base = Process.findModuleByName("libg.so").base;
let sendPepperAuthentication = new NativeFunction(base.add(0x124A454), 'pointer', ['pointer', 'pointer']);
const libc = Process.getModuleByName("libc.so");
const getaddrinfo = libc.findExportByName('getaddrinfo');

const malloc = new NativeFunction(libc.findExportByName("malloc"), "pointer", ["int"]);

const fChatToAllianceStreamMessageCtor = new NativeFunction(base.add(0xF33394), 'void', ['pointer']);
const fMessaging_Send = new NativeFunction(base.add(0x1249338), 'void', ['pointer', 'pointer']);

const StringCtor = new NativeFunction(base.add(0x12598C0), 'void', ['pointer', 'pointer']);

const Utils = {
    StringCtor(ptr, strptr) {
        StringCtor(ptr, strptr);
    },
    createStringPtr(str) {
        var ptr = malloc(str.length + 1);
        ptr.writeUtf8String(str);
        return ptr;
    },
    createStringObject(str) {
        var strptr = Utils.createStringPtr(str);
        let ptr = malloc(128);
        Utils.StringCtor(ptr, strptr);
        return ptr;
    },
    strPtr(content) {
        return Memory.allocUtf8String(content);
    }
}
//nacl back enabled - disabling nacl killer
Interceptor.replace(base.add(0x1249FA4), new NativeCallback(function() {
	console.warn("[+][PepperCrypto::secretbox_open] Skipped decryption");
	return 1;
}, 'int', []));

let messagingPtr = null;


//nacl back enabled - disabling nacl killer
Interceptor.replace(base.add(0x124A454), new NativeCallback(function(a1, a2) {
	a1.add(24).writeU8(5);
	messagingPtr = a1;
	fMessaging_Send(a1, a2);
}, 'pointer', ['pointer', 'pointer']));


const isclientoffsync = base.add(0x104B254);

Interceptor.replace(isclientoffsync, new NativeCallback(function(a1) {
	//console.warn("[+] LogicTime::isClientOffSync bypassed: " + a1);
	return 0;
}, 'int', ['pointer']));



Interceptor.attach(base.add(0xF5E014), {

        onEnter: function (args) {
            this.a1 = args[0];
        },

        onLeave: function () {

            try {
                // Force desync flag OFF
                this.a1.add(489).writeU8(0);

                // Also clear secondary flag
                //this.a1.add(491).writeU8(0);

            } catch (e) {}
        }
    });

//nacl back enabled - disabling nacl killer
const cmpAddress = base.add(0x124AFB0);
Interceptor.attach(cmpAddress, {
    onEnter(args) {
        // Force the message ID to 10100 before the comparison
        this.context.x0 = ptr(10100);
        console.log("[*] Forced message ID to 10100 at cmp instruction");
    }
});

Interceptor.attach(getaddrinfo, {
	onEnter(args) {
		this.c = Memory.allocUtf8String('45.33.96.78');
		args[0] = this.c;
		args[1].writeUtf8String("9330");
	}
});

Interceptor.replace(base.add(0x1054EF4), new NativeCallback(function(a1) {
    console.log("[+] 1054EF4 bypassed → Clan Wars UNLOCKED");
    return 1;
}, 'int', ['pointer']));

Interceptor.attach(base.add(0x10552FC), {
    onLeave(retval) {
        retval.replace(ptr(1));
        console.log("[+] sub_10552FC → forced return 1 (Clan Wars UNLOCKED)");
    }
});

Interceptor.attach(base.add(0x8B7F24), {
	onEnter(args) {
		const a2 = args[1].toInt32();
        if (a2 === 1) {
            this.context.x1 = ptr(0);
        }
	}
});

let ownStars = 0, enemyStars = 0;
let secondsSincelastCommand = -1;

// LogicSummoner::getStars called by CombatHUD::updateGaindedStars
Interceptor.attach(base.add(0xE4A674), {
    onEnter(args) {
        this.returnAddr = this.returnAddress.sub(base).toInt32();
    },
    onLeave(retval) {
        const addr = this.returnAddr;
		//console.log(this.returnAddr + " - " + retval.toInt32());
        switch (addr) {
            case 8682012: // CombatHUD::updateGaindedStars 1st entry
                ownStars = retval.toInt32();
                break;
            case 8681996: // CombatHUD::updateGaindedStars 2nd entry
                enemyStars = retval.toInt32();
                break;
        }
    }
});

Interceptor.attach(base.add(0x1249338), { //messaging::send
	onEnter(args) {
		let msgtype = (new NativeFunction(args[1].readPointer().add(40).readPointer(), 'int', ['pointer']))(args[1]);
		if (msgtype === 19066) {
			secondsSincelastCommand = 0;
		}
	}
});

function buildChatToAllianceStreamMessage(payload) {
	var message = malloc(116);
	fChatToAllianceStreamMessageCtor(message);
	ptr(message).add(0x90).writePointer(Utils.createStringObject(payload));
	return message;
}

function sendClanMessage(payload) {
	let message = buildChatToAllianceStreamMessage(payload);
	fMessaging_Send(messagingPtr, message);
}

setInterval(() => {
	console.log("own stars: " + ownStars);
	console.log("enemy stars: " + enemyStars);
	console.log(secondsSincelastCommand);
	if (secondsSincelastCommand != -1) {
		secondsSincelastCommand += 0.5;
	}
	if ((ownStars >= 1 && ownStars <= 3) || (enemyStars >= 1 && enemyStars <= 3)) {
		if (secondsSincelastCommand >= 3) {
			sendClanMessage(`{${ownStars},${enemyStars}7`);
			ownStars = 0;
			enemyStars = 0;
			secondsSincelastCommand = -1;
		}
	}
}, 500);

function hexToBytes(hex) {
    const bytes = [];
    for (let c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}