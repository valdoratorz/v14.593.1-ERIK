let base = Process.findModuleByName("libg.so").base;
const fMessaging_Send = new NativeFunction(base.add(0x1249338), 'void', ['pointer', 'pointer']);
let sendPepperAuthentication = new NativeFunction(base.add(0x124A454), 'pointer', ['pointer', 'pointer']);

Interceptor.replace(base.add(0x1249FA4), new NativeCallback(function() {
	console.warn("[+][PepperCrypto::secretbox_open] Skipped decryption");
	return 1;
}, 'int', []));

Interceptor.replace(base.add(0x124A454), new NativeCallback(function(a1, a2) {
	a1.add(24).writeU8(5);
	fMessaging_Send(a1, a2);
}, 'pointer', ['pointer', 'pointer']));


const isclientoffsync = base.add(0x104B254);

Interceptor.replace(isclientoffsync, new NativeCallback(function(a1) {
	console.warn("[+] LogicTime::isClientOffSync bypassed: " + a1);
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

const cmpAddress = base.add(0x124AFB0);

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
		this.c = Memory.allocUtf8String('192.168.1.40');
		args[0] = this.c;
		args[1].writeUtf8String("9330");
	}
});