/*---------------------------------------------------------
 * Refactored to use Qiling for ARMv8 emulation
 * Runtime
 *--------------------------------------------------------*/
'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
exports.QilingEmulator = void 0;
const events_1 = require("events");
const Qiling = require('qiling').Qiling; // Qiling is a Node.js wrapper for the Qiling library
class QilingEmulator extends events_1.EventEmitter {
    constructor(arch, rootfs, binaryPath) {
        super();
        this._arch = "arm64";
        this._rootfs = "/path/to/rootfs";
        this._binaryPath = "/path/to/binary";
        this._connected = false;
        this._finished = false;
        this._init = true;
        this._queuedEmulations = new Array();
        this._arch = arch;
        this._rootfs = rootfs;
        this._binaryPath = binaryPath;
    }
    start() {
        if (this._connected) {
            return;
        }
        console.log(`Starting emulation for ${this._binaryPath} on ${this._arch}...`);
        try {
            this._emulator = new Qiling({
                rootfs: this._rootfs,
                arch: this._arch,
                ostype: "linux", // Assuming Linux for simplicity
                binary: this._binaryPath
            });
            this._emulator.on('start', () => {
                this.printInfoMsg('Emulation started');
                this._connected = true;
                this._init = false;
                this._queuedEmulations.forEach(cmd => {
                    this.runCode(cmd);
                });
                this._queuedEmulations.length = 0;
            });
            this._emulator.on('stop', () => {
                this.printInfoMsg('Emulation stopped');
                this._connected = false;
            });
            this._emulator.start();
        }
        catch (error) {
            this.printErrorMsg(`Failed to start Qiling emulator: ${error}`);
        }
    }
    runCode(code) {
        if (!this._connected) {
            this.printDebugMsg('No active emulation. Queueing code for when emulation starts.');
            this._queuedEmulations.push(code);
            return;
        }
        this.printDebugMsg(`Running code: ${code}`);
        // Implement the logic to run code with Qiling here
        // This might involve injecting code into the emulated environment, stepping through execution, etc.
    }
    printDebugMsg(msg) {
        console.info(`Debug: ${msg}`);
    }
    printInfoMsg(msg) {
        this.sendEvent('onInfoMessage', msg);
    }
    printWarningMsg(msg) {
        this.sendEvent('onWarningMessage', msg);
    }
    printErrorMsg(msg) {
        this.sendEvent('onErrorMessage', msg);
    }
    sendEvent(event, ...args) {
        setImmediate(_ => {
            this.emit(event, ...args);
        });
    }
}
exports.QilingEmulator = QilingEmulator;
//# sourceMappingURL=QilingEmulator.js.map