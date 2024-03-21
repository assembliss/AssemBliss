/*---------------------------------------------------------
 * Refactored to use Qiling for ARMv8 emulation
 *--------------------------------------------------------*/
'use strict';

import { EventEmitter } from 'events';
const Qiling = require('qiling').Qiling;

export class QilingEmulator extends EventEmitter {

    private _emulator;
    private _arch = "arm64";
    private _rootfs = "/path/to/rootfs";
    private _binaryPath = "/path/to/binary";

    private _connected = false;
    private _finished = false;
    private _init = true;

    private _queuedEmulations = new Array<string>();

    constructor(arch: string, rootfs: string, binaryPath: string) {
        super();
        this._arch = arch;
        this._rootfs = rootfs;
        this._binaryPath = binaryPath;
    }

    public start() {
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
        } catch (error) {
            this.printErrorMsg(`Failed to start Qiling emulator: ${error}`);
        }
    }

    public runCode(code: string) {
        if (!this._connected) {
            this.printDebugMsg('No active emulation. Queueing code for when emulation starts.');
            this._queuedEmulations.push(code);
            return;
        }
        this.printDebugMsg(`Running code: ${code}`);
        // Implement the logic to run code with Qiling here
        // This might involve injecting code into the emulated environment, stepping through execution, etc.
    }

    public printDebugMsg(msg: string) {
        console.info(`Debug: ${msg}`);       
    }

    public printInfoMsg(msg: string) {
        this.sendEvent('onInfoMessage', msg);
    }

    public printWarningMsg(msg: string) {
        this.sendEvent('onWarningMessage', msg);
    }

    public printErrorMsg(msg: string) {
        this.sendEvent('onErrorMessage', msg);
    }

    private sendEvent(event: string, ...args: any[]) {
        setImmediate(_ => {
            this.emit(event, ...args);
        });
    }
}
