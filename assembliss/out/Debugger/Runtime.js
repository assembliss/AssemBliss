"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QilingDebugger = exports.timeout = void 0;
const child_process_1 = require("child_process");
const events_1 = require("events");
/**
 * Delays the execution for the specified number of milliseconds.
 * @param ms - The number of milliseconds to delay the execution.
 * @returns A promise that resolves after the specified delay.
 */
function timeout(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
exports.timeout = timeout;
/**
 * A runtime with debugger functionality.
 * An execution engine with debugging support:
 * It takes an assembly (*.s | *.asm | arm) file and "executes" it
 * The runtime can not only run through the whole file but also executes one line at a time
 * and stops on lines for which a breakpoint has been registered. This functionality is the
 * core of the "debugging support".
 * Since the Runtime is completely independent from VS Code or the Debug Adapter Protocol,
 * it can be viewed as a simplified representation of a real "execution engine" (e.g. node.js)
 * or debugger (e.g. gdb).
 * When implementing your own debugger extension for VS Code, you probably don't need this
 * class because you can rely on some existing debugger or runtime.
*/
class QilingDebugger extends events_1.EventEmitter {
    // TODO: figure out how to run qdb.py or use qiling hooks (python?) from this class
    // FIXME: I may make this temporarily simply run qdb.py and then later implement the hooks in python
    // NOTE: This class originated from MockRuntime in mockRuntime.ts
    constructor(fileAccessor) {
        super();
        this.fileAccessor = fileAccessor;
    }
    /**
     * Start executing the given program.
     */
    //TODO: pass arguments to qdb.py (these are the launch.json configurations)
    async start(program, stopOnEntry, debug) {
        const qdbProcess = (0, child_process_1.spawn)('python3', ['../../qdb.py']); // load the program
        qdbProcess.stdout.on('data', (data) => {
            console.log(`stdout: ${data}`); // Pray this simply shows the output of qdb.py
        });
        // 	if (debug) {
        // 		await this.verifyBreakpoints(this._sourceFile);
        // 		if (stopOnEntry) {
        // 			this.findNextStatement(false, 'stopOnEntry');
        // 		} else {
        // 			// we just start to run until we hit a breakpoint, an exception, or the end of the program
        // 			this.continue(false);
        // 		}
        // 	} else {
        // 		this.continue(false);
        // 	}
    }
}
exports.QilingDebugger = QilingDebugger;
//# sourceMappingURL=Runtime.js.map