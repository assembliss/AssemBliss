import { spawn } from 'child_process';
import { EventEmitter } from 'events';

export interface FileAccessor {
	isWindows: boolean;
	readFile(path: string): Promise<Uint8Array>;
	writeFile(path: string, contents: Uint8Array): Promise<void>;
}

export interface IRuntimeBreakpoint {
	id: number;
	line: number;
	verified: boolean;
}

interface IRuntimeStepInTargets {
	id: number;
	label: string;
}

interface IRuntimeStackFrame {
	index: number;
	name: string;
	file: string;
	line: number;
	column?: number;
	instruction?: number;
}

interface IRuntimeStack {
	count: number;
	frames: IRuntimeStackFrame[];
}

// NOTE: This may not be necessary since we are debugging assembly code.
/**
//  * RuntimeDisassembledInstruction is a disassembled instruction.
//  * E.g. a runtime could return:
//  *  address: 0x1234,
//  */
// interface RuntimeDisassembledInstruction {
// 	address: number;
// 	instruction: string;
// 	line?: number;
// }

// NOTE: This may not be necessary since we are debugging assembly code. Get RuntimeVariable class example from mock-debug.
// Potentially replace variables with registers.
// export type IRuntimeVariableType = number | boolean | string | RuntimeVariable[];


/** A Word in this context is a sequence of characters that form a token in the source code.
 * Index is the position of the word in the line.
 */
interface Word {
	name: string;
	line: number;
	index: number;
}


/**
 * Delays the execution for the specified number of milliseconds.
 * @param ms - The number of milliseconds to delay the execution.
 * @returns A promise that resolves after the specified delay.
 */
export function timeout(ms: number) {
	return new Promise(resolve => setTimeout(resolve, ms));
}

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
export class QilingDebugger extends EventEmitter {
	// TODO: figure out how to run qdb.py or use qiling hooks (python?) from this class
	// FIXME: I may make this temporarily simply run qdb.py and then later implement the hooks in python
	// NOTE: This class originated from MockRuntime in mockRuntime.ts
	
	constructor(private fileAccessor: FileAccessor) {
		super();
	}

	/**
	 * Start executing the given program.
	 */
	//TODO: pass arguments to qdb.py (these are the launch.json configurations)
	public async start(program: string, stopOnEntry: boolean, debug: boolean): Promise<void> {

		let path = this.normalizePathAndCasing('../../qdb.py');
		const qdbProcess = spawn('python3', [path]); // load the program
		qdbProcess.stdout.on('data', (data) => {
			console.log(`stdout: ${data}`); 
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

	/**
	 * This makes sure that the path is in the right format for the current OS
	 * @param path path to normalize
	 * @returns normalized path
	 */
	private normalizePathAndCasing(path: string) {
		if (this.fileAccessor.isWindows) {
			return path.replace(/\//g, '\\').toLowerCase();
		} else {
			return path.replace(/\\/g, '/');
		}
	}
}