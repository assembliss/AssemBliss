import { spawn } from 'child_process';
import { EventEmitter } from 'events';
import fetch from 'node-fetch';

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

// interface IRuntimeStepInTargets {
// 	id: number;
// 	label: string;
// }

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
// The following is a potential implementation of RuntimeVariable.
// General Purpose Registers
export type GeneralPurposeRegister = 
    | 'x0' | 'x1' | 'x2' | 'x3' | 'x4' | 'x5' | 'x6' | 'x7'
    | 'x8' | 'x9' | 'x10' | 'x11' | 'x12' | 'x13' | 'x14' | 'x15'
    | 'x16' | 'x17' | 'x18' | 'x19' | 'x20' | 'x21' | 'x22' | 'x23'
    | 'x24' | 'x25' | 'x26' | 'x27' | 'x28' | 'x29' | 'x30';

// Special Registers
export type SpecialRegister = 'sp' | 'pc' | 'lr';

// System Registers
export type SystemRegister = 'cpacr_el1' | 'tpidr_el0' | 'pstate';

// SIMD and Floating Point Registers
export type ByteRegister = `b${number}`;  // b0 through b31
export type HalfRegister = `h${number}`;  // h0 through h31
export type SingleRegister = `s${number}`;  // s0 through s31
export type DoubleRegister = `d${number}`;  // d0 through d31
export type QuadRegister = `q${number}`;  // q0 through q31
export type VectorRegister = `v${number}`;  // v0 through v31
export type WorkRegister = `w${number}`;  // w0 through w31

// IRuntimeVariableType definition
export type IRuntimeVariableType = 
    GeneralPurposeRegister | SpecialRegister | SystemRegister |
    ByteRegister | HalfRegister | SingleRegister | DoubleRegister |
    QuadRegister | VectorRegister | WorkRegister;


export class RuntimeVariable {

	/* Used to store the memory representation of a string value */
	private _memory?: Uint8Array;

	/* Used to store the reference number of a variable */
	public reference?: number;

	/**
	 * Returns the value of the variable.
	 */
	public get value() {
		return this._value;
	}

	/**
	 * Sets the value of the variable.
	 */
	public set value(value: IRuntimeVariableType) {
		this._value = value;
		this._memory = undefined;
	}

	/**
	 * Returns the memory representation of the value.
	 */
	public get memory() {
		if (this._memory === undefined && typeof this._value === 'string') {
			this._memory = new TextEncoder().encode(this._value);
		}
		return this._memory;
	}

	constructor(public readonly name: string, private _value: IRuntimeVariableType) {}

	// public setMemory(data: Uint8Array, offset = 0) {
	// 	const memory = this.memory;
	// 	if (!memory) {
	// 		return;
	// 	}

	// 	memory.set(data, offset);
	// 	this._memory = memory;
	// 	this._value = new TextDecoder().decode(memory);
	// }
}

/** A Word in this context is a sequence of characters that form a token in the source code.
 * Index is the position of the word in the line.
 */
interface Word {
	// name: string;
	text: string;
	line: number;
	// index: number;
}

interface Line {
	line: number;
	text: string;
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
	// NOTE: This class originated from MockRuntime in mockRuntime.ts


	/** The port number for the server. */
	private readonly PORT: number = 31415;

	/** The host address for the runtime. */
    private readonly HOST: string = 'localhost';

	/**
	 * Map that stores runtime variables. 
	 * NOTE: Might refactor to be registers or just use registers as variables.
	 */
	private variables = new Map<string, RuntimeVariable>();

	private qdbProcess: any;

	// the initial (and one and only) file we are 'debugging'
	private _sourceFile: string = '';
	public get sourceFile() {
		return this._sourceFile;
	}

	// the contents (= lines) of the one and only file
	private sourceLines: string[] = [];
	private instructions: Word[] = [];
	
	// This is the next line that will be 'executed'
	private _currentLine = 0;
	private get currentLine() {
		return this._currentLine;
	}
	private set currentLine(x) {
		this._currentLine = x;
		// this.instruction = this.starts[x];
		// this.instruction = x;
	}

	// public instruction = 0;
	// all instruction breakpoint addresses
	private instructionBreakpoints = new Set<number>();

	// maps from sourceFile to array of IRuntimeBreakpoint
	private breakPoints = new Map<string, IRuntimeBreakpoint[]>();

	constructor(private fileAccessor: FileAccessor) {
		super();
	}

	/**
	 * Start executing the given program.
	 */
	public async start(program: string, stopOnEntry: boolean, debug: boolean): Promise<void> {
		
		await this.loadSource(this.normalizePathAndCasing(program)); // load the program
		//Get the path to qdb.py
		var re = /\/out\/backend/gi;
		process.chdir(__dirname.replace(re, ""));
		console.log("Current working directory: " + process.cwd());

		let path = this.normalizePathAndCasing('src/backend/DebugServer/debugServer.py');
		if (!program) 
			return;
		let binary = program.split('.')[0]; // gets the binary name by removing the extension
		this.qdbProcess = spawn('python3', [path, binary]); // load the program
		this.qdbProcess.stdout.on('data', (data) => { // function for when there is standard output
			console.log(`stdout: ${data}`); // just display in console.
			// Note: The following is a failed implementation of getting a randomly generated port number from the output of the python script.
			// this.port = parseInt(data.toString().trim()); // get the port number from the output
			// console.log(`Port number: ${this.port}`);
			// this.client.connect(this.port, this.host, () => {
			// 	console.log(`Connected to server on ${this.host}:${this.port}`);
			// 	// You can now send data to the server
			// 	// this.client.write('Hello Server!');
			// });
		});
		this.qdbProcess.stderr.on('data', (data) => {
			console.error(`stderr: ${data}`);
		});
		this.qdbProcess.on('close', (code) => {
			console.log(`debugServer exited with code ${code}`);
		});
		
		await this.getRun(); // start the program

		if (debug) {
			await this.verifyBreakpoints(this._sourceFile);

			if (stopOnEntry) {
				this.findNextStatement(false, 'stopOnEntry');
			} else {
				// we just start to run until we hit a breakpoint, an exception, or the end of the program
				this.continue(false);
			}
		} else {
			this.continue(false);
		}

	}

	async getMemMap(): Promise<void> {
		//TODO: implement this
	}

	async getRun(): Promise<void> {
		const respone = await fetch(`http://${this.HOST}:${this.PORT}/?get_run=true`)
		const data = await respone.json();
		this.parseResponse(data);
	}

	async getCont(): Promise<void> {
		//TODO: implement this, Make sure to parse the response and update the registers and memory
	}

	/**
	 * Continue execution to the end/beginning.
	 * @param reverse - If true continue execution in reverse. (Reverse execution is not supported)
	 */
	public continue(reverse: boolean) {

		while (!this.executeLine(this.currentLine)) {
			if (this.updateCurrentLine(reverse)) {
				break;
			}
			if (this.findNextStatement(reverse)) {
				break;
			}
		}
		return; // TODO: implement this
	}

	
	/**
	 * Executes the next step in the program execution.
	 * 
	 * @param instruction - Indicates whether to step by instruction or by line. This is irrelevant for assembly code because each line is an instruction.
	 * @param reverse - Indicates whether to step in reverse or forward direction. (Reverse execution is not supported)
	 */
	public step(instruction: boolean, reverse: boolean) {
		// TODO: implement this
		// if (instruction) {
		// 	if (reverse) {
		// 		this.instruction--;
		// 	} else {
		// 		this.instruction++;
		// 	}
		// 	this.sendEvent('stopOnStep');
		// } else {
		// 	if (!this.executeLine(this.currentLine, reverse)) {
		// 		if (!this.updateCurrentLine(reverse)) {
		// 			this.findNextStatement(reverse, 'stopOnStep');
		// 		}
		// 	}
		// }

		// client.on('close', function() {
		// 	console.log('Connection closed');
		// });
		this.sendEvent('stopOnStep'); // this sends the event to the frontend
		
	}

	private updateCurrentLine(reverse: boolean): boolean {
		//TODO: implement this
		return false;
	// 	if (reverse) {
	// 		if (this.currentLine > 0) {
	// 			this.currentLine--;
	// 		} else {
	// 			// no more lines: stop at first line
	// 			this.currentLine = 0;
	// 			this.currentColumn = undefined;
	// 			this.sendEvent('stopOnEntry');
	// 			return true;
	// 		}
	// 	} else {
	// 		if (this.currentLine < this.sourceLines.length-1) {
	// 			this.currentLine++;
	// 		} else {
	// 			// no more lines: run to end
	// 			this.currentColumn = undefined;
	// 			this.sendEvent('end');
	// 			return true;
	// 		}
	// 	}
	// 	return false;
	}

	// /**
	//  * "Step into" for Mock debug means: go to next character
	//  */
	// public stepIn(targetId: number | undefined) {
	// 	if (typeof targetId === 'number') {
	// 		this.currentColumn = targetId;
	// 		this.sendEvent('stopOnStep');
	// 	} else {
	// 		if (typeof this.currentColumn === 'number') {
	// 			if (this.currentColumn <= this.sourceLines[this.currentLine].length) {
	// 				this.currentColumn += 1;
	// 			}
	// 		} else {
	// 			this.currentColumn = 1;
	// 		}
	// 		this.sendEvent('stopOnStep');
	// 	}
	// }

	// /**
	//  * "Step out" for Mock debug means: go to previous character
	//  */
	// public stepOut() {
	// 	if (typeof this.currentColumn === 'number') {
	// 		this.currentColumn -= 1;
	// 		if (this.currentColumn === 0) {
	// 			this.currentColumn = undefined;
	// 		}
	// 	}
	// 	this.sendEvent('stopOnStep');
	// }

	// public getStepInTargets(frameId: number): IRuntimeStepInTargets[] {

	// 	const line = this.getLine();
	// 	const words = this.getWords(this.currentLine, line);

	// 	// return nothing if frameId is out of range
	// 	if (frameId < 0 || frameId >= words.length) {
	// 		return [];
	// 	}

	// 	const { name, index  }  = words[frameId];

	// 	// make every character of the frame a potential "step in" target
	// 	return name.split('').map((c, ix) => {
	// 		return {
	// 			id: index + ix,
	// 			label: `target: ${c}`
	// 		};
	// 	});
	// }

	
	/**
	 * Returns the runtime stack within the specified range of frames.
	 * @param startFrame The index of the first frame to include in the stack.
	 * @param endFrame The index of the last frame to include in the stack.
	 * @returns An object representing the runtime stack.
	 */
	public stack(startFrame: number, endFrame: number): IRuntimeStack {

		// const line = this.getLine();
		// const words = this.getWords(this.currentLine, line);
		// words.push({ name: 'BOTTOM', line: -1, index: -1 });	// add a sentinel so that the stack is never empty...

		// // if the line contains the word 'disassembly' we support to "disassemble" the line by adding an 'instruction' property to the stackframe
		// const instruction = line.indexOf('disassembly') >= 0 ? this.instruction : undefined;

		// const column = typeof this.currentColumn === 'number' ? this.currentColumn : undefined;

		// const frames: IRuntimeStackFrame[] = [];
		// // every word of the current line becomes a stack frame.
		// for (let i = startFrame; i < Math.min(endFrame, words.length); i++) {

		// 	const stackFrame: IRuntimeStackFrame = {
		// 		index: i,
		// 		name: `${words[i].name}(${i})`,	// use a word of the line as the stackframe name
		// 		file: this._sourceFile,
		// 		line: this.currentLine,
		// 		column: column, // words[i].index
		// 		instruction: instruction ? instruction + i : 0
		// 	};

		// 	frames.push(stackFrame);
		// }

		// return {
		// 	frames: frames,
		// 	count: words.length
		// };
		return { count: 0, frames: [] }; // TODO: implement this
	}

	
	/**
	 * Retrieves the breakpoints for a given path and line number.
	 * 
	 * Determine possible column breakpoint positions for the given line.
	 * Here we return the start location of words with more than 8 characters.
	 * @param path - The path of the file.
	 * @param line - The line number.
	 * @returns An array of breakpoint indices.
	 */
	public getBreakpoints(path: string, line: number): number[] {
	    return [0];
	}

	// /*
	//  * Set breakpoint in file with given line.
	//  */
	public async setBreakPoint(path: string, line: number): Promise<IRuntimeBreakpoint> {
		// path = this.normalizePathAndCasing(path);

		// const bp: IRuntimeBreakpoint = { verified: false, line, id: this.breakpointId++ };
		// let bps = this.breakPoints.get(path);
		// if (!bps) {
		// 	bps = new Array<IRuntimeBreakpoint>();
		// 	this.breakPoints.set(path, bps);
		// }
		// bps.push(bp);

		// await this.verifyBreakpoints(path);

		// return bp;
		return { id: 0, line, verified: false }; // TODO: implement this
	}

	/*
	 * Clear breakpoint in file with given line.
	 */
	public clearBreakPoint(path: string, line: number): IRuntimeBreakpoint | undefined {
		// const bps = this.breakPoints.get(this.normalizePathAndCasing(path));
		// if (bps) {
		// 	const index = bps.findIndex(bp => bp.line === line);
		// 	if (index >= 0) {
		// 		const bp = bps[index];
		// 		bps.splice(index, 1);
		// 		return bp;
		// 	}
		// }
		return undefined; // TODO: implement this
	}

	/**
	 * Clears the breakpoints for the specified path.
	 * 
	 * @param path - The path for which breakpoints should be cleared.
	 */
	public clearBreakpoints(path: string): void {
		this.breakPoints.delete(this.normalizePathAndCasing(path));
	}

	// public setDataBreakpoint(address: string, accessType: 'read' | 'write' | 'readWrite'): boolean {

	// 	const x = accessType === 'readWrite' ? 'read write' : accessType;

	// 	const t = this.breakAddresses.get(address);
	// 	if (t) {
	// 		if (t !== x) {
	// 			this.breakAddresses.set(address, 'read write');
	// 		}
	// 	} else {
	// 		this.breakAddresses.set(address, x);
	// 	}
	// 	return true;
	// }

	// public clearAllDataBreakpoints(): void {
	// 	this.breakAddresses.clear();
	// }

	// public setExceptionsFilters(namedException: string | undefined, otherExceptions: boolean): void {
	// 	this.namedException = namedException;
	// 	this.otherExceptions = otherExceptions;
	// }

	/**
	 * Sets an instruction breakpoint at the specified address.
	 * 
	 * @param address - The address where the instruction breakpoint should be set.
	 * @returns A boolean indicating whether the instruction breakpoint was successfully set.
	 */
	public setInstructionBreakpoint(address: number): boolean {
		this.instructionBreakpoints.add(address);
		return true;
	}

	/**
	 * Clears all instruction breakpoints.
	 */
	public clearInstructionBreakpoints(): void {
		this.instructionBreakpoints.clear();
	}

	// public async getGlobalVariables(cancellationToken?: () => boolean ): Promise<RuntimeVariable[]> {

	// 	let a: RuntimeVariable[] = [];

	// 	for (let i = 0; i < 10; i++) {
	// 		a.push(new RuntimeVariable(`global_${i}`, i));
	// 		if (cancellationToken && cancellationToken()) {
	// 			break;
	// 		}
	// 		await timeout(1000);
	// 	}

	// 	return a;
	// }

	// public getLocalVariables(): RuntimeVariable[] {
	// 	return Array.from(this.variables, ([name, value]) => value);
	// }

	/**
	 * Retrieves a local variable by name.
	 * @param name - The name of the variable to retrieve.
	 * @returns The RuntimeVariable object representing the local variable, or undefined if the variable does not exist.
	 */
	public getLocalVariable(name: string): RuntimeVariable | undefined {
		return this.variables.get(name);
	}

	// /**
	//  * Return words of the given address range as "instructions"
	//  */
	// public disassemble(address: number, instructionCount: number): RuntimeDisassembledInstruction[] {

	// 	const instructions: RuntimeDisassembledInstruction[] = [];

	// 	for (let a = address; a < address + instructionCount; a++) {
	// 		if (a >= 0 && a < this.instructions.length) {
	// 			instructions.push({
	// 				address: a,
	// 				instruction: this.instructions[a].name,
	// 				line: this.instructions[a].line
	// 			});
	// 		} else {
	// 			instructions.push({
	// 				address: a,
	// 				instruction: 'nop'
	// 			});
	// 		}
	// 	}

	// 	return instructions;
	// }

	// // private methods

	/**
	 * Retrieves the content of a specific line from the source code.
	 * If no line number is provided, it returns the content of the current line.
	 *
	 * @param line - The line number to retrieve the content from (optional).
	 * @returns The content of the specified line.
	 */
	private getLine(line?: number): string {
		return this.sourceLines[line === undefined ? this.currentLine : line].trim();
	}

	// /**
	//  * Retrieves an array of words from a given line of text.
	//  * 
	//  * @param l - The line number.
	//  * @param line - The line of text to extract words from.
	//  * @returns An array of Word objects containing the name, line number, and index of each word.
	//  */
	// private getWords(l: number, line: string): Word[] {
	// 	// break line into words
	// 	const WORD_REGEXP = /[a-z]+/ig; // This is a simple regex that matches any sequence of lowercase letters.
	// 	const words: Word[] = []; // This array will store the words found in the line.
	// 	let match: RegExpExecArray | null; // This variable will store the result of the regex match.
	// 	while (match = WORD_REGEXP.exec(line)) { // This loop will continue until there are no more matches.
	// 		words.push({ name: match[0], line: l, index: match.index }); // This line adds the word to the words array.
	// 	}
	// 	return words;
	// }

	/**
	 * Loads the source file and initializes its contents.
	 * 
	 * @param file - The path of the source file to load.
	 * @returns A promise that resolves when the source file is loaded and its contents are initialized.
	 */
	private async loadSource(file: string): Promise<void> {
		if (this._sourceFile !== file) {
			this._sourceFile = this.normalizePathAndCasing(file);
			this.initializeContents(await this.fileAccessor.readFile(file));
		}
	}

	/**
	 * Initializes the contents of the runtime.
	 * How it works: The source file is read and split into lines.
	 * Each line is stored as an instruction.
	 * The instructions are stored in the 'instructions' array.
	 * NOTE: This is here because of legacy code. Word objects used to have more fields. 
	 * To refactor, we can remove the Word interface and just use the Instructions interface.
	 * @param memory - The memory to initialize the contents from.
	 */
	private initializeContents(memory: Uint8Array) {

		this.sourceLines = new TextDecoder().decode(memory).split(/\r?\n/);

		this.instructions = [];

		for(let l = 0; l < this.sourceLines.length; l++) {
			this.instructions.push({ line: l, text: this.sourceLines[l] });
		}
	}

	// /**
	//  * return true on stop
	//  */
	 private findNextStatement(reverse: boolean, stepEvent?: string): boolean {
//TODO: implement this
		return false;
	// 	for (let ln = this.currentLine; reverse ? ln >= 0 : ln < this.sourceLines.length; reverse ? ln-- : ln++) {

	// 		// is there a source breakpoint?
	// 		const breakpoints = this.breakPoints.get(this._sourceFile);
	// 		if (breakpoints) {
	// 			const bps = breakpoints.filter(bp => bp.line === ln);
	// 			if (bps.length > 0) {

	// 				// send 'stopped' event
	// 				this.sendEvent('stopOnBreakpoint');

	// 				// the following shows the use of 'breakpoint' events to update properties of a breakpoint in the UI
	// 				// if breakpoint is not yet verified, verify it now and send a 'breakpoint' update event
	// 				if (!bps[0].verified) {
	// 					bps[0].verified = true;
	// 					this.sendEvent('breakpointValidated', bps[0]);
	// 				}

	// 				this.currentLine = ln;
	// 				return true;
	// 			}
	// 		}

	// 		const line = this.getLine(ln);
	// 		if (line.length > 0) {
	// 			this.currentLine = ln;
	// 			break;
	// 		}
	// 	}
	// 	if (stepEvent) {
	// 		this.sendEvent(stepEvent);
	// 		return true;
	// 	}
	// 	return false;
	}

	/**
	 * Parses the response from the server. Change register values and memory values.
	 * @param response - The response to parse in json format.
	 */
	private parseResponse(response: JSON) {
		if (response["line_number"] !== "?") { // line number is ? when the first instruction has not been executed yet
			//parse int response["line_number"]
			this.currentLine = parseInt(response["line_number"]) + 1; //FIXME: this may not need to add 1
		}
		//response schema. TODO: delete this variable when done.
		const data = {
			interrupt: "na",
			line_number: "?",
			insn: {
				memory: "0x4000b0",
				instruction: "mov x0, #1",
			},
			regs: {
				x0: 0,
				x1: 0,
				x2: 0,
				x3: 0,
				x4: 0,
				x5: 0,
				x6: 0,
				x7: 0,
				x8: 0,
				x9: 0,
				x10: 0,
				x11: 0,
				x12: 0,
				x13: 0,
				x14: 0,
				x15: 0,
				x16: 0,
				x17: 0,
				x18: 0,
				x19: 0,
				x20: 0,
				x21: 0,
				x22: 0,
				x23: 0,
				x24: 0,
				x25: 0,
				x26: 0,
				x27: 0,
				x28: 0,
				x29: 0,
				x30: 0,
				sp: 140737488412080,
				pc: 4194480,
				lr: 0,
				cpacr_el1: 3145728,
				tpidr_el0: 0,
				pstate: 1073742789,
				b0: 0,
				b1: 0,
				b2: 0,
				b3: 0,
				b4: 0,
				b5: 0,
				b6: 0,
				b7: 0,
				b8: 0,
				b9: 0,
				b10: 0,
				b11: 0,
				b12: 0,
				b13: 0,
				b14: 0,
				b15: 0,
				b16: 0,
				b17: 0,
				b18: 0,
				b19: 0,
				b20: 0,
				b21: 0,
				b22: 0,
				b23: 0,
				b24: 0,
				b25: 0,
				b26: 0,
				b27: 0,
				b28: 0,
				b29: 0,
				b30: 0,
				b31: 0,
				d0: 0,
				d1: 0,
				d2: 0,
				d3: 0,
				d4: 0,
				d5: 0,
				d6: 0,
				d7: 0,
				d8: 0,
				d9: 0,
				d10: 0,
				d11: 0,
				d12: 0,
				d13: 0,
				d14: 0,
				d15: 0,
				d16: 0,
				d17: 0,
				d18: 0,
				d19: 0,
				d20: 0,
				d21: 0,
				d22: 0,
				d23: 0,
				d24: 0,
				d25: 0,
				d26: 0,
				d27: 0,
				d28: 0,
				d29: 0,
				d30: 0,
				d31: 0,
				h0: 0,
				h1: 0,
				h2: 0,
				h3: 0,
				h4: 0,
				h5: 0,
				h6: 0,
				h7: 0,
				h8: 0,
				h9: 0,
				h10: 0,
				h11: 0,
				h12: 0,
				h13: 0,
				h14: 0,
				h15: 0,
				h16: 0,
				h17: 0,
				h18: 0,
				h19: 0,
				h20: 0,
				h21: 0,
				h22: 0,
				h23: 0,
				h24: 0,
				h25: 0,
				h26: 0,
				h27: 0,
				h28: 0,
				h29: 0,
				h30: 0,
				h31: 0,
				q0: 0,
				q1: 0,
				q2: 0,
				q3: 0,
				q4: 0,
				q5: 0,
				q6: 0,
				q7: 0,
				q8: 0,
				q9: 0,
				q10: 0,
				q11: 0,
				q12: 0,
				q13: 0,
				q14: 0,
				q15: 0,
				q16: 0,
				q17: 0,
				q18: 0,
				q19: 0,
				q20: 0,
				q21: 0,
				q22: 0,
				q23: 0,
				q24: 0,
				q25: 0,
				q26: 0,
				q27: 0,
				q28: 0,
				q29: 0,
				q30: 0,
				q31: 0,
				s0: 0,
				s1: 0,
				s2: 0,
				s3: 0,
				s4: 0,
				s5: 0,
				s6: 0,
				s7: 0,
				s8: 0,
				s9: 0,
				s10: 0,
				s11: 0,
				s12: 0,
				s13: 0,
				s14: 0,
				s15: 0,
				s16: 0,
				s17: 0,
				s18: 0,
				s19: 0,
				s20: 0,
				s21: 0,
				s22: 0,
				s23: 0,
				s24: 0,
				s25: 0,
				s26: 0,
				s27: 0,
				s28: 0,
				s29: 0,
				s30: 0,
				s31: 0,
				w0: 0,
				w1: 0,
				w2: 0,
				w3: 0,
				w4: 0,
				w5: 0,
				w6: 0,
				w7: 0,
				w8: 0,
				w9: 0,
				w10: 0,
				w11: 0,
				w12: 0,
				w13: 0,
				w14: 0,
				w15: 0,
				w16: 0,
				w17: 0,
				w18: 0,
				w19: 0,
				w20: 0,
				w21: 0,
				w22: 0,
				w23: 0,
				w24: 0,
				w25: 0,
				w26: 0,
				w27: 0,
				w28: 0,
				w29: 0,
				w30: 0,
				v0: 0,
				v1: 0,
				v2: 0,
				v3: 0,
				v4: 0,
				v5: 0,
				v6: 0,
				v7: 0,
				v8: 0,
				v9: 0,
				v10: 0,
				v11: 0,
				v12: 0,
				v13: 0,
				v14: 0,
				v15: 0,
				v16: 0,
				v17: 0,
				v18: 0,
				v19: 0,
				v20: 0,
				v21: 0,
				v22: 0,
				v23: 0,
				v24: 0,
				v25: 0,
				v26: 0,
				v27: 0,
				v28: 0,
				v29: 0,
				v30: 0,
				v31: 0,
		}
		
}
		/*
	}

	/**
	 * "execute a line" of the readme markdown.
	 * Returns true if execution sent out a stopped event and needs to stop.
	 */
	private executeLine(ln: number): boolean {
		//execute instruction on server
		this.getCont(); // FIXME: get proper return type
		if (this.instructionBreakpoints.has(ln)) {
			this.sendEvent('stopOnInstructionBreakpoint');
			return true;
		}
		return false;
	}

	/**
	 * Verifies the breakpoints for a given path.
	 * 
	 * @param path - The path of the source file.
	 * @returns A promise that resolves when the breakpoints are verified.
	 */
	private async verifyBreakpoints(path: string): Promise<void> {

		const bps = this.breakPoints.get(path);
		if (bps) {
			await this.loadSource(path);
			bps.forEach(bp => {
				if (!bp.verified && bp.line < this.sourceLines.length) {
					const srcLine = this.getLine(bp.line);

					// NOTE: since qiling does not perserve line numbers, we have to  manually match the line number to the source line
					// This makes it difficult to  handle breakpoints on empty lines or lines with comments or other non-executable code
					// In the future, we may have a list of all 354 executable instructions a line must start with to be executable and set breakpoints on those lines
					// if a line is empty or starts with '/*' we don't allow to set a breakpoint but move the breakpoint down
					if (srcLine.length === 0 || srcLine.trim().indexOf('/*') === 0 || srcLine.trim().indexOf('//')=== 0){
						bp.line++;
					}
					// TODO: handle loops and jumps
					// if (srcLine.indexOf('jmp') === 0) {
					// 	bp.line--;
					// }
					bp.verified = true;
					this.sendEvent('breakpointValidated', bp);
				}
			});
		}
	}
	
	/**
	 * Sends an event with the specified name and arguments asynchronously.
	 * @param event - The name of the event to send.
	 * @param args - The arguments to pass along with the event.
	 */
	private sendEvent(event: string, ... args: any[]): void {
		setTimeout(() => {
			this.emit(event, ...args);
		}, 0);
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
			return path.replace(/\\/g, '/'); // Replace backslashes with forward slashes
		}
	}
}