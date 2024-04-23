import { spawn } from 'child_process';
import { EventEmitter } from 'events';
import fetch from 'node-fetch';
import * as vscode from 'vscode';

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
export function isGeneralPurposeRegister(register: string): register is GeneralPurposeRegister {
	return register.startsWith('x') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 30;
}
// Special Registers
export type SpecialRegister = 'sp' | 'pc' | 'lr';
export function isSpecialRegister(register: string): register is SpecialRegister {
	return register === 'sp' || register === 'pc' || register === 'lr';
}
// System Registers
export type SystemRegister = 'cpacr_el1' | 'tpidr_el0' | 'pstate';
export function isSystemRegister(register: string): register is SystemRegister {
	return register === 'cpacr_el1' || register === 'tpidr_el0' || register === 'pstate';
}
// SIMD and Floating Point Registers
export type ByteRegister = `b${number}`;  // b0 through b31
export function isByteRegister(register: string): register is ByteRegister {
	return register.startsWith('b') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
export type HalfRegister = `h${number}`;  // h0 through h31
export function isHalfRegister(register: string): register is HalfRegister {
	return register.startsWith('h') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
export type SingleRegister = `s${number}`;  // s0 through s31
export function isSingleRegister(register: string): register is SingleRegister {
	return register.startsWith('s') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
export type DoubleRegister = `d${number}`;  // d0 through d31
export function isDoubleRegister(register: string): register is DoubleRegister {
	return register.startsWith('d') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
export type QuadRegister = `q${number}`;  // q0 through q31
export function isQuadRegister(register: string): register is QuadRegister {
	return register.startsWith('q') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
export type VectorRegister = `v${number}`;  // v0 through v31
export function isVectorRegister(register: string): register is VectorRegister {
	return register.startsWith('v') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
export type WorkRegister = `w${number}`;  // w0 through w31
export function isWorkRegister(register: string): register is WorkRegister {
	return register.startsWith('w') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}

export type Register = GeneralPurposeRegister | SpecialRegister | 
	SystemRegister | ByteRegister | 
	HalfRegister | SingleRegister | 
	DoubleRegister | QuadRegister | 
	VectorRegister | WorkRegister
;

// export type Interrupt = 
// IRuntimeVariableType definition
export type IRuntimeVariableType = Register | "Interrupt" | "Memory" | "Instruction" ;


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

// interface Line {
// 	line: number;
// 	text: string;
// }

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
	// private instructionBreakpoints = new Set<number>();

	// maps from sourceFile to array of IRuntimeBreakpoint
	private breakPoints = new Map<string, IRuntimeBreakpoint[]>();

	// since we want to send breakpoint events, we will assign an id to every event
	// so that the frontend can match events with breakpoints.
	private breakpointId = 1;

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
			{return;}
		let binary = program.split('.')[0]; // gets the binary name by removing the extension
		this.qdbProcess = spawn('python3.11', [path, binary]); // load the program
		this.qdbProcess.stdout.on('data', (data) => { // function for when there is standard output
			// console.log(`stdout: ${data}`); // just display in console.
			vscode.debug.activeDebugConsole.appendLine(data); // display in debug console
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
		

		if (debug) {
			await timeout(1000); // wait for the server to start
			await this.verifyBreakpoints(this._sourceFile);
			if(!stopOnEntry) {
				await this.continue(false);
			} else{
				await this.getRun(); // start the program/
				this.sendEvent('stopOnEntry'); // send the event to the frontend
			}
		} else {
			await timeout(1000); // wait for the server to start
			this.getRunAll();
			// this.stop();
			this.sendEvent('end');
		}

	}

	// private async getMemMap(): Promise<JSON> {
	// 	timeout(1000); 
	// 	const response = await fetch(`http://${this.HOST}:${this.PORT}/?get_MemMap=true`);
	// 	return await response.json();
	// }

	private async getRun(): Promise<void> {
		// await timeout(1000); // wait for the server to start
		const response = await fetch(`http://${this.HOST}:${this.PORT}/?get_run=true`);
		const data = await response.json();
		this.parseResponse(data);
	}

	private async getRunAll(): Promise<void> {
		await fetch(`http://${this.HOST}:${this.PORT}/?get_run_all=true`);
		// const response = await fetch(`http://${this.HOST}:${this.PORT}/?get_run_all=true`);
		// const data = await response.json();
		// this.parseResponse(data);
	}

	private async getCont(): Promise<void> {
		// const response = await Promise.race([
		// 	fetch(`http://${this.HOST}:${this.PORT}/?get_cont=true`),
		// 	new Promise((_, reject) =>
		// 		setTimeout(() => reject(console.error("Request timed out")), 5000)
		// 	)
		// ]);
		const response = await fetch(`http://${this.HOST}:${this.PORT}/?get_cont=true`);
		const data = await response.json();
		this.parseResponse(data);
	}

	/**
	 * Continue execution to the end/beginning.
	 * @param reverse - If true continue execution in reverse. (Reverse execution is not supported)
	 */
	public async continue(reverse: boolean) {

		while (await !this.executeLine(this.currentLine)) { // execute the current line and check if it needs to stop
			// if (this.updateCurrentLine(reverse)) {
			// 	break;
			// }
			// if (this.findNextStatement(reverse)) {
			// 	break;
			// }
		}
		return; 
	}

	
	/**
	 * Executes the next step in the program execution.
	 * 
	 * @param instruction - Indicates whether to step by instruction or by line. This is irrelevant for assembly code because each line is an instruction.
	 * @param reverse - Indicates whether to step in reverse or forward direction. (Reverse execution is not supported)
	 */
	public step(instruction: boolean, reverse: boolean) {
		this.getCont();
		this.sendEvent('stopOnStep'); // this sends the event to the frontend
		
	}

	// private updateCurrentLine(reverse: boolean): boolean {
		// return false;
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
	// }

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
		path = this.normalizePathAndCasing(path);

		const bp: IRuntimeBreakpoint = { verified: false, line, id: this.breakpointId++ };
		let bps = this.breakPoints.get(path);
		if (!bps) {
			bps = new Array<IRuntimeBreakpoint>();
			this.breakPoints.set(path, bps);
		}
		bps.push(bp);

		await this.verifyBreakpoints(path);

		return bp;
		return { id: 0, line, verified: false };
	}

	/*
	 * Clear breakpoint in file with given line.
	 */
	public clearBreakPoint(path: string, line: number): IRuntimeBreakpoint | undefined {
		const bps = this.breakPoints.get(this.normalizePathAndCasing(path));
		if (bps) {
			const index = bps.findIndex(bp => bp.line === line);
			if (index >= 0) {
				const bp = bps[index];
				bps.splice(index, 1);
				return bp;
			}
		}
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

	// /**
	//  * Sets an instruction breakpoint at the specified address.
	//  * 
	//  * @param address - The address where the instruction breakpoint should be set.
	//  * @returns A boolean indicating whether the instruction breakpoint was successfully set.
	//  */
	// public setInstructionBreakpoint(address: number): boolean {
	// 	this.instructionBreakpoints.add(address);
	// 	return true;
	// }

	// /**
	//  * Clears all instruction breakpoints.
	//  */
	// public clearInstructionBreakpoints(): void {
	// 	this.instructionBreakpoints.clear();
	// }

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

	public getGeneralRegisters(): RuntimeVariable[] {
		// return general purpose type registers from this.variables
		let generalRegisters: RuntimeVariable[] = [];
		for (let [key, value] of this.variables) {
			if (isGeneralPurposeRegister(key)) {
				generalRegisters.push(value);
			}
		}
		return generalRegisters;
	}

	public getSpecialRegisters(): RuntimeVariable[] {
		// return special type registers from this.variables
		let specialRegisters: RuntimeVariable[] = [];
		for (let [key, value] of this.variables) {
			if (isSpecialRegister(key)) {
				specialRegisters.push(value);
			}
		}
		return specialRegisters;
	}

	public getSystemRegisters(): RuntimeVariable[] {
		// return system type registers from this.variables
		let systemRegisters: RuntimeVariable[] = [];
		for (let [key, value] of this.variables) {
			if (isSystemRegister(key)) {
				systemRegisters.push(value);
			}
		}
		return systemRegisters;
	}

	public getByteRegisters(): RuntimeVariable[] {
		// return byte type registers from this.variables
		let byteRegisters: RuntimeVariable[] = [];
		for (let [key, value] of this.variables) {
			if (isByteRegister(key)) {
				byteRegisters.push(value);
			}
		}
		return byteRegisters;
	}

	public getHalfRegisters(): RuntimeVariable[] {
		// return half type registers from this.variables
		let halfRegisters: RuntimeVariable[] = [];
		for (let [key, value] of this.variables) {
			if (isHalfRegister(key)) {
				halfRegisters.push(value);
			}
		}
		return halfRegisters;
	}

	public getSingleRegisters(): RuntimeVariable[] {
		// return single type registers from this.variables
		let singleRegisters: RuntimeVariable[] = [];
		for (let [key, value] of this.variables) {
			if (isSingleRegister(key)) {
				singleRegisters.push(value);
			}
		}
		return singleRegisters;
	}

	public getDoubleRegisters(): RuntimeVariable[] {
		// return double type registers from this.variables
		let doubleRegisters: RuntimeVariable[] = [];
		for (let [key, value] of this.variables) {
			if (isDoubleRegister(key)) {
				doubleRegisters.push(value);
			}
		}
		return doubleRegisters;
	}

	public getQuadRegisters(): RuntimeVariable[] {
		// return quad type registers from this.variables
		let quadRegisters: RuntimeVariable[] = [];
		for (let [key, value] of this.variables) {
			if (isQuadRegister(key)) {
				quadRegisters.push(value);
			}
		}
		return quadRegisters;
	}

	public getVectorRegisters(): RuntimeVariable[] {
		// return vector type registers from this.variables
		let vectorRegisters: RuntimeVariable[] = [];
		for (let [key, value] of this.variables) {
			if (isVectorRegister(key)) {
				vectorRegisters.push(value);
			}
		}
		return vectorRegisters;
	}

	public getWorkRegisters(): RuntimeVariable[] {
		// return work type registers from this.variables
		let workRegisters: RuntimeVariable[] = [];
		for (let [key, value] of this.variables) {
			if (isWorkRegister(key)) {
				workRegisters.push(value);
			}
		}
		return workRegisters;
	}

	public getInterrupt(): RuntimeVariable {
		return this.variables.get("Interrupt")!;
	}

	public getMemory(): RuntimeVariable {
		return this.variables.get("Memory")!;
	}

	public getInstruction(): RuntimeVariable {
		return this.variables.get("Instruction")!;
	}


	/**
	 * Retrieves a register by name.
	 * @param name - The name of the variable to retrieve.
	 * @returns The RuntimeVariable object representing the local variable, or undefined if the variable does not exist.
	 */
	public getRegister(name: string): RuntimeVariable | undefined {
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

	/**
	 * Parses the response from the server. Change register values and memory values.
	 * @param response - The response to parse in json format.
	 */
	private parseResponse(response: JSON) {
		if (response["line_number"] !== "?") { // line number is ? when the first instruction has not been executed yet
			//parse int response["line_number"]
			this.currentLine = parseInt(response["line_number"]);
		}

		//Clear this.variables and update it with the new values
		this.variables.clear();

		let interrupt = response["interrupt"];
		let variable = new RuntimeVariable("Interrupt", interrupt);
		this.variables.set("Interrupt", variable);

		let memory = response["insn"]["memory"];
		variable = new RuntimeVariable("Memory", memory);
		this.variables.set("Memory", variable);

		let instruction = response["insn"]["instruction"];
		variable = new RuntimeVariable("Instruction", instruction);
		this.variables.set("Instruction", variable);

		for (let reg in response["regs"]) {
			variable = new RuntimeVariable(reg, response["regs"][reg]);
			this.variables.set(reg, variable);
		}
	}

	/**
	 * execute a line and check for breakpoints
	 * Returns true if execution sent out a stopped event and needs to stop.
	 */
	private async executeLine(ln: number): Promise<boolean> {
		//execute instruction on server
		if(this.currentLine === 0) {
			this.getRun();
		}
		if (this.breakPoints.get(this._sourceFile)?.find(bp => bp.line === ln)) { 
			this.sendEvent('stopOnBreakpoint');
			return true;
		}
		await this.getCont();
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

	public stop() {
		this.qdbProcess.kill('SIGKILL');
	}
}