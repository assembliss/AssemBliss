"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QilingDebugger = exports.timeout = exports.RuntimeVariable = exports.isWorkRegister = exports.isVectorRegister = exports.isQuadRegister = exports.isDoubleRegister = exports.isSingleRegister = exports.isHalfRegister = exports.isByteRegister = exports.isSystemRegister = exports.isSpecialRegister = exports.isGeneralPurposeRegister = void 0;
const child_process_1 = require("child_process");
const events_1 = require("events");
const node_fetch_1 = require("node-fetch");
const vscode = require("vscode");
function isGeneralPurposeRegister(register) {
    return register.startsWith('x') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 30;
}
exports.isGeneralPurposeRegister = isGeneralPurposeRegister;
function isSpecialRegister(register) {
    return register === 'sp' || register === 'pc' || register === 'lr';
}
exports.isSpecialRegister = isSpecialRegister;
function isSystemRegister(register) {
    return register === 'cpacr_el1' || register === 'tpidr_el0' || register === 'pstate';
}
exports.isSystemRegister = isSystemRegister;
function isByteRegister(register) {
    return register.startsWith('b') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
exports.isByteRegister = isByteRegister;
function isHalfRegister(register) {
    return register.startsWith('h') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
exports.isHalfRegister = isHalfRegister;
function isSingleRegister(register) {
    return register.startsWith('s') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
exports.isSingleRegister = isSingleRegister;
function isDoubleRegister(register) {
    return register.startsWith('d') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
exports.isDoubleRegister = isDoubleRegister;
function isQuadRegister(register) {
    return register.startsWith('q') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
exports.isQuadRegister = isQuadRegister;
function isVectorRegister(register) {
    return register.startsWith('v') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
exports.isVectorRegister = isVectorRegister;
function isWorkRegister(register) {
    return register.startsWith('w') && parseInt(register.slice(1)) >= 0 && parseInt(register.slice(1)) <= 31;
}
exports.isWorkRegister = isWorkRegister;
class RuntimeVariable {
    /**
     * Returns the value of the variable.
     */
    get value() {
        return this._value;
    }
    /**
     * Sets the value of the variable.
     */
    set value(value) {
        this._value = value;
        this._memory = undefined;
    }
    /**
     * Returns the memory representation of the value.
     */
    get memory() {
        if (this._memory === undefined && typeof this._value === 'string') {
            this._memory = new TextEncoder().encode(this._value);
        }
        return this._memory;
    }
    constructor(name, _value) {
        this.name = name;
        this._value = _value;
    }
}
exports.RuntimeVariable = RuntimeVariable;
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
 * it can be viewed as part of the debugger itself. It is the component that records the machine
 * state from the python server and holds the breakpoints and line numbers.
*/
class QilingDebugger extends events_1.EventEmitter {
    get sourceFile() {
        return this._sourceFile;
    }
    get currentLine() {
        return this._currentLine;
    }
    set currentLine(x) {
        this._currentLine = x;
        // this.instruction = this.starts[x];
        // this.instruction = x;
    }
    constructor(fileAccessor) {
        super();
        this.fileAccessor = fileAccessor;
        // NOTE: This class originated from MockRuntime in mockRuntime.ts
        /** The port number for the server. */
        this.PORT = 31415;
        /** The host address for the runtime. */
        this.HOST = 'localhost';
        /**
         * Map that stores runtime variables.
         */
        this.variables = new Map();
        // the initial (and one and only) file we are 'debugging'
        this._sourceFile = '';
        // the contents (= lines) of the one and only file
        this.sourceLines = [];
        this.instructions = [];
        // This is the next line that will be 'executed'
        this._currentLine = 0;
        this.lastLine = -1;
        this._onBreakpoint = false;
        // public instruction = 0;
        // all instruction breakpoint addresses
        // private instructionBreakpoints = new Set<number>();
        // maps from sourceFile to array of IRuntimeBreakpoint
        this.breakPoints = new Map();
        // since we want to send breakpoint events, we will assign an id to every event
        // so that the frontend can match events with breakpoints.
        this.breakpointId = 1;
    }
    /**
     * Start executing the given program.
     */
    async start(program, stopOnEntry, debug) {
        await this.loadSource(this.normalizePathAndCasing(program)); // load the program
        //Get the path to qdb.py
        var re = /\/out\/backend/gi;
        process.chdir(__dirname.replace(re, ""));
        console.log("Current working directory: " + process.cwd());
        let path = this.normalizePathAndCasing('src/backend/DebugServer/debugServer.py');
        if (!program) {
            return;
        }
        let binary = program.split('.')[0]; // gets the binary name by removing the extension
        this.qdbProcess = (0, child_process_1.spawn)('python3.11', [path, binary]); // load the program
        const out = vscode.window.createOutputChannel("Assembliss");
        this.qdbProcess.stdout.on('data', (data) => {
            // console.log(`stdout: ${data}`); // just display in console.
            // vscode.debug.activeDebugConsole.appendLine(data); // display in debug console
            out.appendLine(data.toString());
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
            if (!stopOnEntry) {
                await this.continue(false);
            }
            else {
                await this.getRun(); // start the program/
                this.sendEvent('stopOnEntry'); // send the event to the frontend
            }
        }
        else {
            await timeout(1000); // wait for the server to start
            await this.getRunAll();
            // this.stop();
            this.sendEvent('end');
        }
    }
    // private async getMemMap(): Promise<JSON> {
    // 	timeout(1000); 
    // 	const response = await fetch(`http://${this.HOST}:${this.PORT}/?get_MemMap=true`);
    // 	return await response.json();
    // }
    async getRun() {
        // await timeout(1000); // wait for the server to start
        const response = await (0, node_fetch_1.default)(`http://${this.HOST}:${this.PORT}/?get_run=true`);
        const data = await response.json();
        this.parseResponse(data);
    }
    async getRunAll() {
        await (0, node_fetch_1.default)(`http://${this.HOST}:${this.PORT}/?get_run_all=true`);
        // const response = await fetch(`http://${this.HOST}:${this.PORT}/?get_run_all=true`);
        // const data = await response.json();
        // this.parseResponse(data);
    }
    async getCont() {
        // const response = await Promise.race([
        // 	fetch(`http://${this.HOST}:${this.PORT}/?get_cont=true`),
        // 	new Promise((_, reject) =>
        // 		setTimeout(() => reject(console.error("Request timed out")), 5000)
        // 	)
        // ]);
        const response = await (0, node_fetch_1.default)(`http://${this.HOST}:${this.PORT}/?get_cont=true`);
        const data = await response.json();
        this.parseResponse(data);
    }
    /**
     * Continue execution to the end/beginning.
     * @param reverse - If true continue execution in reverse. (Reverse execution is not supported)
     */
    async continue(reverse) {
        let execution = false;
        do {
            execution = await this.executeLine(this.currentLine);
        } while (!execution);
        return;
    }
    /**
     * Executes the next step in the program execution.
     *
     * @param instruction - Indicates whether to step by instruction or by line. This is irrelevant for assembly code because each line is an instruction.
     * @param reverse - Indicates whether to step in reverse or forward direction. (Reverse execution is not supported)
     */
    async step(instruction, reverse) {
        await this.getCont();
        this.sendEvent('stopOnStep'); // this sends the event to the frontend
    }
    /**
     * Returns the runtime stack within the specified range of frames.
     * @param startFrame The index of the first frame to include in the stack.
     * @param endFrame The index of the last frame to include in the stack.
     * @returns An object representing the runtime stack.
     */
    stack(startFrame, endFrame) {
        const line = this.getLine();
        const words = this.getWords(this.currentLine, line);
        words.push({ text: 'BOTTOM', line: -1 }); // add a sentinel so that the stack is never empty...
        const frames = [];
        // every word of the current line becomes a stack frame.
        for (let i = startFrame; i < Math.min(endFrame, words.length); i++) {
            const stackFrame = {
                index: i,
                name: `${words[i].text}(${i})`, // use a word of the line as the stackframe name
                file: this._sourceFile,
                line: this.currentLine,
            };
            frames.push(stackFrame);
        }
        return {
            frames: frames,
            count: words.length
        };
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
    getBreakpoints(path, line) {
        return [0];
    }
    /*
     * Set breakpoint in file with given line.
     */
    async setBreakPoint(path, line) {
        path = this.normalizePathAndCasing(path);
        const bp = { verified: false, line, id: this.breakpointId++ };
        let bps = this.breakPoints.get(path);
        if (!bps) {
            bps = new Array();
            this.breakPoints.set(path, bps);
        }
        bps.push(bp);
        await this.verifyBreakpoints(path);
        return bp;
    }
    /*
     * Clear breakpoint in file with given line.
     */
    clearBreakPoint(path, line) {
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
    clearBreakpoints(path) {
        this.breakPoints.delete(this.normalizePathAndCasing(path));
    }
    /**
     * Retrieves the general purpose registers from the `variables` map.
     *
     * @returns An array of `RuntimeVariable` objects representing the general purpose registers.
     */
    getGeneralRegisters() {
        // return general purpose type registers from this.variables
        let generalRegisters = [];
        for (let [key, value] of this.variables) {
            if (isGeneralPurposeRegister(key)) {
                generalRegisters.push(value);
            }
        }
        return generalRegisters;
    }
    /**
     * Retrieves the special type registers from the `variables` map.
     *
     * @returns An array of `RuntimeVariable` objects representing the special registers.
     */
    getSpecialRegisters() {
        // return special type registers from this.variables
        let specialRegisters = [];
        for (let [key, value] of this.variables) {
            if (isSpecialRegister(key)) {
                specialRegisters.push(value);
            }
        }
        return specialRegisters;
    }
    /**
     * Retrieves the system type registers from the `variables` map.
     *
     * @returns An array of `RuntimeVariable` objects representing the system registers.
     */
    getSystemRegisters() {
        // return system type registers from this.variables
        let systemRegisters = [];
        for (let [key, value] of this.variables) {
            if (isSystemRegister(key)) {
                systemRegisters.push(value);
            }
        }
        return systemRegisters;
    }
    /**
     * Retrieves the byte type registers from the `variables` map.
     *
     * @returns An array of `RuntimeVariable` objects representing the byte type registers.
     */
    getByteRegisters() {
        // return byte type registers from this.variables
        let byteRegisters = [];
        for (let [key, value] of this.variables) {
            if (isByteRegister(key)) {
                byteRegisters.push(value);
            }
        }
        return byteRegisters;
    }
    /**
     * Retrieves the half type registers from the `variables` map.
     *
     * @returns An array of `RuntimeVariable` objects representing the half type registers.
     */
    getHalfRegisters() {
        // return half type registers from this.variables
        let halfRegisters = [];
        for (let [key, value] of this.variables) {
            if (isHalfRegister(key)) {
                halfRegisters.push(value);
            }
        }
        return halfRegisters;
    }
    /**
     * Retrieves an array of single type registers from the `variables` map.
     *
     * @returns An array of `RuntimeVariable` objects representing the single type registers.
     */
    getSingleRegisters() {
        // return single type registers from this.variables
        let singleRegisters = [];
        for (let [key, value] of this.variables) {
            if (isSingleRegister(key)) {
                singleRegisters.push(value);
            }
        }
        return singleRegisters;
    }
    /**
     * Retrieves the double type registers from the `variables` map.
     *
     * @returns An array of `RuntimeVariable` objects representing the double type registers.
     */
    getDoubleRegisters() {
        // return double type registers from this.variables
        let doubleRegisters = [];
        for (let [key, value] of this.variables) {
            if (isDoubleRegister(key)) {
                doubleRegisters.push(value);
            }
        }
        return doubleRegisters;
    }
    /**
     * Retrieves the quad type registers from the `variables` map.
     *
     * @returns An array of `RuntimeVariable` objects representing the quad type registers.
     */
    getQuadRegisters() {
        // return quad type registers from this.variables
        let quadRegisters = [];
        for (let [key, value] of this.variables) {
            if (isQuadRegister(key)) {
                quadRegisters.push(value);
            }
        }
        return quadRegisters;
    }
    /**
     * Retrieves the vector type registers from the `variables` map.
     *
     * @returns An array of `RuntimeVariable` objects representing the vector registers.
     */
    getVectorRegisters() {
        // return vector type registers from this.variables
        let vectorRegisters = [];
        for (let [key, value] of this.variables) {
            if (isVectorRegister(key)) {
                vectorRegisters.push(value);
            }
        }
        return vectorRegisters;
    }
    /**
     * Retrieves the work type registers from the `variables` map.
     *
     * @returns An array of `RuntimeVariable` objects representing the work type registers.
     */
    getWorkRegisters() {
        // return work type registers from this.variables
        let workRegisters = [];
        for (let [key, value] of this.variables) {
            if (isWorkRegister(key)) {
                workRegisters.push(value);
            }
        }
        return workRegisters;
    }
    getInterrupt() {
        return this.variables.get("Interrupt");
    }
    getMemory() {
        return this.variables.get("Memory");
    }
    getInstruction() {
        return this.variables.get("Instruction");
    }
    /**
     * Retrieves a register by name.
     * @param name - The name of the variable to retrieve.
     * @returns The RuntimeVariable object representing the local variable, or undefined if the variable does not exist.
     */
    getRegister(name) {
        return this.variables.get(name);
    }
    /**
     * Retrieves the content of a specific line from the source code.
     * If no line number is provided, it returns the content of the current line.
     *
     * @param line - The line number to retrieve the content from (optional).
     * @returns The content of the specified line.
     */
    getLine(line) {
        return this.sourceLines[line === undefined ? this.currentLine - 1 : line - 1].trim();
    }
    // /**
    //  * Retrieves an array of words from a given line of text.
    //  * 
    //  * @param l - The line number.
    //  * @param line - The line of text to extract words from.
    //  * @returns An array of Word objects containing the name, line number, and index of each word.
    //  */
    getWords(l, line) {
        // break line into words
        const WORD_REGEXP = /[a-z]+/ig; // This is a simple regex that matches any sequence of lowercase letters.
        const words = []; // This array will store the words found in the line.
        // let match: RegExpExecArray | null; // This variable will store the result of the regex match.
        while (WORD_REGEXP.exec(line)) { // This loop will continue until there are no more matches.
            words.push({ text: line, line: l }); // This line adds the word to the words array.
        }
        return words;
    }
    /**
     * Loads the source file and initializes its contents.
     *
     * @param file - The path of the source file to load.
     * @returns A promise that resolves when the source file is loaded and its contents are initialized.
     */
    async loadSource(file) {
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
    initializeContents(memory) {
        this.sourceLines = new TextDecoder().decode(memory).trimEnd().split(/\r?\n/);
        this.instructions = [];
        for (let l = 0; l < this.sourceLines.length; l++) {
            this.instructions.push({ line: l, text: this.sourceLines[l] });
        }
    }
    /**
     * Parses the response from the server. Change register values and memory values.
     * @param response - The response to parse in json format.
     */
    parseResponse(response) {
        if (this.currentLine >= this.sourceLines.length) {
            //handle exit
            this.sendEvent('end');
        }
        if (response["line_number"] !== "?") { // line number is ? when the first instruction has not been executed yet
            //parse int response["line_number"]
            this.lastLine = this.currentLine;
            this.currentLine = parseInt(response["line_number"]);
        }
        if (this.lastLine === this.currentLine) {
            this.sendEvent('end');
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
    async executeLine(ln) {
        //execute instruction on server
        if (ln === 0) {
            await this.getRun();
        }
        else {
            await this.getCont();
        }
        if (this.currentLine >= this.sourceLines.length || this.currentLine === this.lastLine) {
            this.sendEvent('end');
            return true;
        }
        if (this.breakPoints.get(this._sourceFile)?.find(bp => bp.line === this.currentLine)) {
            this.sendEvent('stopOnBreakpoint');
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
    async verifyBreakpoints(path) {
        const bps = this.breakPoints.get(path);
        if (bps) {
            await this.loadSource(path);
            bps.forEach(bp => {
                if (!bp.verified && bp.line < this.sourceLines.length) {
                    const srcLine = this.getLine(bp.line - 1);
                    // NOTE: since qiling does not perserve line numbers, we have to  manually match the line number to the source line
                    // This makes it difficult to  handle breakpoints on empty lines or lines with comments or other non-executable code
                    // In the future, we may have a list of all 354 executable instructions a line must start with to be executable and set breakpoints on those lines
                    // if a line is empty or starts with '/*' we don't allow to set a breakpoint but move the breakpoint down
                    if (srcLine.length === 0 || srcLine.trim().indexOf('/*') === 0 || srcLine.trim().indexOf('//') === 0) {
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
    sendEvent(event, ...args) {
        setTimeout(() => {
            this.emit(event, ...args);
        }, 0);
    }
    /**
     * This makes sure that the path is in the right format for the current OS
     * @param path path to normalize
     * @returns normalized path
     */
    normalizePathAndCasing(path) {
        if (this.fileAccessor.isWindows) {
            return path.replace(/\//g, '\\').toLowerCase();
        }
        else {
            return path.replace(/\\/g, '/'); // Replace backslashes with forward slashes
        }
    }
    stop() {
        this.qdbProcess.kill('SIGKILL');
    }
}
exports.QilingDebugger = QilingDebugger;
//# sourceMappingURL=Runtime.js.map