"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AssemblissDebugSession = void 0;
const DebugAdapter = require("@vscode/debugadapter");
const Runtime_1 = require("../backend/Runtime");
const await_notify_1 = require("await-notify");
const path_browserify_1 = require("path-browserify");
// TODO: implement properly
class AssemblissDebugSession extends DebugAdapter.LoggingDebugSession {
    // 	/**
    // 	 * Creates a new debug adapter that is used for one debug session.
    // 	 * We configure the default implementation of a debug adapter here.
    // 	 */
    constructor(fileAccessor) {
        super("debug-log.txt");
        // NOTE: This has been repurposed from variables to registers, heap, and stack
        /** Handles for different types of variables in the debugger. */
        this._variableHandles = new DebugAdapter.Handles();
        // NOTE: This has been repurposed from variables to registers, heap, and stack
        // private _variableHandles = new DebugAdapter.Handles<'locals' | 'globals' | RuntimeVariable>();
        /**
         * Represents the configuration done subject.
         * This subject is used to notify the launchRequest that configuration has finished.
         */
        this._configurationDone = new await_notify_1.Subject();
        /**
         * Map that stores cancellation tokens for asynchronous operations.
         * This is used to cancel long running operations.
         */
        this._cancellationTokens = new Map();
        /** Indicates whether progress reporting is enabled. */
        // private _reportProgress = false;
        // private _progressId = 10000;
        // private _cancelledProgressId: string | undefined = undefined;
        // private _isProgressCancellable = true;
        // private _valuesInHex = false;
        // 	private _useInvalidatedEvent = false;
        this._addressesInHex = true;
        // this debugger uses one-based lines and columns
        this.setDebuggerLinesStartAt1(true);
        // this.setDebuggerColumnsStartAt1(true);
        this._runtime = new Runtime_1.QilingDebugger(fileAccessor);
        // setup event handlers
        this._runtime.on('stopOnEntry', () => {
            this.sendEvent(new DebugAdapter.StoppedEvent('entry', AssemblissDebugSession.threadID));
        });
        this._runtime.on('stopOnStep', () => {
            this.sendEvent(new DebugAdapter.StoppedEvent('step', AssemblissDebugSession.threadID));
        });
        this._runtime.on('stopOnBreakpoint', () => {
            this.sendEvent(new DebugAdapter.StoppedEvent('breakpoint', AssemblissDebugSession.threadID));
        });
        // this._runtime.on('stopOnDataBreakpoint', () => {
        // 	this.sendEvent(new DebugAdapter.StoppedEvent('data breakpoint', AssemblissDebugSession.threadID));
        // });
        // this._runtime.on('stopOnInstructionBreakpoint', () => {
        // 	this.sendEvent(new DebugAdapter.StoppedEvent('instruction breakpoint', AssemblissDebugSession.threadID));
        // });
        // 		this._runtime.on('stopOnException', (exception) => {
        // 			if (exception) {
        // 				this.sendEvent(new StoppedEvent(`exception(${exception})`, MockDebugSession.threadID));
        // 			} else {
        // 				this.sendEvent(new StoppedEvent('exception', MockDebugSession.threadID));
        // 			}
        // 		}); FIXME: Implement exception handling
        this._runtime.on('breakpointValidated', (bp) => {
            this.sendEvent(new DebugAdapter.BreakpointEvent('changed', { verified: bp.verified, id: bp.id }));
        });
        this._runtime.on('output', (type, text, filePath, line, column) => {
            let category;
            switch (type) {
                case 'prio':
                    category = 'important';
                    break;
                case 'out':
                    category = 'stdout';
                    break;
                case 'err':
                    category = 'stderr';
                    break;
                default:
                    category = 'console';
                    break;
            }
            const e = new DebugAdapter.OutputEvent(`${text}\n`, category);
            if (text === 'start' || text === 'startCollapsed' || text === 'end') {
                e.body.group = text;
                e.body.output = `group-${text}\n`;
            }
            e.body.source = this.createSource(filePath);
            e.body.line = this.convertDebuggerLineToClient(line);
            e.body.column = this.convertDebuggerColumnToClient(column);
            this.sendEvent(e);
        });
        this._runtime.on('end', () => {
            this.sendEvent(new DebugAdapter.TerminatedEvent());
        });
    }
    /**
     * Initializes the debug adapter by setting up its capabilities and sending an 'initializeRequest' to the frontend.
     * This method is called when the debug session starts.
     *
     * @param response - The response object to send back to the frontend.
     * @param args - The arguments passed in the 'initializeRequest'.
     */
    initializeRequest(response, args) {
        // if (args.supportsProgressReporting) {
        // 	this._reportProgress = true;
        // }
        // 		if (args.supportsInvalidatedEvent) {
        // 			this._useInvalidatedEvent = true;
        // 		}
        // build and return the capabilities of this debug adapter:
        response.body = response.body || {};
        // the adapter implements the configurationDone request.
        response.body.supportsConfigurationDoneRequest = true;
        // make VS Code use 'evaluate' when hovering over source
        response.body.supportsEvaluateForHovers = true;
        // make VS Code show a 'step back' button
        response.body.supportsStepBack = false;
        // make VS Code support data breakpoints
        response.body.supportsDataBreakpoints = false;
        // make VS Code support completion in REPL
        response.body.supportsCompletionsRequest = false;
        // response.body.completionTriggerCharacters = [ ".", "[" ];
        // make VS Code send cancel request
        response.body.supportsCancelRequest = true; // NOTE: This may be disabled if I can't figure out how to implement it
        // make VS Code send the breakpointLocations request
        response.body.supportsBreakpointLocationsRequest = true;
        // make VS Code provide "Step in Target" functionality
        response.body.supportsStepInTargetsRequest = false; // NOTE: this is disabled because assembly code doesn't have functions to step into
        // the adapter defines two exceptions filters, one with support for conditions.
        response.body.supportsExceptionFilterOptions = false; // NOTE: This is disabled because I don't know if I need it
        // 		response.body.exceptionBreakpointFilters = [
        // 			{
        // 				filter: 'namedException',
        // 				label: "Named Exception",
        // 				description: `Break on named exceptions. Enter the exception's name as the Condition.`,
        // 				default: false,
        // 				supportsCondition: true,
        // 				conditionDescription: `Enter the exception's name`
        // 			},
        // 			{
        // 				filter: 'otherExceptions',
        // 				label: "Other Exceptions",
        // 				description: 'This is a other exception',
        // 				default: true,
        // 				supportsCondition: false
        // 			}
        // 		];
        // make VS Code send exceptionInfo request
        response.body.supportsExceptionInfoRequest = false; // NOTE: This is disabled because I don't know if I need it
        // make VS Code send setVariable request
        response.body.supportsSetVariable = false;
        // make VS Code send setExpression request
        response.body.supportsSetExpression = false;
        // make VS Code send disassemble request
        response.body.supportsDisassembleRequest = false;
        response.body.supportsSteppingGranularity = false;
        //make VS Code support instruction breakpoints 
        response.body.supportsInstructionBreakpoints = false;
        // 		// make VS Code able to read and write variable memory
        response.body.supportsReadMemoryRequest = true;
        response.body.supportsWriteMemoryRequest = false;
        response.body.supportSuspendDebuggee = true;
        response.body.supportTerminateDebuggee = true;
        response.body.supportsFunctionBreakpoints = false;
        response.body.supportsDelayedStackTraceLoading = false;
        this.sendResponse(response);
        // since this debug adapter can accept configuration requests like 'setBreakpoint' at any time,
        // we request them early by sending an 'initializeRequest' to the frontend.
        // The frontend will end the configuration sequence by calling 'configurationDone' request.
        this.sendEvent(new DebugAdapter.InitializedEvent());
    }
    /**
     * Called at the end of the configuration sequence.
     * Indicates that all breakpoints etc. have been sent to the DA and that the 'launch' can start.
     */
    configurationDoneRequest(response, args) {
        super.configurationDoneRequest(response, args);
        // notify the launchRequest that configuration has finished
        this._configurationDone.notify();
    }
    /**
     * Handles the disconnect request from the debugger.
     * This occurs when the user stops the debugger or the program exits.
     * @param response - The response object to send back to the debugger.
     * @param args - The arguments passed with the disconnect request.
     * @param request - The optional request object associated with the disconnect request.
     */
    disconnectRequest(response, args, request) {
        console.log(`disconnectRequest suspend: ${args.suspendDebuggee}, terminate: ${args.terminateDebuggee}`);
        this._runtime.stop();
        // The following is a potential way I want to handle disconnecting from the debugger
        // if (args.terminateDebuggee) {
        // 	this._runtime.stop();
        // } else {
        // 	// this._runtime.disconnect();
        // }
    }
    // 	protected async attachRequest(response: DebugProtocol.AttachResponse, args: IAttachRequestArguments) {
    // 		return this.launchRequest(response, args);
    // 	}
    /**
     * Handles the 'launch' request from the debugger.
     * Launches the program in the runtime and sends the response back to the debugger.
     * If there is a compile error, it simulates the error and sends an error response.
     * @param response - The response object to send back to the debugger.
     * @param args - The launch request arguments.
     */
    async launchRequest(response, args) {
        // 		// make sure to 'Stop' the buffered logging if 'trace' is not set
        // logger.setup(args.trace ? Logger.LogLevel.Verbose : Logger.LogLevel.Stop, false);
        // 		// wait 1 second until configuration has finished (and configurationDoneRequest has been called)
        await this._configurationDone.wait(1000);
        // 		// start the program in the runtime
        await this._runtime.start(args.target, !!args.stopOnEntry, !args.noDebug);
        // TODO: implement this when launch configurations that assemble and link are implemented
        //_runtime.start() will make args.compileError true if there is no binary file to run
        // if args.compileError is true, attempt to assemble and link the program
        // 		if (args.compileError) {
        // 			// simulate a compile/build error in "launch" request:
        // 			// the error should not result in a modal dialog since 'showUser' is set to false.
        // 			// A missing 'showUser' should result in a modal dialog.
        // 			this.sendErrorResponse(response, {
        // 				id: 1001,
        // 				format: `compile error: some fake error.`,
        // 				showUser: args.compileError === 'show' ? true : (args.compileError === 'hide' ? false : undefined)
        // 			});
        // 		} else {
        // 			this.sendResponse(response);
        // 		}
        this.sendResponse(response);
    }
    // 	protected setFunctionBreakPointsRequest(response: DebugProtocol.SetFunctionBreakpointsResponse, args: DebugProtocol.SetFunctionBreakpointsArguments, request?: DebugProtocol.Request): void {
    // 		this.sendResponse(response);
    // 	}
    /**
     * Sets breakpoints in the specified file and sends back the actual breakpoint positions.
     *
     * @param response - The response object to send back to the client.
     * @param args - The arguments containing the file path and lines to set breakpoints on.
     * @returns A promise that resolves once the breakpoints have been set.
     */
    async setBreakPointsRequest(response, args) {
        const path = args.source.path; // the path is the file to set breakpoints in
        const clientLines = args.lines || []; // the lines to set breakpoints on
        // clear all breakpoints for this file
        this._runtime.clearBreakpoints(path);
        // set and verify breakpoint locations
        const actualBreakpoints0 = clientLines.map(async (l) => {
            const { verified, line, id } = await this._runtime.setBreakPoint(path, this.convertClientLineToDebugger(l));
            const bp = new DebugAdapter.Breakpoint(verified, this.convertDebuggerLineToClient(line));
            bp.id = id;
            return bp;
        });
        const actualBreakpoints = await Promise.all(actualBreakpoints0);
        // send back the actual breakpoint positions
        response.body = {
            breakpoints: actualBreakpoints
        };
        this.sendResponse(response);
    }
    /**
     * Retrieves the locations where breakpoints can be set for a given source and line.
     *
     * @param response - The response object to send back to the debugger.
     * @param args - The arguments passed to the breakpoint locations request.
     * @param request - The original request object.
     */
    breakpointLocationsRequest(response, args, request) {
        if (args.source.path) { // if the source path is provided
            const bps = this._runtime.getBreakpoints(args.source.path, this.convertClientLineToDebugger(args.line)); // get the breakpoints for the source and line
            response.body = {
                breakpoints: bps.map(col => {
                    return {
                        line: args.line,
                        column: this.convertDebuggerColumnToClient(col)
                    };
                })
            };
        }
        else {
            response.body = {
                breakpoints: []
            };
        }
        this.sendResponse(response);
    }
    // 	protected async setExceptionBreakPointsRequest(response: DebugProtocol.SetExceptionBreakpointsResponse, args: DebugProtocol.SetExceptionBreakpointsArguments): Promise<void> {
    // 		let namedException: string | undefined = undefined;
    // 		let otherExceptions = false;
    // 		if (args.filterOptions) {
    // 			for (const filterOption of args.filterOptions) {
    // 				switch (filterOption.filterId) {
    // 					case 'namedException':
    // 						namedException = args.filterOptions[0].condition;
    // 						break;
    // 					case 'otherExceptions':
    // 						otherExceptions = true;
    // 						break;
    // 				}
    // 			}
    // 		}
    // 		if (args.filters) {
    // 			if (args.filters.indexOf('otherExceptions') >= 0) {
    // 				otherExceptions = true;
    // 			}
    // 		}
    // 		this._runtime.setExceptionsFilters(namedException, otherExceptions);
    // 		this.sendResponse(response);
    // 	}
    // 	protected exceptionInfoRequest(response: DebugProtocol.ExceptionInfoResponse, args: DebugProtocol.ExceptionInfoArguments) {
    // 		response.body = {
    // 			exceptionId: 'Exception ID',
    // 			description: 'This is a descriptive description of the exception.',
    // 			breakMode: 'always',
    // 			details: {
    // 				message: 'Message contained in the exception.',
    // 				typeName: 'Short type name of the exception object',
    // 				stackTrace: 'stack frame 1\nstack frame 2',
    // 			}
    // 		};
    // 		this.sendResponse(response);
    // 	}
    /**
     * Sends a threads request to the debug adapter and sets the response body with default threads.
     * @param response - The response object to be sent back to the client.
     */
    threadsRequest(response) {
        // runtime supports no threads so just return a default thread.
        response.body = {
            threads: [
                new DebugAdapter.Thread(AssemblissDebugSession.threadID, "thread 1"),
            ]
        };
        this.sendResponse(response);
    }
    /**
     * Retrieves the stack trace for the debugger.
     *
     * @param response - The response object to send back to the client.
     * @param args - The arguments for the stack trace request.
     */
    stackTraceRequest(response, args) {
        const startFrame = typeof args.startFrame === 'number' ? args.startFrame : 0;
        const maxLevels = typeof args.levels === 'number' ? args.levels : 1000;
        const endFrame = startFrame + maxLevels;
        const stk = this._runtime.stack(startFrame, endFrame);
        response.body = {
            stackFrames: stk.frames.map((f, ix) => {
                const sf = new DebugAdapter.StackFrame(f.index, f.name, this.createSource(f.file), this.convertDebuggerLineToClient(f.line));
                if (typeof f.column === 'number') {
                    sf.column = this.convertDebuggerColumnToClient(f.column);
                }
                if (typeof f.instruction === 'number') {
                    const address = this.formatAddress(f.instruction);
                    sf.name = `${f.name} ${address}`;
                    sf.instructionPointerReference = address;
                }
                return sf;
            }),
            // 4 options for 'totalFrames':
            //omit totalFrames property: 	// VS Code has to probe/guess. Should result in a max. of two requests
            totalFrames: stk.count // stk.count is the correct size, should result in a max. of two requests
            //totalFrames: 1000000 			// not the correct size, should result in a max. of two requests
            //totalFrames: endFrame + 20 	// dynamically increases the size with every requested chunk, results in paging
        };
        this.sendResponse(response);
    }
    /**
     * Handles the scopes request from the debugger.
     * Populates the response with the available scopes.
     * @param response - The response object to be populated.
     * @param args - The arguments passed with the request.
     */
    scopesRequest(response, args) {
        response.body = {
            scopes: [
                // new DebugAdapter.Scope("Registers", this._variableHandles.create(RuntimeVariable), false),
                // new DebugAdapter.Scope("Stack", this._variableHandles.create('stack'), true),
                // new DebugAdapter.Scope("Heap", this._variableHandles.create('heap'), true),
                new DebugAdapter.Scope("Interrupt", this._variableHandles.create('Interrupt'), false),
                new DebugAdapter.Scope("Memory", this._variableHandles.create('Memory'), false),
                new DebugAdapter.Scope("General Purpose Registers", this._variableHandles.create('General Purpose Register'), true),
                new DebugAdapter.Scope("Special Registers", this._variableHandles.create('Special Registers'), false),
                new DebugAdapter.Scope("System Registers", this._variableHandles.create('System Registers'), false),
                new DebugAdapter.Scope("Byte Registers", this._variableHandles.create('Byte Registers'), true),
                new DebugAdapter.Scope("Halfword Registers", this._variableHandles.create('Halfword Registers'), true),
                new DebugAdapter.Scope("Singleword Registers", this._variableHandles.create('Singleword Registers'), true),
                new DebugAdapter.Scope("Doubleword Registers", this._variableHandles.create('Doubleword Registers'), true),
                new DebugAdapter.Scope("Quadword Registers", this._variableHandles.create('Quadword Registers'), true),
                new DebugAdapter.Scope("Vector Registers", this._variableHandles.create('Vector Registers'), true),
                new DebugAdapter.Scope("Work Registers", this._variableHandles.create('Work Registers'), true),
                new DebugAdapter.Scope("Instruction", this._variableHandles.create('Instruction'), false)
            ]
        };
        this.sendResponse(response);
    }
    // 	protected async writeMemoryRequest(response: DebugProtocol.WriteMemoryResponse, { data, memoryReference, offset = 0 }: DebugProtocol.WriteMemoryArguments) {
    // 		const variable = this._variableHandles.get(Number(memoryReference));
    // 		if (typeof variable === 'object') {
    // 			const decoded = base64.toByteArray(data);
    // 			variable.setMemory(decoded, offset);
    // 			response.body = { bytesWritten: decoded.length };
    // 		} else {
    // 			response.body = { bytesWritten: 0 };
    // 		}
    // 		this.sendResponse(response);
    // 		this.sendEvent(new InvalidatedEvent(['variables']));
    // 	}
    /**
     * Reads memory from the debug target and populates the response object.
     * @param response - The response object to populate with the memory data.
     * @param offset - The offset in memory to start reading from.
     * @param count - The number of bytes to read from memory.
     * @param memoryReference - The reference to the memory location.
     */
    async readMemoryRequest(response, { offset = 0, count, memoryReference }) {
        // const variable = this._variableHandles.get(Number(memoryReference));
        // if (typeof variable === 'object' && variable.memory) {
        // 	const memory = variable.memory.subarray(
        // 		Math.min(offset, variable.memory.length),
        // 		Math.min(offset + count, variable.memory.length),
        // 	);
        // 	response.body = {
        // 		address: offset.toString(),
        // 		data: base64.fromByteArray(memory),
        // 		unreadableBytes: count - memory.length
        // 	};
        // } else {
        // 	response.body = {
        // 		address: offset.toString(),
        // 		data: '',
        // 		unreadableBytes: count
        // 	};
        // }
        response.body = {
            address: offset.toString(),
            data: '',
            unreadableBytes: count
        };
        this.sendResponse(response);
    }
    /**
     * Handles the variablesRequest from the debugger.
     * Retrieves the variables based on the variablesReference provided in the arguments.
     * Populates the response with the retrieved variables and sends the response back to the debugger.
     * @param response - The response object to populate with the retrieved variables.
     * @param args - The arguments object containing the variablesReference.
     * @param request - The optional request object associated with the variablesRequest.
     * @returns A Promise that resolves when the variables have been retrieved and the response has been sent.
     */
    async variablesRequest(response, args, request) {
        let vs = [];
        const v = this._variableHandles.get(args.variablesReference);
        if (v === 'General Purpose Register') {
            // vs = this._runtime.getLocalVariables();
            vs = this._runtime.getGeneralRegisters();
        }
        else if (v === 'Special Registers') {
            vs = this._runtime.getSpecialRegisters();
        }
        else if (v === 'System Registers') {
            vs = this._runtime.getSystemRegisters();
        }
        else if (v === 'Byte Registers') {
            vs = this._runtime.getByteRegisters();
        }
        else if (v === 'Halfword Registers') {
            vs = this._runtime.getHalfRegisters();
        }
        else if (v === 'Singleword Registers') {
            vs = this._runtime.getSingleRegisters();
        }
        else if (v === 'Doubleword Registers') {
            vs = this._runtime.getDoubleRegisters();
        }
        else if (v === 'Quadword Registers') {
            vs = this._runtime.getQuadRegisters();
        }
        else if (v === 'Vector Registers') {
            vs = this._runtime.getVectorRegisters();
        }
        else if (v === 'Work Registers') {
            vs = this._runtime.getWorkRegisters();
        }
        else if (v === 'Interrupt') {
            vs = [this._runtime.getInterrupt()];
        }
        else if (v === 'Memory') {
            vs = [this._runtime.getMemory()];
        }
        else if (v === 'Instruction') {
            vs = [this._runtime.getInstruction()];
        }
        else {
            console.log('Invalid variable reference'); //FIXME: handle this
        }
        // 	if (request) {
        // 		this._cancellationTokens.set(request.seq, false);
        // 		vs = await this._runtime.getGlobalVariables(() => !!this._cancellationTokens.get(request.seq));
        // 		this._cancellationTokens.delete(request.seq);
        // 	} else {
        // 		vs = await this._runtime.getGlobalVariables();
        // 	}
        // } else if (v && Array.isArray(v.value)) {
        // 	vs = v.value;
        // }
        response.body = {
            variables: vs.map(v => this.convertFromRuntime(v))
        };
        this.sendResponse(response);
    }
    // 	protected setVariableRequest(response: DebugProtocol.SetVariableResponse, args: DebugProtocol.SetVariableArguments): void {
    // 		const container = this._variableHandles.get(args.variablesReference);
    // 		const rv = container === 'locals'
    // 			? this._runtime.getLocalVariable(args.name)
    // 			: container instanceof RuntimeVariable && container.value instanceof Array
    // 			? container.value.find(v => v.name === args.name)
    // 			: undefined;
    // 		if (rv) {
    // 			rv.value = this.convertToRuntime(args.value);
    // 			response.body = this.convertFromRuntime(rv);
    // 			if (rv.memory && rv.reference) {
    // 				this.sendEvent(new MemoryEvent(String(rv.reference), 0, rv.memory.length));
    // 			}
    // 		}
    // 		this.sendResponse(response);
    // 	}
    /**
     * Resumes the execution of the debugged program.
     *
     * @param response - The response object to send back to the debugger client.
     * @param args - The arguments passed to the 'continue' request.
     */
    continueRequest(response, args) {
        this._runtime.continue(false);
        this.sendResponse(response);
    }
    // /**
    //  * Resumes the execution of the debug target in reverse mode.
    //  * Reverse mode is not supported, so this method sends a response back to the client.
    //  * @param response - The response object to send back to the client.
    //  * @param args - The arguments for the reverse continue request.
    //  */
    // protected reverseContinueRequest(response: DebugProtocol.ReverseContinueResponse, args: DebugProtocol.ReverseContinueArguments): void {
    // 	this._runtime.continue(true);
    // 	this.sendResponse(response);
    // }
    /**
     * Handles the 'next' request from the debugger.
     * Steps the runtime based on the specified granularity and sends the response.
     *
     * @param response - The response object to send back to the debugger.
     * @param args - The arguments passed with the 'next' request.
     */
    nextRequest(response, args) {
        this._runtime.step(args.granularity === 'instruction', false);
        this.sendResponse(response);
    }
    // 	protected stepBackRequest(response: DebugProtocol.StepBackResponse, args: DebugProtocol.StepBackArguments): void {
    // 		this._runtime.step(args.granularity === 'instruction', true);
    // 		this.sendResponse(response);
    // 	}
    // 	protected stepInTargetsRequest(response: DebugProtocol.StepInTargetsResponse, args: DebugProtocol.StepInTargetsArguments) {
    // 		const targets = this._runtime.getStepInTargets(args.frameId);
    // 		response.body = {
    // 			targets: targets.map(t => {
    // 				return { id: t.id, label: t.label };
    // 			})
    // 		};
    // 		this.sendResponse(response);
    // 	}
    // 	protected stepInRequest(response: DebugProtocol.StepInResponse, args: DebugProtocol.StepInArguments): void {
    // 		this._runtime.stepIn(args.targetId);
    // 		this.sendResponse(response);
    // 	}
    // 	protected stepOutRequest(response: DebugProtocol.StepOutResponse, args: DebugProtocol.StepOutArguments): void {
    // 		this._runtime.stepOut();
    // 		this.sendResponse(response);
    // 	}
    /**
     * Evaluates a debug protocol evaluate request.
     *
     * @param response - The debug protocol evaluate response.
     * @param args - The debug protocol evaluate arguments.
     * @returns A promise that resolves when the evaluation is complete.
     */
    async evaluateRequest(response, args) {
        let reply;
        let rv;
        switch (args.context) {
            case 'repl':
                // handle some REPL commands:
                // 'evaluate' supports to create and delete breakpoints from the 'repl':
                const matches = /new +([0-9]+)/.exec(args.expression);
                if (matches && matches.length === 2) {
                    const mbp = await this._runtime.setBreakPoint(this._runtime.sourceFile, this.convertClientLineToDebugger(parseInt(matches[1])));
                    const bp = new DebugAdapter.Breakpoint(mbp.verified, this.convertDebuggerLineToClient(mbp.line), undefined, this.createSource(this._runtime.sourceFile));
                    bp.id = mbp.id;
                    this.sendEvent(new DebugAdapter.BreakpointEvent('new', bp));
                    reply = `breakpoint created`;
                }
                else {
                    const matches = /del +([0-9]+)/.exec(args.expression);
                    if (matches && matches.length === 2) {
                        const mbp = this._runtime.clearBreakPoint(this._runtime.sourceFile, this.convertClientLineToDebugger(parseInt(matches[1])));
                        if (mbp) {
                            const bp = new DebugAdapter.Breakpoint(false);
                            bp.id = mbp.id;
                            this.sendEvent(new DebugAdapter.BreakpointEvent('removed', bp));
                            reply = `breakpoint deleted`;
                        }
                    }
                    else {
                        // const matches = /progress/.exec(args.expression);
                        // if (matches && matches.length === 1) {
                        // 	if (this._reportProgress) {
                        // 		reply = `progress started`;
                        // 		this.progressSequence();
                        // 	} else {
                        // 		reply = `frontend doesn't support progress (capability 'supportsProgressReporting' not set)`;
                        // 	}
                        // }
                    }
                }
            // fall through
            default:
                if (args.expression.startsWith('$')) {
                    rv = this._runtime.getRegister(args.expression.substr(1));
                }
                else {
                    rv = new Runtime_1.RuntimeVariable('eval', this.convertToRuntime(args.expression)); //FIXME: Implement this
                }
                break;
        }
        if (rv) {
            const v = this.convertFromRuntime(rv);
            response.body = {
                result: v.value,
                type: v.type,
                variablesReference: v.variablesReference,
                presentationHint: v.presentationHint
            };
        }
        else {
            response.body = {
                result: reply ? reply : `evaluate(context: '${args.context}', '${args.expression}')`,
                variablesReference: 0
            };
        }
        this.sendResponse(response);
    }
    // /**
    //  * Sets the value of a local variable in the debugger.
    //  * 
    //  * @param response - The response object to send back to the client.
    //  * @param args - The arguments containing the expression and value to set.
    //  */
    // protected setExpressionRequest(response: DebugProtocol.SetExpressionResponse, args: DebugProtocol.SetExpressionArguments): void {
    // 	if (args.expression.startsWith('$')) {
    // 		const rv = this._runtime.getLocalVariable(args.expression.substr(1));
    // 		if (rv) {
    // 			rv.value = this.convertToRuntime(args.value);
    // 			response.body = this.convertFromRuntime(rv);
    // 			this.sendResponse(response);
    // 		} else {
    // 			this.sendErrorResponse(response, {
    // 				id: 1002,
    // 				format: `variable '{lexpr}' not found`,
    // 				variables: { lexpr: args.expression },
    // 				showUser: true
    // 			});
    // 		}
    // 	} else {
    // 		this.sendErrorResponse(response, {
    // 			id: 1003,
    // 			format: `'{lexpr}' not an assignable expression`,
    // 			variables: { lexpr: args.expression },
    // 			showUser: true
    // 		});
    // 	}
    // }
    // /**
    //  * Executes a progress sequence.
    //  * This method starts a long-running operation and sends progress events to the debugger.
    //  * If the operation is cancellable, it can be cancelled by setting the `_cancelledProgressId` property.
    //  */
    // private async progressSequence() {
    // 	const ID = '' + this._progressId++;
    // 	await timeout(100);
    // 	const title = this._isProgressCancellable ? 'Cancellable operation' : 'Long running operation';
    // 	const startEvent: DebugProtocol.ProgressStartEvent = new DebugAdapter.ProgressStartEvent(ID, title);
    // 	startEvent.body.cancellable = this._isProgressCancellable;
    // 	this._isProgressCancellable = !this._isProgressCancellable;
    // 	this.sendEvent(startEvent);
    // 	this.sendEvent(new DebugAdapter.OutputEvent(`start progress: ${ID}\n`));
    // 	let endMessage = 'progress ended';
    // 	for (let i = 0; i < 100; i++) {
    // 		await timeout(500);
    // 		this.sendEvent(new DebugAdapter.ProgressUpdateEvent(ID, `progress: ${i}`));
    // 		if (this._cancelledProgressId === ID) {
    // 			endMessage = 'progress cancelled';
    // 			this._cancelledProgressId = undefined;
    // 			this.sendEvent(new DebugAdapter.OutputEvent(`cancel progress: ${ID}\n`));
    // 			break;
    // 		}
    // 	}
    // 	this.sendEvent(new DebugAdapter.ProgressEndEvent(ID, endMessage));
    // 	this.sendEvent(new DebugAdapter.OutputEvent(`end progress: ${ID}\n`));
    // 	this._cancelledProgressId = undefined;
    // }
    // /**
    //  * Handles the data breakpoint info request.
    //  * 
    //  * @param response - The response object to send back to the debugger.
    //  * @param args - The arguments passed to the data breakpoint info request.
    //  */
    // protected dataBreakpointInfoRequest(response: DebugProtocol.DataBreakpointInfoResponse, args: DebugProtocol.DataBreakpointInfoArguments): void {
    // 	response.body = {
    //         dataId: null,
    //         description: "cannot break on data access",
    //         accessTypes: undefined,
    //         canPersist: false
    //     };
    // 	if (args.variablesReference && args.name) {
    // 		const v = this._variableHandles.get(args.variablesReference);
    // 		if (v === 'globals') {
    // 			response.body.dataId = args.name;
    // 			response.body.description = args.name;
    // 			response.body.accessTypes = [ "write" ];
    // 			response.body.canPersist = true;
    // 		} else {
    // 			response.body.dataId = args.name;
    // 			response.body.description = args.name;
    // 			response.body.accessTypes = ["read", "write", "readWrite"];
    // 			response.body.canPersist = true;
    // 		}
    // 	}
    // 	this.sendResponse(response);
    // }
    // 	protected setDataBreakpointsRequest(response: DebugProtocol.SetDataBreakpointsResponse, args: DebugProtocol.SetDataBreakpointsArguments): void {
    // 		// clear all data breakpoints
    // 		this._runtime.clearAllDataBreakpoints();
    // 		response.body = {
    // 			breakpoints: []
    // 		};
    // 		for (const dbp of args.breakpoints) {
    // 			const ok = this._runtime.setDataBreakpoint(dbp.dataId, dbp.accessType || 'write');
    // 			response.body.breakpoints.push({
    // 				verified: ok
    // 			});
    // 		}
    // 		this.sendResponse(response);
    // 	}
    // /**
    //  * Handles the completions request from the debugger.
    //  * @param response - The response object to send back to the debugger.
    //  * @param args - The arguments for the completions request.
    //  */
    // protected completionsRequest(response: DebugProtocol.CompletionsResponse, args: DebugProtocol.CompletionsArguments): void {
    // 	response.body = {
    // 		targets: [
    // 			{
    // 				label: "item 10",
    // 				sortText: "10"
    // 			},
    // 			{
    // 				label: "item 1",
    // 				sortText: "01",
    // 				detail: "detail 1"
    // 			},
    // 			{
    // 				label: "item 2",
    // 				sortText: "02",
    // 				detail: "detail 2"
    // 			},
    // 			{
    // 				label: "array[]",
    // 				selectionStart: 6,
    // 				sortText: "03"
    // 			},
    // 			{
    // 				label: "func(arg)",
    // 				selectionStart: 5,
    // 				selectionLength: 3,
    // 				sortText: "04"
    // 			}
    // 		]
    // 	};
    // 	this.sendResponse(response);
    // }
    /**
     * Cancels a request and updates the cancellation tokens and progress ID.
     * @param response - The response object.
     * @param args - The arguments object containing the request ID and progress ID.
     */
    cancelRequest(response, args) {
        if (args.requestId) {
            this._cancellationTokens.set(args.requestId, true);
        }
        // if (args.progressId) {
        // 	this._cancelledProgressId = args.progressId;
        // }
    }
    // 	protected disassembleRequest(response: DebugProtocol.DisassembleResponse, args: DebugProtocol.DisassembleArguments) {
    // 		const memoryInt = args.memoryReference.slice(3);
    // 		const baseAddress = parseInt(memoryInt);
    // 		const offset = args.instructionOffset || 0;
    // 		const count = args.instructionCount;
    // 		const isHex = memoryInt.startsWith('0x');
    // 		const pad = isHex ? memoryInt.length-2 : memoryInt.length;
    // 		const loc = this.createSource(this._runtime.sourceFile);
    // 		let lastLine = -1;
    // 		const instructions = this._runtime.disassemble(baseAddress+offset, count).map(instruction => {
    // 			let address = Math.abs(instruction.address).toString(isHex ? 16 : 10).padStart(pad, '0');
    // 			const sign = instruction.address < 0 ? '-' : '';
    // 			const instr : DebugProtocol.DisassembledInstruction = {
    // 				address: sign + (isHex ? `0x${address}` : `${address}`),
    // 				instruction: instruction.instruction
    // 			};
    // 			// if instruction's source starts on a new line add the source to instruction
    // 			if (instruction.line !== undefined && lastLine !== instruction.line) {
    // 				lastLine = instruction.line;
    // 				instr.location = loc;
    // 				instr.line = this.convertDebuggerLineToClient(instruction.line);
    // 			}
    // 			return instr;
    // 		});
    // 		response.body = {
    // 			instructions: instructions
    // 		};
    // 		this.sendResponse(response);
    // 	}
    // /**
    //  * Sets the instruction breakpoints based on the provided arguments.
    //  * 
    //  * @param response - The response object to send back to the debugger.
    //  * @param args - The arguments containing the breakpoints to set.
    //  */
    // protected setInstructionBreakpointsRequest(response: DebugProtocol.SetInstructionBreakpointsResponse, args: DebugProtocol.SetInstructionBreakpointsArguments) {
    // 	// clear all instruction breakpoints
    // 	this._runtime.clearInstructionBreakpoints();
    // 	// set instruction breakpoints
    // 	const breakpoints = args.breakpoints.map(ibp => {
    // 		const address = parseInt(ibp.instructionReference.slice(3));
    // 		const offset = ibp.offset || 0;
    // 		return <DebugProtocol.Breakpoint>{
    // 			verified: this._runtime.setInstructionBreakpoint(address + offset)
    // 		};
    // 	});
    // 	response.body = {
    // 		breakpoints: breakpoints
    // 	};
    // 	this.sendResponse(response);
    // }
    // protected customRequest(command: string, response: DebugProtocol.Response, args: any) {
    // 	if (command === 'toggleFormatting') {
    // 		this._valuesInHex = ! this._valuesInHex;
    // 		if (this._useInvalidatedEvent) {
    // 			this.sendEvent(new InvalidatedEvent( ['variables'] ));
    // 		}
    // 		this.sendResponse(response);
    // 	} else {
    // 		super.customRequest(command, response, args);
    // 	}
    // }
    // 	//---- helpers
    /**
     * Converts a string value to its corresponding runtime variable type.
     *
     * @param value - The string value to be converted.
     * @returns The converted runtime variable type.
     */
    convertToRuntime(value) {
        // value= value.trim();
        // if (value === 'true') {
        // 	return true;
        // }
        // if (value === 'false') {
        // 	return false;
        // }
        // if (value[0] === '\'' || value[0] === '"') {
        // 	return value.substr(1, value.length-2);
        // }
        // const n = parseFloat(value);
        // if (!isNaN(n)) {
        // }
        // return value;
        return 'x0'; //TODO: Implement properly, handle registers, stack, and heap
    }
    /**
     * Converts a `RuntimeVariable` object to a `DebugProtocol.Variable` object.
     *
     * @param v - The `RuntimeVariable` object to convert.
     * @returns The converted `DebugProtocol.Variable` object.
     */
    convertFromRuntime(v) {
        let dapVariable = {
            name: v.name,
            value: v.value.toString(),
            type: typeof v.value,
            variablesReference: 0,
            evaluateName: '$' + v.name
        };
        // if (v.name.indexOf('lazy') >= 0) {
        // 	// a "lazy" variable needs an additional click to retrieve its value
        // 	dapVariable.value = 'lazy var';		// placeholder value
        // 	v.reference ??= this._variableHandles.create(new RuntimeVariable('', [ new RuntimeVariable('', v.value) ]));
        // 	dapVariable.variablesReference = v.reference;
        // 	dapVariable.presentationHint = { lazy: true };
        // } else {
        // 	if (Array.isArray(v.value)) {
        // 		dapVariable.value = 'Object';
        // 		v.reference ??= this._variableHandles.create(v);
        // 		dapVariable.variablesReference = v.reference;
        // 	} else {
        // 		switch (typeof v.value) {
        // 			case 'number':
        // 				if (Math.round(v.value) === v.value) {
        // 					dapVariable.value = this.formatNumber(v.value);
        // 					(<any>dapVariable).__vscodeVariableMenuContext = 'simple';	// enable context menu contribution
        // 					dapVariable.type = 'integer';
        // 				} else {
        // 					// dapVariable.value = v.value.toString();
        // 					// dapVariable.type = 'float';
        // 				}
        // 				break;
        // 			case 'string':
        // 				dapVariable.value = `"${v.value}"`;
        // 				break;
        // 			case 'boolean':
        // 				dapVariable.value = v.value ? 'true' : 'false';
        // 				break;
        // 			default:
        // 				dapVariable.value = typeof v.value;
        // 				break;
        // 		}
        // 	}
        // }
        // if (v.memory) {
        // 	v.reference ??= this._variableHandles.create(v);
        // 	dapVariable.memoryReference = String(v.reference);
        // }
        return dapVariable;
    }
    /**
     * Formats the address value.
     * @param x - The address value to format.
     * @param pad - The number of characters to pad the formatted address with. Default is 8.
     * @returns The formatted address string.
     */
    formatAddress(x, pad = 8) {
        return 'mem' + (this._addressesInHex ? '0x' + x.toString(16).padStart(8, '0') : x.toString(10));
    }
    // /**
    //  * Formats a number as either hexadecimal or decimal based on the `_valuesInHex` flag.
    //  * @param x - The number to be formatted.
    //  * @returns The formatted number.
    //  */
    // private formatNumber(x: number) {
    // 	return this._valuesInHex ? '0x' + x.toString(16) : x.toString(10);
    // }
    /**
     * Creates a DebugAdapter.Source object based on the provided file path.
     *
     * @param filePath - The path of the source file. e.g. /path/to/file.s
     * @returns A DebugAdapter.Source object representing the source file. e.g. { name: 'file.s', path: '/path/to/file.s' }
     */
    createSource(filePath) {
        // this.convertDebuggerPathTOClient taeks the following parameters: path, sourceReference, source
        // qdb-adapter-data is a custom data type that is used to identify the source as a custom source
        return new DebugAdapter.Source((0, path_browserify_1.basename)(filePath), this.convertDebuggerPathToClient(filePath), undefined, undefined, 'qdb-adapter-data');
    }
}
exports.AssemblissDebugSession = AssemblissDebugSession;
// we don't support multiple threads, so we can use a hardcoded ID for the default thread
AssemblissDebugSession.threadID = 1;
//# sourceMappingURL=Qdb.js.map