"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.initialize = void 0;
const vscode = __importStar(require("vscode"));
function initialize(context) {
    //throw new Error('Function not implemented.');
    vscode.commands.registerCommand('assembliss.getProgramName', config => {
        return vscode.window.showInputBox({
            placeHolder: 'Please enter the name of an arm assembly file in the workspace folder',
            value: 'hello.s'
        });
    });
}
exports.initialize = initialize;
// class AssemblissDebugSession extends debugadapter.DebugSession {
//     // The 'initialize' request is the first request called by the frontend to interrogate the features the debug adapter provides.
//     protected initializeRequest(response: debugadapter.InitializeResponse, args: debugadapter.InitializeRequestArguments): void {
//         // Build and return the capabilities of this debug adapter.
//         response.body = response.body || {};
//         // The debug adapter implements the configurationDoneRequest.
//         response.body.supportsConfigurationDoneRequest = true;
//         // The debug adapter supports function breakpoints.
//         response.body.supportsFunctionBreakpoints = true;
//         // The debug adapter supports conditional breakpoints.
//         response.body.supportsConditionalBreakpoints = true;
//         // The debug adapter supports a (side effect free) evaluate request for data hovers.
//         response.body.supportsEvaluateForHovers = true;
//         // The debug adapter supports setting variable values.
//         response.body.supportsSetVariable = true;
//         // The debug adapter supports the 'restart' request.
//         response.body.supportsRestartRequest = true;
//         // The debug adapter supports the 'restart frame' request.
//         response.body.supportsRestartFrame = true;
//         // The debug adapter supports the 'goto targets' request.
//         response.body.supportsGotoTargetsRequest = true;
//         // The debug adapter supports the 'step back' request.
//         response.body.supportsStepBack = true;
//         // The debug adapter supports the 'completions' request.
//         response.body.supportsCompletionsRequest = true;
//         // The debug adapter supports the 'modules' request.
//         response.body.supportsModulesRequest = true;
//         // The debug adapter supports the 'loaded sources' request.
//         response.body.supportsLoadedSourcesRequest = true;
//         // The debug adapter supports the 'log points'.
//         response.body.supportsLogPoints = true;
//         // The debug adapter supports the 'terminate' request.
//         response.body.supportsTerminateRequest = true;
//         // The debug adapter supports the 'terminate threads' request.
//         response.body.supportsTerminateThreadsRequest = true;
//         // The debug adapter supports the 'timeouts' request.
//         response.body.supportsTimeouts = true;
//         // The debug adapter supports the 'exception options' request.
//         response.body.supportsExceptionOptions = true;
//         // The debug adapter supports the 'value formatting' request.
//         response.body.supportsValueFormattingOptions = true;
//         // The debug adapter supports the '
//     }
// }
//# sourceMappingURL=DebuggerExtension.js.map