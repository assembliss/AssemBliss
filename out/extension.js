"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const DebuggerExtension = require("./frontend/Debugger");
const assemblerCommands = require("./AssemblerLinker/assemblerCommands");
// this method is called when your extension is activated
async function activate(context) {
    console.log('Extension "Assembliss" is now active.');
    // Register the assembler commands
    assemblerCommands.activateAssemblerCommands(context);
    // Initialize the DebuggerExtension and register the related commands and providers.
    await DebuggerExtension.initialize(context); // await is used to wait for the promise to resolve before continuing execution.
    console.log('Assembliss extension has finished initializing.');
}
exports.activate = activate;
// this method is called when your extension is deactivated
function deactivate() {
}
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map