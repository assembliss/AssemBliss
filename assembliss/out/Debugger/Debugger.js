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
exports.workspaceFileAccessor = exports.initialize = void 0;
const vscode = __importStar(require("vscode"));
const utils = __importStar(require("./utils"));
function initialize(context) {
    //throw new Error('Function not implemented.');
    // register a configuration provider for 'qdb' debug type
    const provider = new ConfigurationProvider();
    context.subscriptions.push(vscode.debug.registerDebugConfigurationProvider('qdb', provider));
    console.log('Added configuration provider for qdb debug type.');
    context.subscriptions.push(vscode.commands.registerCommand('assembliss.runEditorContents', (resource) => {
        let targetResource = resource; // targetResource is the file to be run
        if (!targetResource && vscode.window.activeTextEditor) { // if there is no targetResource and there is an active text editor
            targetResource = vscode.window.activeTextEditor.document.uri; // set the targetResource to the active text editor's document uri
        }
        if (targetResource) { // if there is a targetResource
            vscode.debug.startDebugging(undefined, {
                type: 'qdb',
                name: 'Run File',
                request: 'launch',
                program: targetResource.fsPath
            }, { noDebug: true } // noDebug is set to true so that the debugger does not stop at the first line of the program
            );
        }
    }), vscode.commands.registerCommand('assembliss.debugEditorContents', (resource) => {
        let targetResource = resource;
        if (!targetResource && vscode.window.activeTextEditor) {
            targetResource = vscode.window.activeTextEditor.document.uri;
        }
        if (targetResource) {
            vscode.debug.startDebugging(undefined, {
                type: 'qdb',
                name: 'Debug File',
                request: 'launch',
                program: targetResource.fsPath,
                stopOnEntry: true
            });
        }
    }), vscode.commands.registerCommand('assemblis.toggleFormatting', (variable) => {
        const ds = vscode.debug.activeDebugSession;
        if (ds) {
            ds.customRequest('toggleFormatting');
        }
    }));
    console.log('Added commands for running and debugging editor contents.');
    // register a command that asks for a program name
    vscode.commands.registerCommand('assembliss.getProgramName', config => {
        return vscode.window.showInputBox({
            placeHolder: 'Please enter the name of an arm assembly file in the workspace folder'
        });
    });
    console.log('Added command for getting program name.');
    // register a dynamic configuration provider for 'qdb' debug type
    context.subscriptions.push(vscode.debug.registerDebugConfigurationProvider('qdb', {
        // TODO: figure out how to get this to appear in Assembliss instead of undefined
        provideDebugConfigurations(folder) {
            return [
                {
                    name: "Assembliss: Dynamic Launch",
                    request: "launch",
                    type: "qdb",
                    program: "${file}"
                }
            ];
        }
    }, vscode.DebugConfigurationProviderTriggerKind.Dynamic));
    console.log('Added dynamic configuration provider for qdb debug type.');
    let factory = new DebugAdapterFactory(); // This is where the debug adapter is created
    context.subscriptions.push(vscode.debug.registerDebugAdapterDescriptorFactory('qdb', factory));
    // Checks if the factory object has a dispose method. 
    // The dispose method is a convention in VSCode extensions for cleaning up resources. 
    // If the factory object can be disposed of, it's added to the context subscriptions as well. 
    // This ensures that the factory's dispose method will be called when the extension is deactivated, 
    // allowing the factory to clean up its resources.
    if ('dispose' in factory) {
        context.subscriptions.push(factory);
    }
    console.log('Added debug adapter descriptor factory for qdb debug type.');
    utils.overrideDebugHover(context); // This is used to override the default hover behavior in the debugger. This may be a stretch goal.
    utils.overrideInlineValues(context); // This is used to override the default inline values behavior in the debugger. This may be a stretch goal.
}
exports.initialize = initialize;
/**
 * This is used to provide the initial configuration for the debugger if launch.json is missing or empty.
 */
class ConfigurationProvider {
    /**
     * Massage a debug configuration just before a debug session is being launched,
     * e.g. add all missing attributes to the debug configuration.
     */
    resolveDebugConfiguration(folder, config, token) {
        // if launch.json is missing or empty
        if (!config.type && !config.request && !config.name) {
            const editor = vscode.window.activeTextEditor;
            if (editor && editor.document.languageId === 'arm64') {
                config.type = 'qdb';
                config.name = 'Launch';
                config.request = 'launch';
                config.program = '${file}';
                config.stopOnEntry = true;
            }
        }
        if (!config.program) {
            return vscode.window.showInformationMessage("Cannot find a program to debug").then(_ => {
                return undefined; // abort launch
            });
        }
        return config;
    }
}
exports.workspaceFileAccessor = {
    isWindows: typeof process !== 'undefined' && process.platform === 'win32',
    async readFile(path) {
        let uri;
        try {
            uri = utils.pathToUri(path);
        }
        catch (e) {
            return new TextEncoder().encode(`cannot read '${path}'`);
        }
        return await vscode.workspace.fs.readFile(uri);
    },
    async writeFile(path, contents) {
        await vscode.workspace.fs.writeFile(utils.pathToUri(path), contents);
    }
};
/**
 * An implementation of a debug adapter descriptor factory that uses an inline implementation of a debug adapter.
 */
class DebugAdapterFactory {
    createDebugAdapterDescriptor(_session) {
        // return new vscode.DebugAdapterInlineImplementation(new AssemblissDebugSession(workspaceFileAccessor));
        return null; // TODO: implement DebugSession
    }
}
//# sourceMappingURL=Debugger.js.map