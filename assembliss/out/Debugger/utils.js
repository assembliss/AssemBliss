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
exports.pathToUri = exports.overrideInlineValues = exports.overrideDebugHover = void 0;
const vscode = __importStar(require("vscode"));
/*
 * This function is used to override the default hover behavior in the debugger.
 * It is used to provide a custom hover behavior for the debugger.
 */
function overrideDebugHover(context) {
    // This is how mock debug hover works
    // FIXME: This is not working
    // context.subscriptions.push(vscode.languages.registerEvaluatableExpressionProvider('markdown', {
    // 	provideEvaluatableExpression(document: vscode.TextDocument, position: vscode.Position): vscode.ProviderResult<vscode.EvaluatableExpression> {
    // 		const VARIABLE_REGEXP = /\$[a-z][a-z0-9]*/ig;
    // 		const line = document.lineAt(position.line).text;
    // 		let m: RegExpExecArray | null;
    // 		while (m = VARIABLE_REGEXP.exec(line)) {
    // 			const varRange = new vscode.Range(position.line, m.index, position.line, m.index + m[0].length);
    // 			if (varRange.contains(position)) {
    // 				return new vscode.EvaluatableExpression(varRange);
    // 			}
    // 		}
    // 		return undefined;
    // 	}
    // }));
}
exports.overrideDebugHover = overrideDebugHover;
/*
 * This function is used to override the default inline values behavior in the debugger.
 * It is used to provide a custom inline values behavior for the debugger.
 */
function overrideInlineValues(context) {
    // This is how mock inline values work
    // FIXME: This is not working
    // context.subscriptions.push(vscode.languages.registerInlineValuesProvider('markdown', {
    // 	provideInlineValues(document: vscode.TextDocument, viewport: vscode.Range, context: vscode.InlineValueContext) : vscode.ProviderResult<vscode.InlineValue[]> {
    // 		const allValues: vscode.InlineValue[] = [];
    // 		for (let l = viewport.start.line; l <= context.stoppedLocation.end.line; l++) {
    // 			const line = document.lineAt(l);
    // 			var regExp = /\$([a-z][a-z0-9]*)/ig;	// variables are words starting with '$'
    // 			do {
    // 				var m = regExp.exec(line.text);
    // 				if (m) {
    // 					const varName = m[1];
    // 					const varRange = new vscode.Range(l, m.index, l, m.index + varName.length);
    // 					// some literal text
    // 					//allValues.push(new vscode.InlineValueText(varRange, `${varName}: ${viewport.start.line}`));
    // 					// value found via variable lookup
    // 					allValues.push(new vscode.InlineValueVariableLookup(varRange, varName, false));
    // 					// value determined via expression evaluation
    // 					//allValues.push(new vscode.InlineValueEvaluatableExpression(varRange, varName));
    // 				}
    // 			} while (m);
    // 		}
    // 		return allValues;
    // 	}
    // }));
}
exports.overrideInlineValues = overrideInlineValues;
function pathToUri(path) {
    try {
        return vscode.Uri.file(path);
    }
    catch (e) {
        return vscode.Uri.parse(path);
    }
}
exports.pathToUri = pathToUri;
//# sourceMappingURL=utils.js.map