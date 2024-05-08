"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pathToUri = void 0;
const vscode = require("vscode");
/**
 * Converts a file path to a vscode Uri.
 * If the path is a valid file path, it returns a Uri using `vscode.Uri.file()`.
 * If the path is not a valid file path, it returns a Uri using `vscode.Uri.parse()`.
 * @param path - The file path to convert.
 * @returns A vscode Uri representing the file path.
 */
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