from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json
import sys
from qiling import Qiling
from qiling.const import QL_VERBOSE
from capstone import Cs
import random
import subprocess

#root fs file path
ROOTFS_LOC = r"./rootfs/arm64_linux"
#ARM instructions are 4 bytes long
ARM_INSTRUCT_SIZE = 4
#files to store program state
INSN_INFO_FILE_NAME = 'insnINFO.txt'
REGS_INFO_FILE_NAME = 'regsINFO.txt'

#variable to store qiling session
ql = None
interupt = None
programPath = None

#simple disassembler method to get program information
def simple_diassembler(ql: Qiling, address: int, size: int, md: Cs) -> None:
    # Reads the memory from the given address.
    buf = ql.mem.read(address, size)

    with open(INSN_INFO_FILE_NAME, 'w') as f:
        pass
    with open(REGS_INFO_FILE_NAME, 'w') as f:
        pass

    # Disassemble the memory part so we can remap it to what instruction happened.
    #Write register and instruction info for file to store on server
    for insn in md.disasm(buf, address):
        #print(f"Running:: {insn.address:#x} : {insn.mnemonic:24s} {insn.op_str}")
        m = ql.arch.regs.register_mapping
        regs = {}
        for k in m:
            regs[k] = ql.arch.regs.read(k)
        #write instruction info to file for access by server
        with open(INSN_INFO_FILE_NAME, 'a') as f:
            f.write(f"{insn.address:#x}, {insn.mnemonic:s} {insn.op_str}\n")
        #write register state to file for later access
        with open(REGS_INFO_FILE_NAME, 'a') as f:
            json.dump(regs, f)
            f.write('\n')  # Add a newline to separate JSON objects

#interupt reader prints interupt number and sets interupt number when qiling hooks to interupt
def interRead(ql: Qiling, intno):
    global interupt
    interupt = intno
    #ql.log.debug(f'intno: {intno}')
    #print(f'intno: {intno}')

#handles HTTP Requests for server
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    #builds header for responses
    def send_response_with_headers(self, status_code, content_type='text/html'):
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        self.end_headers()

    #builds response
    def respond(self, status_code, message):
        self.send_response_with_headers(status_code)
        self.wfile.write(message.encode())

    #builds JSON string for server response from recorded information
    def build_program_state_JSON(self, interupt):
        
        with open(INSN_INFO_FILE_NAME, 'r') as insnf:
            with open(REGS_INFO_FILE_NAME, 'r') as regsf:
                #if interupt has been detected send interupt number else send na
                state={}
                if interupt is not None:
                    state['interrupt'] = f'{interupt}'
                else:
                    state['interrupt'] = f'na'
                #get instruction information from file and read information to get line number and info about instruction
                try:
                    insn_info = f'{insnf.readline()[:-1]}'
                    
                    line_number = subprocess.check_output(['addr2line', '-e', programPath, insn_info.split(",")[0]]).decode('utf-8').split(":")[-1].strip()
                    state['line_number'] = line_number
                    
                    insnMap = {}
                    insnMap['memory'] = insn_info.split(",")[0]
                    insnMap['instruction'] = insn_info[insn_info.find(",") + 2:]
                    state['insn'] = insnMap
                except:
                    state['insn'] = f'could not read insn info'
                
                #Load registers from file into new json
                try:
                    state['regs'] = json.load(regsf)
                except:
                    state['regs'] = f'could not read regs info'
                
        return json.dumps(state)
    
    
    #GET request handler, handles getting intial memory map information, starting emulation,
    #and stepping emulation
    def do_GET(self):
        global ql
        global interupt
        
        # Parse the URL
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        
        # Check if request is to get the value
        if 'get_MemMap' in query_params:
            #return memory map string from Qiling
            m = ql.mem.get_formatted_mapinfo()
            returnMap = {}
            returnMap['memMap'] = m
            self.respond(200, json.dumps(returnMap))
        
        #if get run is called, start emulation of loaded file and return program state for first instruction
        elif 'get_run' in query_params:
            interupt = None
            try:
                #hook to code and interupts before starting execution
                ql.clear_hooks()
                ql.hook_code(simple_diassembler, user_data=ql.arch.disassembler)
                ql.hook_intr(interRead)

                ql.run(count=1)
                self.respond(200, self.build_program_state_JSON(interupt))
            except:
                self.respond(400, "ql could not run")

        #if get cont is called, continue emulation from new address and return program state for first instruction
        elif 'get_cont' in query_params:
            interupt = None
            try:
                #read pc register to get next instruction address
                address = ql.arch.regs.read("pc")
                
                ql.run(begin=address, count=1)
                self.respond(200, self.build_program_state_JSON(interupt))
            except:
                self.respond(400, "ql could not run")
        
        #runs entire program in emulation, Not in use
        elif 'get_run_all' in query_params:
            try:
                ql.run()
                self.respond(200, "Ran all way")
            except:
                self.respond(400, "ql could not run")
        else:
            self.respond(400, f"Invalid request: {query_params}")

    #PUT request handler, used to attach file to server, NOT in use
    def do_PUT(self):
        global ql
        
        # Extract content length to read the request body
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(body)
            #if file data is sent load file into ql for emulation can be used to load file onto server from client
            if 'file' in data:
                print(f'target: {str(data["file"])}')
                try:
                    ql = Qiling(
                        str(data['file']).split(), ROOTFS_LOC, verbose=QL_VERBOSE.DEBUG)

                    self.respond(200, "File uploaded successfully")
                except:
                    self.respond(400, "File upload failed")
            else:
                self.respond(400, "Invalid request body")
        except json.JSONDecodeError:
            self.respond(400, "Invalid JSON data")

#starts server
def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8000):
    try:
        server_address = ('', port)
        httpd = server_class(server_address, handler_class)
        print(f"{port}")
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.exit()

#starts server and gets program to emulate from command line args
if __name__ == "__main__":
    arguments = sys.argv[1:]
    if len(arguments) == 1:
        programPath = arguments[0]
        ql = Qiling(programPath.split(), ROOTFS_LOC)
    run(port=31415)
