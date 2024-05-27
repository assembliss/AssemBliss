from http.server import HTTPServer, SimpleHTTPRequestHandler
import sys


class UserInterface:
    """
    User interface for interacting with the runtime_manager and debugger_server.
    """

    def __init__(self, runtime_manager: runtime_manager, debugger_server: debugger_server):
        self.runtime_manager = runtime_manager
        self.debugger_server = debugger_server

    def run(self) -> None:
        """
        Starts the user interface for interacting with the runtime_manager and debugger_server.
        """
        pass

    def get_user_input(self) -> str:
        """
        Gets input from the user.
        """
        pass

    def display_output(self, output: str) -> None:
        """
        Displays output to the user.
        """
        pass

    def start_server(self, server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=8000) -> None:
        """
        Starts the server.
        """
        try:
            server_address = ('', port)
            httpd = server_class(server_address, handler_class)
            httpd.serve_forever()
        except KeyboardInterrupt:
            # Sent this to its own method so I can figure it out later
            self.shutdown_procedure()
            sys.exit()
            
    def shutdown_procedure(self) -> None:
        """
        Procedure to be executed on shutdown.
        """
        pass