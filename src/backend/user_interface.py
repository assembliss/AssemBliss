class user_interface:
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
