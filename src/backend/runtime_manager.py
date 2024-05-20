class runtime_manager:
    def __init__(self, assembly_file: str):
        self.assembly_file = assembly_file
        self.binary_file = None

    def assemble(self) -> str:
        """
        Assembles the ARMv8 assembly code into a binary file.
        Returns the path to the binary file.
        """
        pass

    def link(self) -> str:
        """
        Links the assembled code into an executable.
        Returns the path to the executable.
        """
        pass

    def run(self) -> str:
        """
        Runs the executable and returns the output.
        """
        pass

    def debug(self, debugger_server: 'debugger_server') -> None:
        """
        Starts a debugging session using the provided debugger_server.
        """
        pass
