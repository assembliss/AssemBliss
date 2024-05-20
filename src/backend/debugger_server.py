class debugger_server:
    def __init__(self):
        self.debugger_instance = None

    def start(self, binary_file: str) -> None:
        """
        Starts the debugger with the given binary file.
        """
        pass

    def set_breakpoint(self, address: int) -> None:
        """
        Sets a breakpoint at the specified address.
        """
        pass

    def step(self) -> None:
        """
        Steps through the code.
        """
        pass

    def get_registers(self) -> dict:
        """
        Returns the current state of the registers.
        """
        pass

    def stop(self) -> None:
        """
        Stops the debugger.
        """
        pass
