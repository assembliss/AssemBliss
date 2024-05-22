"""
This module contains tests for the runtime manager using the pytest framework.
"""
import os
import pytest
from backend.runtime_manager import RuntimeManager


class TestRuntimeManager:
    """
    This class contains unit tests for the runtime_manager class.
    """

    @pytest.fixture
    def manager(self):
        """
        Returns a runtime manager object.

        Parameters:
        - filename (str): The name of the assembly file to be processed.

        Returns:
        - runtime_manager: An instance of the runtime_manager class.

        """
        return RuntimeManager("sampleWorkspace/helloWorld.s")

    def test_assemble(self, manager):
        """
        Test the assemble method of the runtime manager.

        Args:
            manager (RuntimeManager): The runtime manager instance.

        Returns:
            None
        """
        obj_file = manager.assemble()
        if obj_file is None:
            raise AssertionError("obj_file is None")

        if os.path.exists(obj_file):
            os.remove(obj_file)
            
    def test_link(self, manager):
        """
        Test the link method of the RuntimeManager class.

        Args:
            manager (RuntimeManager): An instance of the RuntimeManager class.

        Returns:
            None

        Raises:
            AssertionError: If the executable is None.
        """
        # Ensure the assembly step is performed first 
        if not os.path.exists("sampleWorkspace/helloWorld.obj"):
            obj_file = manager.assemble()
            if not os.path.exists("sampleWorkspace/helloWorld.obj"):
                raise AssertionError("helloWorld.obj is not created")
            
        executable = manager.link()
        if executable is None:
            raise AssertionError("executable is None")

        # Teardown: Remove the created binary and executable files
        if os.path.exists(obj_file):
            os.remove(obj_file)
        if os.path.exists(executable):
            os.remove(executable)
