import os
import random
import string
import subprocess
import pytest
from pathlib import Path
from typing import List, Tuple
import shlex
from tests import FtSslTester


class FuzzTester:
    """A class for fuzzing tests of the ft_ssl program."""

    def __init__(self, tester: FtSslTester):
        self.tester = tester
        self.ft_ssl_path = self.tester.ft_ssl_path
        self.algorithm = self.tester.algorithm
        self.fuzz_dir = Path("./input/fuzz")
        self.fuzz_dir.mkdir(exist_ok=True, parents=True)

    def random_string(self, length: int) -> str:
        """Generate a random string of specified length."""
        chars = string.ascii_letters + string.digits + string.punctuation + " \t\n"
        return ''.join(random.choice(chars) for _ in range(length))
    
    def random_binary(self, length: int) -> bytes:
        """Generate random binary data of specified length."""
        return bytes(random.randint(0, 255) for _ in range(length))
    
    def create_random_file(self, path: str, size: int, binary: bool = False) -> str:
        """Create a file with random content of specified size."""
        with open(path, 'wb') as f:
            if binary:
                f.write(self.random_binary(size))
            else:
                f.write(self.random_string(size).encode())
        return path
    
    def random_option_string(self) -> str:
        """Generate a random combination of valid options."""
        options = ['-p', '-q', '-r', '-s']
        num_options = random.randint(0, 4)  # 0 to 4 options
        selected = random.sample(options, num_options)
        
        # If -s is selected, add a random string parameter
        if '-s' in selected:
            s_index = selected.index('-s')
            # Insert a random string after -s (could be empty)
            random_str = self.random_string(random.randint(0, 20))
            # Use shlex.quote() to safely escape the string for the shell
            escaped_random_str = shlex.quote(random_str)
            selected[s_index] = f'-s {escaped_random_str}'  # Use the escaped string
        
        return ' '.join(selected)
    
    def run_with_timeout(self, command: str, timeout: int = 2) -> Tuple[int, str, str]:
        """Run a command with a timeout and return exit code, stdout, stderr."""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                timeout=timeout
            )
            # Decode stdout and stderr manually, replacing errors
            stdout = result.stdout.decode('utf-8', errors='replace')
            stderr = result.stderr.decode('utf-8', errors='replace')
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout"
    
    def fuzz_command_line(self, num_tests: int = 100) -> List[str]:
        """
        Fuzz the command line interface with random options and inputs.
        Returns a list of commands that caused failures.
        """
        failures = []
        
        for _ in range(num_tests):
            # Generate random options
            options = self.random_option_string()
            
            # Decide what kind of input to provide
            input_type = random.choice(['none', 'stdin', 'file', 'both'])
            
            command = f"{self.ft_ssl_path} {self.algorithm} {options}"
            stdin_data = None
            
            # Create temporary files if needed
            temp_files = []
            
            if input_type in ['file', 'both']:
                # Create 1-3 temporary files with random content
                num_files = random.randint(1, 3)
                for i in range(num_files):
                    size = random.randint(0, 1024)  # 0-1KB files
                    binary = random.choice([True, False])
                    temp_file = f"{self.fuzz_dir}/fuzz_{i}_{random.randint(0, 10000)}.txt"
                    self.create_random_file(temp_file, size, binary)
                    command += f" {temp_file}"
                    temp_files.append(temp_file)
            
            if input_type in ['stdin', 'both']:
                # Generate random stdin input
                size = random.randint(0, 1024)  # 0-1KB input
                binary = random.choice([True, False])
                if binary:
                    stdin_data = self.random_binary(size)
                else:
                    stdin_data = self.random_string(size)
                
                # Create a temporary file for stdin input
                stdin_file = f"{self.fuzz_dir}/stdin_{random.randint(0, 10000)}.txt"
                with open(stdin_file, 'wb') as f:
                    if isinstance(stdin_data, str):
                        f.write(stdin_data.encode())
                    else:
                        f.write(stdin_data)
                
                command = f"cat {stdin_file} | {command}"
                temp_files.append(stdin_file)
            
            # Run the command with a timeout
            exit_code, stdout, stderr = self.run_with_timeout(command)
            
            # Check if the program crashed
            if exit_code != 0 and exit_code != -1:  # Ignore timeouts
                failures.append({
                    'command': command,
                    'exit_code': exit_code,
                    'stdout': stdout,
                    'stderr': stderr,
                    'files': temp_files
                })
            else:
                # Clean up temporary files on success
                for file in temp_files:
                    try:
                        os.remove(file)
                    except:
                        pass
        
        return failures


@pytest.fixture
def fuzz_tester(tester):
    """Create a fuzz tester instance."""
    return FuzzTester(tester)


class TestFuzzing:
    
    def test_command_line_fuzzing(self, fuzz_tester):
        """Test the ft_ssl program with random command-line inputs."""
        # Run 100 fuzzing tests
        failures = fuzz_tester.fuzz_command_line(100)
        
        # If there are failures, format them for the test output
        if failures:
            failure_details = "\n".join([
                f"Command: {f['command']}\n"
                f"Exit code: {f['exit_code']}\n"
                f"Stdout: {f['stdout']}\n"
                f"Stderr: {f['stderr']}\n"
                f"Files: {', '.join(f['files'])}\n"
                for f in failures
            ])
            pytest.fail(f"Found {len(failures)} command line fuzzing failures:\n{failure_details}")
    
    def test_file_content_fuzzing(self, fuzz_tester):
        """Test the ft_ssl program with specially crafted file content."""
        edge_cases = [
            # Empty file
            ("empty.txt", b""),
            # Very large file (1MB of random data)
            ("large.txt", fuzz_tester.random_binary(1024 * 1024)),
            # File with just null bytes
            ("nulls.txt", b"\x00" * 1024),
            # File with non-ASCII characters
            ("non_ascii.txt", "こんにちは世界".encode('utf-8')),
            # File with very long lines
            ("long_line.txt", (fuzz_tester.random_string(10000) + "\n").encode('utf-8')),
            # File with multiple newlines
            ("newlines.txt", b"\n\n\n\n\n\n\n\n\n\n"),
            # File with ASCII control characters
            ("control_chars.txt", bytes(range(32))),
            # File with malformed UTF-8
            ("invalid_utf8.txt", b"\xff\xfe\xfd")
        ]
        
        failures = []
        
        for filename, content in edge_cases:
            temp_file = f"{fuzz_tester.fuzz_dir}/{filename}"
            with open(temp_file, 'wb') as f:
                f.write(content)
            
            command = f"{fuzz_tester.ft_ssl_path} {fuzz_tester.algorithm} {temp_file}"
            exit_code, stdout, stderr = fuzz_tester.run_with_timeout(command)
            
            if exit_code != 0 and exit_code != -1:  # Ignore timeouts
                failures.append({
                    'file': temp_file,
                    'description': filename,
                    'command': command,
                    'exit_code': exit_code,
                    'stdout': stdout,
                    'stderr': stderr
                })
            else:
                try:
                    os.remove(temp_file)
                except:
                    pass
        
        if failures:
            failure_details = "\n".join([
                f"File: {f['file']} ({f['description']})\n"
                f"Command: {f['command']}\n"
                f"Exit code: {f['exit_code']}\n"
                f"Stdout: {f['stdout']}\n"
                f"Stderr: {f['stderr']}\n"
                for f in failures
            ])
            pytest.fail(f"Found {len(failures)} file content fuzzing failures:\n{failure_details}")
    
    def test_invalid_options(self, fuzz_tester):
        """Test the ft_ssl program with invalid option combinations."""
        invalid_options = [
            # Invalid option
            "-z",
            # Duplicate options
            "-p -p",
            # Multiple conflicting options
            "-q -q -q",
            # Missing argument for -s
            "-s",
            # Many options
            "-p -q -r -s test -p -q -r -s test2",
            # Options after filenames
            "file1.txt -p"
        ]
        
        for options in invalid_options:
            # Create a test file
            test_file = f"{fuzz_tester.fuzz_dir}/test_invalid_opts.txt"
            with open(test_file, 'w') as f:
                f.write("test data")
            
            command = f"{fuzz_tester.ft_ssl_path} {fuzz_tester.algorithm} {options}"
            
            # The program should either run without crashing (exit code 0)
            # or exit with a proper error code (not SEGFAULT)
            exit_code, stdout, stderr = fuzz_tester.run_with_timeout(command)
            
            try:
                os.remove(test_file)
            except:
                pass
            
            # We're only checking for crashes, not correct behavior
            # SIGSEGV is 11, so any exit code matching known signals is a problem
            if exit_code in [11, 6, 8, 10]:  # Common crash signals
                pytest.fail(
                    f"Program crashed with exit code {exit_code} for options: {options}\n"
                    f"Command: {command}\n"
                    f"Stdout: {stdout}\n"
                    f"Stderr: {stderr}"
                )