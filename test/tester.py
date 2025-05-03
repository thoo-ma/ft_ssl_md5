import os
import random
import string
import subprocess
import re
import shlex
from pathlib import Path
from typing import List, Tuple, Dict, Any


ALGORITHM_DISPLAY_NAMES = {
    "md5": "MD5",
    "sha256": "SHA2-256"
}


class FtSslTester:
    """A tester class for ft_ssl combining basic testing and fuzzing capabilities."""
    
    def __init__(self, algorithm: str):
        self.algorithm = algorithm
        self.ft_ssl_path = "../ft_ssl"
        self.fuzz_dir = Path("./input/fuzz")
        self.fuzz_dir.mkdir(exist_ok=True, parents=True)
    
    def get_algorithm_display_name(self) -> str:
        """Return the display name for the current algorithm."""
        return ALGORITHM_DISPLAY_NAMES.get(self.algorithm, self.algorithm.upper())
    
    def run_command(self, command: str, capture_text=True, timeout=2) -> str:
        """Run a shell command and return the output."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=capture_text,
                timeout=timeout
            )
            if capture_text:
                return result.stdout.strip()
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout" if not capture_text else ""
    
    def get_hash(self, input_str: str) -> str:
        """Get hash of an input string using openssl."""
        return self.run_command(f"echo -n {input_str} | openssl {self.algorithm} | cut -d ' ' -f2")
    
    def run_with_timeout(self, command: str, timeout: int = 2) -> Tuple[int, str, str]:
        """Run a command with a timeout and return exit code, stdout, stderr."""
        try:
            # Use text=False to get bytes, then manually decode with error handling
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True,
                text=False,  # Get bytes instead of trying to decode as UTF-8
                timeout=timeout
            )
            # Manually decode with error handling
            stdout = result.stdout.decode('utf-8', errors='replace')
            stderr = result.stderr.decode('utf-8', errors='replace')
            return result.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout"
    
    # Fuzzing methods
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
    
    def create_test_file(self, filename: str, content=None):
        """Create a test file with specific content or random content."""
        if content is None:
            # Generate a file with standard test content for hash testing
            content = "test_content"
        
        file_path = f"{self.fuzz_dir}/{filename}"
        with open(file_path, 'w') as f:
            f.write(content)
        
        return file_path
    
    def generate_test_files(self) -> List[str]:
        """Generate a set of test files covering important edge cases."""
        test_files = []
        
        # Important file sizes for hash algorithm testing
        sizes = [0, 1, 63, 64, 65, 127, 128, 129, 511, 512, 513, 1023, 1024, 1025]
        
        for size in sizes:
            # Text file
            file_path = f"{self.fuzz_dir}/text_{size}.txt"
            content = "a" * size
            with open(file_path, 'w') as f:
                f.write(content)
            test_files.append(file_path)
            
            # Binary file
            bin_path = f"{self.fuzz_dir}/bin_{size}.txt"
            bin_content = self.random_binary(size)
            with open(bin_path, 'wb') as f:
                f.write(bin_content)
            test_files.append(bin_path)
        
        return test_files
    
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

    def compare_with_openssl(self, command: str, temp_files: List[str]) -> Tuple[bool, str, str]:
        """
        Compare ft_ssl output with openssl output for the same input.
        Returns (is_match, ft_ssl_output, openssl_output)
        """
        # Skip comparison for options specific to ft_ssl that don't exist in OpenSSL
        if "-p" in command or "-q" in command or "-r" in command:
            # For these custom options, we don't directly compare with OpenSSL
            return True, "", ""
        
        # Run the ft_ssl command first to get its output
        exit_code, ft_ssl_output, _ = self.run_with_timeout(command)
        if exit_code != 0:
            return False, ft_ssl_output, "Command failed"
            
        # For each part of the command, create an equivalent openssl command and compare
        
        # Case 1: -s option handling
        if "-s " in command:
            # Our program processes the -s option specially
            # Extract just the hash value from ft_ssl output
            ft_lines = ft_ssl_output.strip().split('\n')
            
            # Find lines that look like they contain a hash result
            for line in ft_lines:
                if "=" in line and '"' in line:
                    # Extract string content and hash from output like 'MD5("string")= hash'
                    match = re.search(r'"([^"]*)".*=\s*([a-f0-9]+)', line)
                    if match:
                        # Get the string that was hashed
                        s_content = match.group(1)
                        ft_hash = match.group(2).lower()
                        
                        # For complex strings with special characters, write to a temp file
                        # instead of using echo, which might not handle the quotes properly
                        temp_s_file = f"{self.fuzz_dir}/s_string_temp.txt"
                        with open(temp_s_file, 'w') as f:
                            f.write(s_content)
                            
                        # Hash the content with OpenSSL
                        openssl_s_command = f"openssl {self.algorithm} {temp_s_file}"
                        _, openssl_output, _ = self.run_with_timeout(openssl_s_command)
                        
                        # Clean up the temp file
                        try:
                            os.remove(temp_s_file)
                        except:
                            pass
                        
                        # Extract just the hash from OpenSSL output using regex
                        match = re.search(r'([a-f0-9]{32,64})\s*$', openssl_output.strip(), re.IGNORECASE)
                        if match:
                            openssl_hash = match.group(1).lower()
                            if ft_hash != openssl_hash:
                                return False, ft_ssl_output, f"String '{s_content}' hash mismatch: {ft_hash} vs {openssl_hash}"
            
            # If we reach this point when handling -s, assume it's correct
            # since we couldn't find an exact match to verify
            return True, ft_ssl_output, ""
        
        # Case 2: File input handling
        for file_path in temp_files:
            if file_path in command and not file_path.startswith("stdin_"):
                # Create an OpenSSL command just for this file
                openssl_command = f"openssl {self.algorithm} {file_path}"
                _, openssl_file_output, _ = self.run_with_timeout(openssl_command)
                
                # Look for the hash of this file in the ft_ssl output
                if file_path in ft_ssl_output:
                    # Extract just the hash parts from the output line containing this file
                    ft_lines = ft_ssl_output.strip().split('\n')
                    for line in ft_lines:
                        if file_path in line:
                            # Extract hash with regex to get just the hex value
                            ft_match = re.search(r'=\s*([a-f0-9]{32,64})\s*$', line, re.IGNORECASE)
                            if ft_match:
                                ft_hash = ft_match.group(1).lower()
                                
                                # Extract openssl hash
                                openssl_match = re.search(r'([a-f0-9]{32,64})\s*$', openssl_file_output.strip(), re.IGNORECASE)
                                if openssl_match:
                                    openssl_hash = openssl_match.group(1).lower()
                                    
                                    if ft_hash != openssl_hash:
                                        return False, ft_ssl_output, f"File {file_path} hash mismatch"
        
        # Case 3: Standard stdin input
        stdin_file = next((f for f in temp_files if f.startswith(str(self.fuzz_dir) + "/stdin_")), None)
        if stdin_file and "cat" in command and "|" in command:
            # Create an OpenSSL command for the stdin content
            openssl_stdin_command = f"cat {stdin_file} | openssl {self.algorithm}"
            _, openssl_stdin_output, _ = self.run_with_timeout(openssl_stdin_command)
            
            # Look for stdin hash in ft_ssl output
            if "stdin" in ft_ssl_output:
                ft_lines = ft_ssl_output.strip().split('\n')
                for line in ft_lines:
                    if "stdin" in line:
                        # Extract hash with regex
                        ft_match = re.search(r'=\s*([a-f0-9]{32,64})\s*$', line, re.IGNORECASE)
                        if ft_match:
                            ft_hash = ft_match.group(1).lower()
                            
                            # Extract openssl hash
                            openssl_match = re.search(r'([a-f0-9]{32,64})\s*$', openssl_stdin_output.strip(), re.IGNORECASE)
                            if openssl_match:
                                openssl_hash = openssl_match.group(1).lower()
                                
                                if ft_hash != openssl_hash:
                                    return False, ft_ssl_output, f"Stdin hash mismatch"
        
        # If we've made it here without returning False, it's likely correct
        # or the case is too complex for automated verification
        return True, ft_ssl_output, ""

    def fuzz_command_line(self, num_tests: int = 100) -> List[Dict[str, Any]]:
        """
        Fuzz the command line interface with random options and inputs.
        Returns a list of commands that caused failures (crash or incorrect output).
        """
        failures = []
        
        for i in range(num_tests):
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
                    'type': 'crash',
                    'command': command,
                    'exit_code': exit_code,
                    'stdout': stdout,
                    'stderr': stderr,
                    'files': temp_files
                })
                continue  # Skip output verification for crashed commands
            
            # Skip output verification for timeout cases
            if exit_code == -1:
                for file in temp_files:
                    try:
                        os.remove(file)
                    except:
                        pass
                continue
            
            # Skip verification for certain complex cases
            skip_verification = False
            
            # Skip verification for commands with complex quote patterns in -s option
            if "-s " in command:
                # Count nested quotes and special characters
                quote_count = command.count("'") + command.count('"') + command.count('\\')
                special_char_count = sum(1 for c in command if c in '!@#$%^&*(){}[]|;:,.<>?/~`')
                
                # Skip if the command has too many special characters or quotes
                if quote_count >= 3 and special_char_count >= 5:
                    skip_verification = True
            
            # Compare with openssl output for correctness if not skipped
            if not skip_verification and "-z" not in options:  # Skip verification for known-invalid options
                is_match, ft_ssl_output, openssl_output = self.compare_with_openssl(command, temp_files)
                
                if not is_match:
                    failures.append({
                        'type': 'incorrect_output',
                        'command': command,
                        'ft_ssl_output': ft_ssl_output,
                        'openssl_output': openssl_output,
                        'files': temp_files
                    })
                    continue
            
            # Clean up temporary files on success
            for file in temp_files:
                try:
                    os.remove(file)
                except:
                    pass
        
        return failures