import os
# import sys
import pytest
from tester import FtSslTester


class TestFuzzing:
    """Tests that verify ft_ssl doesn't crash and produces correct hashes."""
    
    def test_command_line_fuzzing(self, tester: FtSslTester):
        """Test the ft_ssl program with random command-line inputs."""
        # Run 100 fuzzing tests with random command line options and inputs
        failures = tester.fuzz_command_line(100)
        
        # If there are failures, format them for the test output
        if failures:
            failure_details = "\n".join([
                f"Type: {f.get('type', 'unknown')}\n"
                f"Command: {f.get('command', 'N/A')}\n"
                + (f"Exit code: {f.get('exit_code')}\n" if 'exit_code' in f else "")
                + (f"Stdout: {f.get('stdout')}\n" if 'stdout' in f else "")
                + (f"Stderr: {f.get('stderr')}\n" if 'stderr' in f else "")
                + (f"ft_ssl output: {f.get('ft_ssl_output')}\n" if 'ft_ssl_output' in f else "")
                + (f"openssl output: {f.get('openssl_output')}\n" if 'openssl_output' in f else "")
                + (f"Files: {', '.join(f.get('files', []))}\n")
                for f in failures
            ])
            pytest.fail(f"Found {len(failures)} command line fuzzing failures:\n{failure_details}")
    
    def test_edge_case_files(self, tester: FtSslTester):
        """Test the ft_ssl program with specially crafted file content."""
        edge_cases = [
            # Empty file
            ("empty.txt", b""),
            # Very large file (1MB of random data)
            ("large.txt", tester.random_binary(1024 * 1024)),
            # File with just null bytes
            ("nulls.txt", b"\x00" * 1024),
            # File with non-ASCII characters
            ("non_ascii.txt", "こんにちは世界".encode('utf-8')),
            # File with very long lines
            ("long_line.txt", (tester.random_string(10000) + "\n").encode('utf-8')),
            # File with multiple newlines
            ("newlines.txt", b"\n\n\n\n\n\n\n\n\n\n"),
            # File with ASCII control characters
            ("control_chars.txt", bytes(range(32))),
            # File with malformed UTF-8
            ("invalid_utf8.txt", b"\xff\xfe\xfd")
        ]
        
        failures = []
        
        for filename, content in edge_cases:
            temp_file = f"{tester.fuzz_dir}/{filename}"
            with open(temp_file, 'wb') as f:
                f.write(content)
            
            command = f"{tester.ft_ssl_path} {tester.algorithm} {temp_file}"
            exit_code, stdout, stderr = tester.run_with_timeout(command)
            
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
    
    def test_invalid_option_combinations(self, tester: FtSslTester):
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
            test_file = f"{tester.fuzz_dir}/test_invalid_opts.txt"
            with open(test_file, 'w') as f:
                f.write("test data")
            
            command = f"{tester.ft_ssl_path} {tester.algorithm} {options}"
            
            # The program should either run without crashing (exit code 0)
            # or exit with a proper error code (not SEGFAULT)
            exit_code, stdout, stderr = tester.run_with_timeout(command)
            
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
    
    def test_hash_correctness(self, tester: FtSslTester):
        """Test the ft_ssl hash output correctness against OpenSSL for edge cases."""
        edge_cases = [
            # Empty file
            ("empty.txt", b""),
            # Small file with predictable content
            ("one_char.txt", b"a"),
            # File with exactly 64 bytes (block size)
            ("block_size.txt", b"a" * 64),
            # File with 63 bytes (just under block size)
            ("under_block.txt", b"a" * 63),
            # File with 65 bytes (just over block size) 
            ("over_block.txt", b"a" * 65),
            # File with 127 bytes (just under two blocks)
            ("under_two_blocks.txt", b"a" * 127),
            # File with 128 bytes (exactly two blocks)
            ("two_blocks.txt", b"a" * 128),
            # File with 129 bytes (just over two blocks)
            ("over_two_blocks.txt", b"a" * 129),
            # File with mixed content
            ("mixed.txt", b"Hello, World! 123\nTest\0\xff\xaa"),
            # File with all bytes (0-255)
            ("all_bytes.txt", bytes(range(256)))
        ]
        
        failures = []
        
        for filename, content in edge_cases:
            temp_file = f"{tester.fuzz_dir}/{filename}"
            with open(temp_file, 'wb') as f:
                f.write(content)
            
            # Test the file with simple hash (no special options)
            command = f"{tester.ft_ssl_path} {tester.algorithm} {temp_file}"
            exit_code, stdout, stderr = tester.run_with_timeout(command)
            
            # First check: did it crash?
            if exit_code != 0 and exit_code != -1:  # Ignore timeouts
                failures.append({
                    'type': 'crash',
                    'file': temp_file,
                    'description': filename,
                    'command': command,
                    'exit_code': exit_code,
                    'stdout': stdout,
                    'stderr': stderr
                })
                continue
                
            # Second check: is the output correct compared to OpenSSL?
            openssl_command = f"openssl {tester.algorithm} {temp_file}"
            _, openssl_stdout, _ = tester.run_with_timeout(openssl_command)
            
            # Extract only the hash part from both outputs
            ft_hash = ''.join(c for c in stdout if c.lower() in "abcdef0123456789")
            openssl_hash = ''.join(c for c in openssl_stdout if c.lower() in "abcdef0123456789")
            
            if ft_hash != openssl_hash:
                failures.append({
                    'type': 'incorrect_output',
                    'file': temp_file,
                    'description': filename,
                    'command': command,
                    'ft_ssl_output': stdout,
                    'openssl_output': openssl_stdout,
                    'ft_hash': ft_hash,
                    'openssl_hash': openssl_hash
                })
            
            # Clean up on success
            try:
                os.remove(temp_file)
            except:
                pass
        
        if failures:
            failure_details = "\n".join([
                f"Type: {f.get('type', 'unknown')}\n"
                f"File: {f.get('file')} ({f.get('description')})\n"
                f"Command: {f.get('command')}\n"
                + (f"Exit code: {f.get('exit_code')}\n" if 'exit_code' in f else "")
                + (f"ft_ssl output: {f.get('ft_ssl_output')}\n" if 'ft_ssl_output' in f else "")
                + (f"openssl output: {f.get('openssl_output')}\n" if 'openssl_output' in f else "")
                for f in failures
            ])
            pytest.fail(f"Found {len(failures)} verification failures:\n{failure_details}")

    def test_boundary_cases(self, tester: FtSslTester):
        """Test generated files that represent important boundary sizes for hash algorithms."""
        # Generate test files for all the key block boundaries
        test_files = tester.generate_test_files()
        
        failures = []
        
        for file_path in test_files:
            # Test the file with simple hash (no special options)
            command = f"{tester.ft_ssl_path} {tester.algorithm} {file_path}"
            exit_code, stdout, stderr = tester.run_with_timeout(command)
            
            # First check: did it crash?
            if exit_code != 0 and exit_code != -1:  # Ignore timeouts
                failures.append({
                    'type': 'crash',
                    'file': file_path,
                    'command': command,
                    'exit_code': exit_code,
                    'stdout': stdout,
                    'stderr': stderr
                })
                continue
                
            # Second check: is the output correct compared to OpenSSL?
            openssl_command = f"openssl {tester.algorithm} {file_path}"
            _, openssl_stdout, _ = tester.run_with_timeout(openssl_command)
            
            # Extract only the hash part from both outputs
            ft_hash = ''.join(c for c in stdout if c.lower() in "abcdef0123456789")
            openssl_hash = ''.join(c for c in openssl_stdout if c.lower() in "abcdef0123456789")
            
            if ft_hash != openssl_hash:
                failures.append({
                    'type': 'incorrect_output',
                    'file': file_path,
                    'command': command,
                    'ft_ssl_output': stdout,
                    'openssl_output': openssl_stdout,
                    'ft_hash': ft_hash,
                    'openssl_hash': openssl_hash
                })
            
        # Clean up test files
        for file_path in test_files:
            try:
                os.remove(file_path)
            except:
                pass
                
        if failures:
            failure_details = "\n".join([
                f"Type: {f.get('type', 'unknown')}\n"
                f"File: {f.get('file')}\n"
                f"Command: {f.get('command')}\n"
                + (f"Exit code: {f.get('exit_code')}\n" if 'exit_code' in f else "")
                + (f"ft_ssl output: {f.get('ft_ssl_output')}\n" if 'ft_ssl_output' in f else "")
                + (f"openssl output: {f.get('openssl_output')}\n" if 'openssl_output' in f else "")
                for f in failures
            ])
            pytest.fail(f"Found {len(failures)} verification failures:\n{failure_details}")


# if __name__ == "__main__":
#     if len(sys.argv) < 2:
#         print("Usage: python test_fuzzing.py <algorithm>")
#         sys.exit(1)
#     algorithm = sys.argv[1]
#     pytest.main(["-v", f"--algorithm={algorithm}"])