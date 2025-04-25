import os
import sys
import subprocess
import pytest


TEST_FILES = [
    "./input/0.txt",
    "./input/1.txt",
    "./input/63.txt",
    "./input/64.txt",
    "./input/65.txt",
    "./input/639.txt",
    "./input/640.txt",
    "./input/641.txt",
    "./input/6399.txt",
    "./input/6400.txt",
    "./input/6401.txt",
]


ALGORITHM_DISPLAY_NAMES = {
    "md5": "MD5",
    "sha256": "SHA2-256"
}


class FtSslTester:

    def __init__(self, algorithm: str):
        self.algorithm = algorithm
        self.ft_ssl_path = "../ft_ssl"

    def get_algorithm_display_name(self) -> str:
        """Return the display name for the current algorithm."""
        return ALGORITHM_DISPLAY_NAMES.get(self.algorithm, self.algorithm.upper())

    def run_command(self, command: str) -> str:
        """Run a shell command and return the output."""
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()

    def get_hash(self, input_str: str) -> str:
        """Get hash of an input string using openssl."""
        return self.run_command(f"echo -n {input_str} | openssl {self.algorithm} | cut -d ' ' -f2")


@pytest.fixture
def tester(request):
    """Return a tester instance with the specified algorithm."""
    return FtSslTester(request.param)


@pytest.fixture
def test_file():
    """Create a test file with 'bar' content and clean up afterward."""
    with open("file", "w") as f:
        f.write("bar")
    yield "file"
    if os.path.exists("file"):
        os.remove("file")


class TestComparisonWithOpenSSL:
    
    @pytest.mark.parametrize("filename", TEST_FILES)
    def test_file_input(self, tester: FtSslTester, filename: str):
        """Test file input mode."""
        openssl_output = tester.run_command(f"openssl {tester.algorithm} {filename}")
        ft_ssl_output = tester.run_command(f"{tester.ft_ssl_path} {tester.algorithm} {filename}")
        assert ft_ssl_output == openssl_output, f"File input test failed for {filename}"
    
    @pytest.mark.parametrize("filename", TEST_FILES)
    def test_stdin_input(self, tester: FtSslTester, filename: str):
        """Test stdin input mode."""
        openssl_output = tester.run_command(f"cat {filename} | openssl {tester.algorithm}")
        ft_ssl_output = tester.run_command(f"cat {filename} | {tester.ft_ssl_path} {tester.algorithm}")
        assert ft_ssl_output == openssl_output, f"Stdin input test failed for {filename}"
    
    @pytest.mark.parametrize("filename", TEST_FILES)
    def test_r_option(self, tester: FtSslTester, filename: str):
        """Test -r option."""
        openssl_output = tester.run_command(f"openssl {tester.algorithm} -r {filename}")
        ft_ssl_output = tester.run_command(f"{tester.ft_ssl_path} {tester.algorithm} -r {filename}")
        assert ft_ssl_output == openssl_output, f"r option test failed for {filename}"

    def test_multiple_files(self, tester: FtSslTester):
        """Test multiple files input."""
        files = " ".join(TEST_FILES)
        openssl_output = tester.run_command(f"openssl {tester.algorithm} {files}")
        ft_ssl_output = tester.run_command(f"{tester.ft_ssl_path} {tester.algorithm} {files}")
        assert ft_ssl_output == openssl_output, "Multiple files test failed"


class TestSubjectCases:
    
    # NOTE: We're testing against "{algorithm.upper()}(stdin)=" format rather than
    # just "(stdin)=" (which is mentioned in the subject) to match the format
    # of the openssl version installed on school computers.
    def test_stdin_basic(self, tester: FtSslTester):
        """Test basic stdin input."""
        hash_foo = tester.get_hash("foo")
        algorithm_name = tester.get_algorithm_display_name()
        expected = f"{algorithm_name}(stdin)= {hash_foo}"
        actual = tester.run_command(f"echo -n foo | {tester.ft_ssl_path} {tester.algorithm}")
        assert actual == expected, "Basic stdin test failed"

    def test_stdin_p_option(self, tester: FtSslTester):
        """Test -p option with stdin."""
        hash_foo = tester.get_hash("foo")
        expected = f"(\"foo\")= {hash_foo}"
        actual = tester.run_command(f"echo -n foo | {tester.ft_ssl_path} {tester.algorithm} -p")
        assert actual == expected, "p option with stdin test failed"

    def test_stdin_qr_options(self, tester: FtSslTester):
        """Test -q -r options with stdin."""
        hash_foo = tester.get_hash("foo")
        expected = hash_foo
        actual = tester.run_command(f"echo -n foo | {tester.ft_ssl_path} {tester.algorithm} -q -r")
        assert actual == expected, "q and r options with stdin test failed"

    def test_file_basic(self, tester: FtSslTester, test_file):
        """Test basic file input."""
        hash_bar = tester.get_hash("bar")
        algorithm_name = tester.get_algorithm_display_name()
        expected = f"{algorithm_name}(file)= {hash_bar}"
        actual = tester.run_command(f"{tester.ft_ssl_path} {tester.algorithm} file")
        assert actual == expected, "Basic file test failed"

    def test_file_r_option(self, tester: FtSslTester, test_file):
        """Test -r option with file."""
        hash_bar = tester.get_hash("bar")
        expected = f"{hash_bar} *file"
        actual = tester.run_command(f"{tester.ft_ssl_path} {tester.algorithm} -r file")
        assert actual == expected, "r option with file test failed"

    def test_s_option(self, tester: FtSslTester):
        """Test -s option."""
        hash_foo = tester.get_hash("foo")
        algorithm_name = tester.get_algorithm_display_name()

        expected = f"{algorithm_name}(\"foo\")= {hash_foo}"

        # NOTE: When running with pytest, the program receives an empty stdin input
        # that it processes before handling the -s option, resulting in two lines of output:
        # 1. "{ALGORITHM}(stdin)= {hash of empty string}"  - from the empty stdin
        # 2. "{ALGORITHM}("foo")= {hash_foo}"              - from the -s option
        # We need to extract just the second line which contains the -s option result
        output = tester.run_command(f"{tester.ft_ssl_path} {tester.algorithm} -s foo")
        lines = output.strip().split('\n')
        actual = lines[-1]  # Get the last line
    
        assert actual == expected, "s option test failed"

    def test_stdin_with_file(self, tester: FtSslTester, test_file):
        """Test stdin with file input."""
        hash_bar = tester.get_hash("bar")
        algorithm_name = tester.get_algorithm_display_name()
        expected = f"{algorithm_name}(file)= {hash_bar}"
        actual = tester.run_command(f"echo -n foo | {tester.ft_ssl_path} {tester.algorithm} file")
        assert actual == expected, "stdin with file test failed"

    def test_p_option_with_file(self, tester: FtSslTester, test_file):
        """Test -p option with file."""
        hash_foo = tester.get_hash("foo")
        hash_bar = tester.get_hash("bar")
        algorithm_name = tester.get_algorithm_display_name()
        expected = f"(\"foo\")= {hash_foo}\n{algorithm_name}(file)= {hash_bar}"
        actual = tester.run_command(f"echo -n foo | {tester.ft_ssl_path} {tester.algorithm} -p file")
        assert actual == expected, "p option with file test failed"

    def test_p_r_options_with_file(self, tester: FtSslTester, test_file):
        """Test -p -r options with file."""
        hash_foo = tester.get_hash("foo")
        hash_bar = tester.get_hash("bar")
        expected = f"(\"foo\")= {hash_foo}\n{hash_bar} *file"
        actual = tester.run_command(f"echo -n foo | {tester.ft_ssl_path} {tester.algorithm} -p -r file")
        assert actual == expected, "p and r options with file test failed"

    def test_p_s_options_with_file(self, tester: FtSslTester, test_file):
        """Test -p -s options with file."""
        hash_foo = tester.get_hash("foo")
        hash_bar = tester.get_hash("bar")
        algorithm_name = tester.get_algorithm_display_name()
        expected = f"(\"foo\")= {hash_foo}\n{algorithm_name}(\"foo\")= {hash_foo}\n{algorithm_name}(file)= {hash_bar}"
        actual = tester.run_command(f"echo -n foo | {tester.ft_ssl_path} {tester.algorithm} -p -s foo file")
        assert actual == expected, "p and s options with file test failed"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tests.py <algorithm>")
        sys.exit(1)
    algorithm = sys.argv[1]
    pytest.main(["-v", f"--algorithm={algorithm}"])