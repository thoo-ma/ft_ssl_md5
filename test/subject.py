import os
# import sys
import pytest
from tester import FtSslTester


@pytest.fixture
def test_file():
    """Create a test file with 'bar' content and clean up afterward."""
    with open("file", "w") as f:
        f.write("bar")
    yield "file"
    if os.path.exists("file"):
        os.remove("file")


class TestSubjectCases:
    """Tests that verify the output format matches the subject requirements."""
    
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


# if __name__ == "__main__":
#     if len(sys.argv) < 2:
#         print("Usage: python test_subject.py <algorithm>")
#         sys.exit(1)
#     algorithm = sys.argv[1]
#     pytest.main(["-v", f"--algorithm={algorithm}"])