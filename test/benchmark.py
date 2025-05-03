import os
import time
import pytest
from tester import FtSslTester


class TestBenchmark:
    """Benchmark tests comparing ft_ssl with openssl."""

    def test_small_file_benchmark(self, tester: FtSslTester):
        """Benchmark small file hashing performance."""
        # Create small test file (10KB)
        file_path = f"{tester.fuzz_dir}/bench_small.txt"
        tester.create_random_file(file_path, size=10 * 1024, binary=False)
        
        # Benchmark ft_ssl
        ft_start = time.time()
        for _ in range(100):  # Run 100 times for more accurate measurement
            tester.run_command(f"{tester.ft_ssl_path} {tester.algorithm} {file_path}")
        ft_time = time.time() - ft_start
        
        # Benchmark openssl
        openssl_start = time.time()
        for _ in range(100):
            tester.run_command(f"openssl {tester.algorithm} {file_path}")
        openssl_time = time.time() - openssl_start
        
        # Calculate comparison
        ratio = ft_time / openssl_time if openssl_time > 0 else float('inf')
        
        # Clean up
        try:
            os.remove(file_path)
        except:
            pass
            
        print(f"\nSmall file benchmark results for {tester.algorithm}:")
        print(f"ft_ssl: {ft_time:.4f}s, openssl: {openssl_time:.4f}s")
        print(f"ft_ssl is {ratio:.2f}x slower than openssl for small files")
        
        # We don't assert on performance, just report it

    def test_medium_file_benchmark(self, tester: FtSslTester):
        """Benchmark medium file hashing performance."""
        # Create medium test file (1MB)
        file_path = f"{tester.fuzz_dir}/bench_medium.txt"
        tester.create_random_file(file_path, size=1 * 1024 * 1024, binary=True)
        
        # Benchmark ft_ssl
        ft_start = time.time()
        for _ in range(10):  # Run 10 times for more accurate measurement
            tester.run_command(f"{tester.ft_ssl_path} {tester.algorithm} {file_path}")
        ft_time = time.time() - ft_start
        
        # Benchmark openssl
        openssl_start = time.time()
        for _ in range(10):
            tester.run_command(f"openssl {tester.algorithm} {file_path}")
        openssl_time = time.time() - openssl_start
        
        # Calculate comparison
        ratio = ft_time / openssl_time if openssl_time > 0 else float('inf')
        
        # Clean up
        try:
            os.remove(file_path)
        except:
            pass
            
        print(f"\nMedium file benchmark results for {tester.algorithm}:")
        print(f"ft_ssl: {ft_time:.4f}s, openssl: {openssl_time:.4f}s")
        print(f"ft_ssl is {ratio:.2f}x slower than openssl for medium files")

    def test_large_file_benchmark(self, tester: FtSslTester):
        """Benchmark large file hashing performance."""
        # Create large test file (10MB)
        file_path = f"{tester.fuzz_dir}/bench_large.txt"
        tester.create_random_file(file_path, size=10 * 1024 * 1024, binary=True)
        
        # Benchmark ft_ssl
        ft_start = time.time()
        for _ in range(3):  # Run 3 times for a reasonable test duration
            tester.run_command(f"{tester.ft_ssl_path} {tester.algorithm} {file_path}")
        ft_time = time.time() - ft_start
        
        # Benchmark openssl
        openssl_start = time.time()
        for _ in range(3):
            tester.run_command(f"openssl {tester.algorithm} {file_path}")
        openssl_time = time.time() - openssl_start
        
        # Calculate comparison
        ratio = ft_time / openssl_time if openssl_time > 0 else float('inf')
        
        # Clean up
        try:
            os.remove(file_path)
        except:
            pass
            
        print(f"\nLarge file benchmark results for {tester.algorithm}:")
        print(f"ft_ssl: {ft_time:.4f}s, openssl: {openssl_time:.4f}s")
        print(f"ft_ssl is {ratio:.2f}x slower than openssl for large files")

    def test_option_overhead_benchmark(self, tester: FtSslTester):
        """Benchmark performance overhead of different options."""
        # Create test file
        file_path = f"{tester.fuzz_dir}/bench_options.txt"
        tester.create_random_file(file_path, size=100 * 1024, binary=False)
        
        options = [
            "",
            "-q",
            "-r",
            "-p",
            "-s 'test string'",
            "-q -r",
            "-p -s 'test string'"
        ]
        
        print(f"\nOption overhead benchmark results for {tester.algorithm}:")
        
        base_time = None
        
        for opt in options:
            ft_start = time.time()
            for _ in range(20):
                cmd = f"{tester.ft_ssl_path} {tester.algorithm} {opt}"
                if not opt or "-s" not in opt:
                    cmd += f" {file_path}"
                tester.run_command(cmd)
            ft_time = time.time() - ft_start
            
            if base_time is None and opt == "":
                base_time = ft_time
                print(f"Base (no options): {ft_time:.4f}s")
            elif base_time is not None:
                overhead = (ft_time - base_time) / base_time * 100
                print(f"Option '{opt}': {ft_time:.4f}s ({overhead:.1f}% overhead)")
        
        # Clean up
        try:
            os.remove(file_path)
        except:
            pass