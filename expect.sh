#!/usr/bin/expect

# Define the test files
set test_files {
    "input/0.txt"
    "input/1.txt"
    "input/63.txt"
    "input/64.txt"
    "input/65.txt"
    "input/639.txt"
    "input/640.txt"
    "input/641.txt"
    "input/6399.txt"
    "input/6400.txt"
    "input/6401.txt"
}

# Function to run file input test cases
proc run_file_tests {algorithm test_files} {
    send_user "\n=== Testing file input mode ===\n"
    foreach filename $test_files {
        # Disable logging of spawn output
        log_user 0

        # Get openssl hash
        spawn openssl $algorithm $filename
        expect eof
        set expected [string trim $expect_out(buffer)]

        # Get ft_ssl hash
        spawn ./ft_ssl $algorithm $filename
        expect eof
        set output [string trim $expect_out(buffer)]

        # Re-enable logging
        log_user 1

        # Compare the outputs
        if { $output eq $expected } {
            send_user "File test passed for $filename ($algorithm): Output matches openssl ✅\n"
        } else {
            send_user "File test failed for $filename ($algorithm): Output does not match openssl ❌\n"
            send_user "Expected: '$expected'\n"
            send_user "Got:      '$output'\n"
        }
    }
}

# Function to run stdin input test cases
proc run_stdin_tests {algorithm test_files} {
    send_user "\n=== Testing stdin input mode ===\n"
    foreach filename $test_files {
        # Disable logging of spawn output
        log_user 0

        # Get openssl hash
        spawn sh -c "cat $filename | openssl $algorithm"
        expect eof
        set expected [string trim $expect_out(buffer)]

        # Get ft_ssl hash
        spawn sh -c "cat $filename | ./ft_ssl $algorithm"
        expect eof
        set output [string trim $expect_out(buffer)]

        # Re-enable logging
        log_user 1

        # Compare the outputs
        if { $output eq $expected } {
            send_user "Stdin test passed for $filename ($algorithm): Output matches openssl ✅\n"
        } else {
            send_user "Stdin test failed for $filename ($algorithm): Output does not match openssl ❌\n"
            send_user "Expected: '$expected'\n"
            send_user "Got:      '$output'\n"
        }
    }
}

# Get algorithm from command line argument
if {$argc != 1} {
    send_user "Usage: expect expect.sh <algorithm>\n"
    exit 1
}
set algorithm [lindex $argv 0]

# Run both test modes
run_file_tests $algorithm $test_files
run_stdin_tests $algorithm $test_files