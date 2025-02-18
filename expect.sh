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
    # "input/pokemon.nds"

# Helper procedure to clean output string
proc clean_output {str} {
    # Remove trailing pipe characters and whitespace
    set str [string trim $str "|\ \t\n\r"]
    # Normalize line endings
    set str [string map {"\r\n" "\n"} $str]
    return $str
}

# Helper procedure to format multiline strings for comparison
proc format_output_diff {expected got} {
    set result "\n"
    append result "┌──────────────────────────────────────────────\n"
    append result "│ Expected:\n"
    foreach line [split $expected "\n"] {
        append result "│   '$line'\n"
    }
    append result "│\n│ Got:\n"
    foreach line [split $got "\n"] {
        append result "│   '$line'\n"
    }
    append result "└──────────────────────────────────────────────"
    return $result
}

# Function to run file input test cases
proc run_file_tests {algorithm test_files} {
    send_user "───────────────────────────────────────────────\n"
    send_user "Testing file input mode\n"
    send_user "Algorithm: $algorithm\n\n"

    # Track test results
    set passed 0
    set total 0

    foreach filename $test_files {
        incr total
        
        # Disable logging of spawn output
        log_user 0

        # Get openssl hash
        spawn openssl $algorithm $filename
        expect eof
        set expected [clean_output [string trim $expect_out(buffer)]]

        # Get ft_ssl hash
        spawn ./ft_ssl $algorithm $filename
        expect eof
        set output [clean_output [string trim $expect_out(buffer)]]

        # Re-enable logging
        log_user 1

        # Compare outputs
        if {$output eq $expected} {
            incr passed
            send_user "[format "%-30s" $filename] ✅\n"
        } else {
            send_user "[format "%-30s" $filename] ❌"
            send_user [format_output_diff $expected $output]
            send_user "\n"
        }
    }

    # Print summary
    send_user "\nSummary: $passed/$total tests passed\n"
}

# Function to run stdin input test cases
proc run_stdin_tests {algorithm test_files} {
    send_user "───────────────────────────────────────────────\n"
    send_user "Testing stdin input mode\n"
    send_user "Algorithm: $algorithm\n\n"

    # Track test results
    set passed 0
    set total 0

    foreach filename $test_files {
        incr total
        
        # Disable logging of spawn output
        log_user 0

        # Get openssl hash
        spawn sh -c "cat $filename | openssl $algorithm"
        expect eof
        set expected [clean_output [string trim $expect_out(buffer)]]

        # Get ft_ssl hash
        spawn sh -c "cat $filename | ./ft_ssl $algorithm"
        expect eof
        set output [clean_output [string trim $expect_out(buffer)]]

        # Re-enable logging
        log_user 1

        # Compare outputs
        if {$output eq $expected} {
            incr passed
            send_user "[format "%-30s" $filename] ✅\n"
        } else {
            send_user "[format "%-30s" $filename] ❌"
            send_user [format_output_diff $expected $output]
            send_user "\n"
        }
    }

    # Print summary
    send_user "\nSummary: $passed/$total tests passed\n"
}

# Function to run -r option test cases
proc run_r_option_tests {algorithm test_files} {
    send_user "───────────────────────────────────────────────\n"
    send_user "Testing the -r option\n"
    send_user "Algorithm: $algorithm\n\n"

    # Track test results
    set passed 0
    set total 0

    foreach filename $test_files {
        incr total
        
        # Disable logging of spawn output
        log_user 0

        # Get openssl hash
        spawn openssl $algorithm -r $filename
        expect eof
        set expected [clean_output [string trim $expect_out(buffer)]]

        # Get ft_ssl hash
        spawn ./ft_ssl $algorithm -r $filename
        expect eof
        set output [clean_output [string trim $expect_out(buffer)]]

        # Re-enable logging
        log_user 1

        # Compare outputs
        if {$output eq $expected} {
            incr passed
            send_user "[format "%-30s" $filename] ✅\n"
        } else {
            send_user "[format "%-30s" $filename] ❌"
            send_user [format_output_diff $expected $output]
            send_user "\n"
        }
    }

    # Print summary
    send_user "\nSummary: $passed/$total tests passed\n"
}

# Function to run multiple files test
proc run_multiple_files_test {algorithm test_files} {
    send_user "───────────────────────────────────────────────\n"
    send_user "Testing multiple files input\n"
    send_user "Algorithm: $algorithm\n\n"

    # Track test results
    set passed 0
    set total 1

    # Take first 3 files from test_files for multiple file test
    set files_to_test [lrange $test_files 0 2]
    set test_name [join $files_to_test ", "]

    # Disable logging of spawn output
    log_user 0

    # Get openssl hash for multiple files
    spawn openssl $algorithm {*}$files_to_test
    expect eof
    set expected [clean_output [string trim $expect_out(buffer)]]

    # Get ft_ssl hash for multiple files
    spawn ./ft_ssl $algorithm {*}$files_to_test
    expect eof
    set output [clean_output [string trim $expect_out(buffer)]]

    # Re-enable logging
    log_user 1

    # Compare outputs
    if {$output eq $expected} {
        incr passed
        send_user "[format "%-30s" $test_name] ✅\n"
    } else {
        send_user "[format "%-30s" $test_name] ❌"
        send_user [format_output_diff $expected $output]
        send_user "\n"
    }

    # Print summary
    send_user "\nSummary: $passed/$total tests passed\n"
}

# Function to test the subject cases
proc run_subject_cases {algorithm} {
    send_user "───────────────────────────────────────────────\n"
    send_user "Testing subject cases\n"
    send_user "Algorithm: $algorithm\n\n"

    # Define strings and their hashes
    set str_bar "bar"
    set hash_bar "37b51d194a7513e45b56f6524f2d51f2"
    set str_foo "foo"
    set hash_foo "acbd18db4cc2f85cedef654fccc4a4d8"

    exec echo -n $str_bar > file

    # Define test cases in an array with variable substitution
    array set test_cases {
        stdin {
            cmd {echo -n foo | ./ft_ssl %s}
            expected {(stdin)= acbd18db4cc2f85cedef654fccc4a4d8}
        }
        stdin_p {
            cmd {echo -n foo | ./ft_ssl %s -p}
            expected {("foo")= acbd18db4cc2f85cedef654fccc4a4d8}
        }
        stdin_qr {
            cmd {echo -n foo | ./ft_ssl %s -q -r}
            expected {acbd18db4cc2f85cedef654fccc4a4d8}
        }
        file {
            cmd {./ft_ssl %s file}
            expected {MD5(file)= 37b51d194a7513e45b56f6524f2d51f2}
        }
        file_r {
            cmd {./ft_ssl %s -r file}
            expected {37b51d194a7513e45b56f6524f2d51f2 *file}
        }
        s {
            cmd {./ft_ssl %s -s foo}
            expected {MD5("foo")= acbd18db4cc2f85cedef654fccc4a4d8}
        }
        stdin_file {
            cmd {echo -n foo | ./ft_ssl %s file}
            expected {MD5(file)= 37b51d194a7513e45b56f6524f2d51f2}
        }
        stdin_file_p {
            cmd {echo -n foo | ./ft_ssl %s -p file}
            expected {("foo")= acbd18db4cc2f85cedef654fccc4a4d8
MD5(file)= 37b51d194a7513e45b56f6524f2d51f2}
        }
        stdin_file_pr {
            cmd {echo -n foo | ./ft_ssl %s -p -r file}
            expected {("foo")= acbd18db4cc2f85cedef654fccc4a4d8
37b51d194a7513e45b56f6524f2d51f2 *file}
        }
        stdin_file_ps {
            cmd {echo -n foo | ./ft_ssl %s -p -s foo file}
            expected {("foo")= acbd18db4cc2f85cedef654fccc4a4d8
MD5("foo")= acbd18db4cc2f85cedef654fccc4a4d8
MD5(file)= 37b51d194a7513e45b56f6524f2d51f2}
        }
        stdin_file_rps {
            cmd {echo -n foo | ./ft_ssl %s -r -p -s foo file -s bar}
            expected {("foo")= acbd18db4cc2f85cedef654fccc4a4d8
acbd18db4cc2f85cedef654fccc4a4d8 "foo"
37b51d194a7513e45b56f6524f2d51f2 *file
ft_ssl: md5: -s: No such file or directory
ft_ssl: md5: bar: No such file or directory}
        }
        stdin_file_rpsq {
            cmd {echo -n foo | ./ft_ssl %s -r -q -p -s foo file}
            expected {("foo")= acbd18db4cc2f85cedef654fccc4a4d8
acbd18db4cc2f85cedef654fccc4a4d8
37b51d194a7513e45b56f6524f2d51f2}
        }
    }

    # Track test results
    set passed 0
    set total 0

    # Run each test case
    foreach test_name [array names test_cases] {
        array set test_case $test_cases($test_name)
        incr total
        
        # Disable logging of spawn output
        log_user 0
        
        # Format command with algorithm
        set cmd [format $test_case(cmd) $algorithm]
        set expected $test_case(expected)
        
        spawn sh -c $cmd
        expect eof
        set output [clean_output [string trim $expect_out(buffer)]]
        
        # Re-enable logging
        log_user 1
        
        # Compare outputs
        if {$output eq $expected} {
            incr passed
            send_user "[format "%-30s" $test_name] ✅\n"
        } else {
            send_user "[format "%-30s" $test_name] ❌"
            send_user [format_output_diff $expected $output]
            send_user "\n"
        }
        
        # Clean up array
        array unset test_case
    }

    # Print summary
    send_user "\nSummary: $passed/$total tests passed\n"

    # Cleanup
    file delete file
}

# Get algorithm from command line argument
if {$argc != 1} {
    send_user "Usage: expect expect.sh <algorithm>\n"
    exit 1
}
set algorithm [lindex $argv 0]

run_file_tests $algorithm $test_files
run_stdin_tests $algorithm $test_files
run_r_option_tests $algorithm $test_files
run_multiple_files_test $algorithm $test_files
run_subject_cases $algorithm

# run_test_stdin
# run_test_files
# run_test_files_many
# run_test_option_r