import os
import pwd

# Prefixes to ignore
ignore_prefixes = ['sudo', 'proxychains']

# Function to process a single line of history
def process_command(command):
    words = command.strip().split()
    # Remove ignored prefixes
    while words and words[0] in ignore_prefixes:
        words.pop(0)
    
    if not words:
        return None  # No valid command after removing prefixes

    cmd = words[0]
    params = words[1:]
    # Further processing can be done here, like sorting parameters, etc.
    return cmd, params

# Function to process history files for all users
def process_all_user_histories():
    commands = {}
    # Read all users from /etc/passwd
    users = pwd.getpwall()
    for user in users:
        # Construct the path to the user's home directory
        home_dir = user.pw_dir
        history_paths = [f'{home_dir}/.bash_history', f'{home_dir}/.zsh_history']
        # Process each history file for the user
        for path in history_paths:
            try:
                with open(path, 'r') as file:
                    for line in file:
                        result = process_command(line)
                        if result:
                            cmd, params = result
                            if cmd not in commands:
                                commands[cmd] = []
                            commands[cmd].append(params)
            except IOError:
                # Could not read file, might not exist or lack permissions
                pass

    # Further processing to sort and organize
    # ...

    return commands

# Function to print the organized commands
def print_organized_commands(commands):
    for cmd in sorted(commands.keys()):  # Sort the commands alphabetically
        params_list = commands[cmd]
        for params in params_list:
            # Join parameters into a string
            params_str = ' '.join(params)
            print(f"{cmd} {params_str}")

# Run the processing for all users
organized_commands = process_all_user_histories()

# Print the organized list to stdout
print_organized_commands(organized_commands)
