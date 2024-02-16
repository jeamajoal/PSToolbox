import argparse
import itertools

# Set up argument parser
parser = argparse.ArgumentParser(
    description='Combine lines from two files with optional prefix, separator, and postfix.',
    epilog='''Usage Examples:

    Basic Usage Without Optional Parameters:
    python combine_lines.py File1.txt File2.txt

    Using a Separator:
    python combine_lines.py File1.txt File2.txt -s ","
    python combine_lines.py File1.txt File2.txt --separator ","

    Adding Prefix and Postfix:
    python combine_lines.py File1.txt File2.txt -p "Start-" -x "-End"
    python combine_lines.py File1.txt File2.txt --prefix "Start-" --postfix "-End"

    Combining All Options:
    python combine_lines.py File1.txt File2.txt -s ";" -p "Start-" -x "-End"
    ''',
    formatter_class=argparse.RawDescriptionHelpFormatter
)

parser.add_argument('file1', help='First input file')
parser.add_argument('file2', help='Second input file')
parser.add_argument('-s', '--separator', help='String to separate lines from File1 and File2', default='')
parser.add_argument('-p', '--prefix', help='String to add before each combined line', default='')
parser.add_argument('-x', '--postfix', help='String to add after each combined line', default='')

# Parse arguments
args = parser.parse_args()

lists = []

# Reading File1
with open(args.file1) as fp:
    words = [line.rstrip() for line in fp]
    lists.append(words)

# Reading File2
with open(args.file2) as fp:
    words = [line.rstrip() for line in fp]
    lists.append(words)

# Combining lines from both files with the separator, prefix, and postfix
for element in itertools.product(*lists):
    print(f"{args.prefix}{args.separator.join(element)}{args.postfix}")

