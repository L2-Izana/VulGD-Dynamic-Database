# Define your input and output file paths
input_file = r'datasource\ExploitNodes.csv'
output_file = r'datasource\ExploitNodes_fixed.csv'

with open(input_file, 'r', encoding='utf8') as infile, \
     open(output_file, 'w', encoding='utf8') as outfile:
    
    # Read and write the header line unchanged
    header = infile.readline()
    outfile.write(header)
    
    # Process the rest of the lines
    for line in infile:
        line = line.rstrip("\n")
        # Split into exactly 5 parts: ExploitID, Exploit_Date, Author, Exploit_Type, Platform
        parts = line.split(",", 4)
        if len(parts) != 5:
            # If the line doesn't match the expected format, log or handle it accordingly.
            print("Unexpected format:", line)
            outfile.write(line + "\n")
            continue
        
        # Ensure the Author field (third column) is enclosed in quotes
        author = parts[2]
        if not (author.startswith('"') and author.endswith('"')):
            parts[2] = f'"{author}"'
        
        fixed_line = ",".join(parts)
        outfile.write(fixed_line + "\n")

print("File has been processed and written to", output_file)
