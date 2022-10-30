if ['pwd' != '/The/Correct/Path' ]; then
    cd /The/Correct/Path/
    echo What is the file?
    read filename
    tshark -r $filename --export-objects 'http,path_1'; cd path_1; pwd # Extract the files in a PCAP and go to path_1
    for file in *; # It
    do
    if grep -q 'object' <<< '$file'; then # Pass if files have the word 'object' 
        true
    else
        shasum -a 256 $file >> '/The/Correct/Path/hashes.txt' # Get the hashes of each file that does not contain word 'object' 
    fi
    done
fi
python3 /The/Chosen/Path/pcap_hash.py #Run the Python script
pwd
rm -r '/The/Correct/Path/path_1' # Once Python script has run, remove every file recursively
