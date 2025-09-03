import os
import subprocess
import shutil
import re

def start():
    try:
        # Define PBS directory paths
        pbs_dir_path = os.getcwd()
        bundle_file_dir = os.path.join(pbs_dir_path, "bundle_file")
        transport_key_dir = os.path.join(pbs_dir_path, "transport_key")

        # Check if required directories exist
        if not os.path.exists(bundle_file_dir) or not os.path.exists(transport_key_dir):
            print("Error: Required directories are missing. Please create required bundle_file directory and transport_key directory first.")
            return False 

        default_pbs_value = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40"

        chipID = str(OnChipID())
        print(f"Chip ID: {chipID}")

        return process_pbs_keys(None, chipID, default_pbs_value)

    except Exception as e:
        print(f"\nError creating or writing to PBS file: {str(e)}")
        return False
        
def OnTransKey(key_file_path):
    try:
        with open(key_file_path, 'r') as keys_file:
            for line in keys_file:
                if "Transport key value" in line:
                    return line.split(":")[1].strip()  # Extract transport key value
                else:
                    raise ValueError("Transport key value not found in keys file.")
    except Exception as e:
        raise RuntimeError(f"Error reading transport key: {e}")
        
def process_pbs_keys(extract_dir, chipID, default_pbs_value):
    """ Process PBS keys by extracting them using a transport key. """
    try:
        bundle_file_dir = os.path.join(os.getcwd(), "bundle_file")
        zip_files = [f for f in os.listdir(bundle_file_dir) if f.endswith(".7z")]
        if len(zip_files) != 1:
            print(f"Warning: Expected exactly 1 .7z file in {bundle_file_dir}, but found {len(zip_files)}.")
            write_pbs_file_with_default_value(default_pbs_value)
            return False

        zip_file_path = os.path.join(bundle_file_dir, zip_files[0])
        extract_dir = os.path.join(bundle_file_dir, os.path.splitext(zip_files[0])[0])

        if not os.path.exists(extract_dir) or not os.listdir(extract_dir):
            os.makedirs(extract_dir, exist_ok=True)
            command_output = subprocess.run(
                ["7z", "x", zip_file_path, f"-o{extract_dir}"],
                capture_output=True,
                text=True
            )
            if command_output.returncode != 0:
                print(f"Error extracting {zip_files[0]}: {command_output.stderr}")
                write_pbs_file_with_default_value(default_pbs_value)
                return False
            print(f"Extracted {zip_files[0]} to {extract_dir}")
        else:
            print(f"Skipping extraction: {extract_dir} already exists and is not empty.")

        transport_key_dir = os.path.join(os.getcwd(), "transport_key")
        transport_key_files = [f for f in os.listdir(transport_key_dir) if f.endswith(".txt")]
        if len(transport_key_files) != 1:
            print(f"Error: Expected exactly 1 transport key file in {transport_key_dir}, but found {len(transport_key_files)}.")
            write_pbs_file_with_default_value(default_pbs_value)
            return False
        transport_key_path = os.path.join(transport_key_dir, transport_key_files[0])
        if not os.path.exists(transport_key_path):
            print(f"Error: Transport key file {transport_key_path} not found.")
            write_pbs_file_with_default_value(default_pbs_value)
            return False

        transport_key = OnTransKey(transport_key_path)
        print(f"Transport Key for Chip ID {chipID}: {transport_key}")
        
        auto_keys_path = os.path.join(extract_dir, "auto_keys.txt")
        pbs_keys_path = os.path.join(extract_dir, "PBS_keys.txt")
        
        if os.path.exists(auto_keys_path) and os.path.exists(pbs_keys_path):
            print(f"Keys already extracted. Skipping extraction.")
        else:
            keys_archive_path = os.path.join(extract_dir, f"{chipID}_keys.7z")
            if not os.path.exists(keys_archive_path):
                print(f"Error: Keys archive {keys_archive_path} not found.")
                write_pbs_file_with_default_value(default_pbs_value)
                return False

            command_output = subprocess.run(
                ["7z", "x", keys_archive_path, f"-o{extract_dir}", f"-p{transport_key}"],
                capture_output=True,
                text=True
            )
            if command_output.returncode != 0:
                print(f"Error extracting keys archive {keys_archive_path} using transport key: {command_output.stderr}")
                write_pbs_file_with_default_value(default_pbs_value)
                return False

            print(f"Extracted keys from {keys_archive_path} using transport key.")

        if not os.path.exists(pbs_keys_path):
            print(f"Error: PBS_keys.txt not found in {extract_dir}. Using default PBS value.")
            extracted_pbs_value = None
        else:
            extracted_pbs_value = OnExtractChipSpecificKey(pbs_keys_path)

        pbs_value = extracted_pbs_value if extracted_pbs_value else default_pbs_value
        print(f"Chip ID = {chipID}. PBS value: {pbs_value}")

        pbs_file_path = os.path.join(os.getcwd(), "pbsfile.txt")
        with open(pbs_file_path, 'w') as f:
            f.write(pbs_value)
        print(f"PBS file updated with value: {pbs_value}")

        return True

    except Exception as e:
        print(f"\nError processing PBS keys: {str(e)}")
        write_pbs_file_with_default_value(default_pbs_value)
        return False

def OnExtractChipSpecificKey(filename):
    try:
        chipID = str(OnChipID())

        with open(filename, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) == 2 and parts[0] == chipID:
                    return parts[1].strip()

        print(f"Error: Chip ID {chipID} not found in {filename}.")
        return None
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
        return None
        
def write_pbs_file_with_default_value(default_pbs_value):
    """ Helper function to write the default PBS value to pbsfile.txt """
    pbs_file_path = os.path.join(os.getcwd(), "pbsfile.txt")
    with open(pbs_file_path, 'w') as f:
        f.write(default_pbs_value)
    print(f"PBS value set to default value.")

def OnChipID():
    parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    chipinfo_path = os.path.join(parent_dir, "bin", "trustm_chipinfo")
    result = subprocess.run([chipinfo_path], 
                            capture_output=True, 
                            text=True)
    
    output = result.stdout
    batch_match = re.search(r'Batch Number.*?: ((?:0x[0-9a-fA-F]{2}\s*){6})', output)
    x_coord_match = re.search(r'X-coordinate.*?: 0x([0-9a-fA-F]{4})', output)
    y_coord_match = re.search(r'Y-coordinate.*?: 0x([0-9a-fA-F]{4})', output)
    
    if not all([batch_match, x_coord_match, y_coord_match]):
        raise ValueError("Could not extract all required values from CLI output")
    
    batch_hex = batch_match.group(1).replace('0x', '').replace(' ', '').strip()
    x_coord = x_coord_match.group(1)
    y_coord = y_coord_match.group(1)

    return f"{batch_hex}{x_coord}{y_coord}".upper()

start()
