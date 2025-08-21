# Import necessary libraries.
# You'll need to install the 'cryptography' and 'py7zr' libraries:
# pip install cryptography
# pip install py7zr
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import json
import py7zr
import io
import shutil

# ==============================================================================
# --- AES-256 aka A bunch of Eatable Shit (j4f) ---
# ==============================================================================

# In a real application, the key and IV would be managed securely.
# For this example, we use a fixed key and IV.
# The key must be 32 bytes for AES-256.
ENCRYPTION_KEY = os.urandom(32) 
# The IV must be 16 bytes.
ENCRYPTION_IV = os.urandom(16)

def generate_key_and_iv():
    """
    Generates a new AES-256 key and IV.
    In a production application, these would be managed securely.
    """
    return os.urandom(32), os.urandom(16)

def aes_encrypt(data, key, iv):
    """
    Encrypts data using AES-256 in CBC mode.
    The data is padded to be a multiple of the block size (16 bytes).
    """
    # Create a padder instance for PKCS7 padding.
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    # Create an encryptor object with the key and IV.
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the padded data.
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data

def aes_decrypt(encrypted_data, key, iv):
    """
    Decrypts AES-256 encrypted data.
    """
    # Create a decryptor object.
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data.
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Unpad the data.
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# ==============================================================================
# --- Main Logic for mtherfking File Operations ---
# ==============================================================================

class OpenLive2D:
    """
    A class to handle OpenLive2D file operations.
    """
    def __init__(self, key=None, iv=None):
        self.key = key if key else ENCRYPTION_KEY
        self.iv = iv if iv else ENCRYPTION_IV
        self.temp_dir = 'temp_model_data'

    def _save_to_archive(self, archive_path, file_map):
        """
        Helper to save multiple JSON files to a 7z archive.
        The file_map is a dictionary of filename -> content.
        """
        os.makedirs(self.temp_dir, exist_ok=True)
        try:
            for filename, content in file_map.items():
                with open(os.path.join(self.temp_dir, filename), 'w', encoding='utf-8') as f:
                    json.dump(content, f, indent=2)

            with py7zr.SevenZipFile(archive_path, 'w') as archive:
                archive.writeall(self.temp_dir, 'model')
            print(f"Archived all model parts to {archive_path}")
        finally:
            shutil.rmtree(self.temp_dir)
            
    def _load_from_archive(self, archive_path):
        """
        Helper to load multiple JSON files from a 7z archive.
        """
        if not os.path.exists(archive_path):
            raise FileNotFoundError(f"Archive not found: {archive_path}")

        os.makedirs(self.temp_dir, exist_ok=True)
        try:
            with py7zr.SevenZipFile(archive_path, 'r') as archive:
                archive.extractall(path=self.temp_dir)
            print(f"Extracted model parts from {archive_path}")

            # Load the main humanoid.json file
            humanoid_path = os.path.join(self.temp_dir, 'model', 'humanoid.json')
            if not os.path.exists(humanoid_path):
                raise FileNotFoundError(f"humanoid.json not found in archive.")

            with open(humanoid_path, 'r', encoding='utf-8') as f:
                humanoid_data = json.load(f)

            full_model_data = {}
            for key, filename in humanoid_data.items():
                part_path = os.path.join(self.temp_dir, 'model', filename)
                with open(part_path, 'r', encoding='utf-8') as f:
                    full_model_data[key] = json.load(f)
            
            return full_model_data
        finally:
            shutil.rmtree(self.temp_dir)

    def load_model(self, file_path):
        """
        Loads and decrypts a Live2D model based on its file extension.
        Handles both .ol2d (open-source) and .ml2d (encrypted) formats.
        """
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension not in ['.ol2d', '.ml2d']:
            print(f"Error: Unsupported file type '{file_extension}'.")
            return None

        try:
            if file_extension == '.ol2d':
                print(f"Loading open-source model: {file_path}")
                model_data = self._load_from_archive(file_path)
                print("Model loaded successfully.")
                return model_data
            
            elif file_extension == '.ml2d':
                print(f"Loading encrypted model: {file_path}")
                # Read the entire encrypted file content.
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                # Decrypt the data.
                decrypted_bytes = aes_decrypt(encrypted_data, self.key, self.iv)
                
                # Write the decrypted bytes to a temporary archive file to load from.
                temp_archive_path = f"temp_decrypted_{os.path.basename(file_path)}.7z"
                with open(temp_archive_path, 'wb') as f:
                    f.write(decrypted_bytes)
                
                model_data = self._load_from_archive(temp_archive_path)
                os.remove(temp_archive_path)
                print("Model decrypted and loaded successfully.")
                return model_data
        except FileNotFoundError:
            print(f"Error: File not found at {file_path}")
            return None
        except Exception as e:
            print(f"An error occurred while loading the model: {e}")
            return None

    def save_model(self, model_data, file_path):
        """
        Saves a Live2D model to a file, packing and encrypting it if the extension is .ml2d.
        """
        file_extension = os.path.splitext(file_path)[1].lower()
        if file_extension not in ['.ol2d', '.ml2d']:
            print(f"Error: Unsupported file type '{file_extension}'.")
            return

        # Prepare the multi-part file structure.
        humanoid_links = {
            "head": "head.json",
            "torso": "torso.json",
            "left_arm": "left_arm.json",
            "right_arm": "right_arm.json",
            "left_legs": "left_legs.json",
            "right_legs": "right_legs.json",
            "nsfw": "nsfw.json",
        }
        
        file_map = {
            "humanoid.json": humanoid_links,
            "head.json": model_data.get("head", {}),
            "torso.json": model_data.get("torso", {}),
            "left_arm.json": model_data.get("left_arm", {}),
            "right_arm.json": model_data.get("right_arm", {}),
            "left_legs.json": model_data.get("left_legs", {}),
            "right_legs.json": model_data.get("right_legs", {}),
            "nsfw.json": model_data.get("nsfw", {}),
        }

        try:
            if file_extension == '.ol2d':
                print(f"Saving as open-source model: {file_path}")
                self._save_to_archive(file_path, file_map)
                print("Model saved successfully.")
            
            elif file_extension == '.ml2d':
                print(f"Saving as encrypted model: {file_path}")
                # Create a temporary archive in memory
                temp_archive_path = f"temp_unencrypted_{os.path.basename(file_path)}.7z"
                self._save_to_archive(temp_archive_path, file_map)
                
                with open(temp_archive_path, 'rb') as f:
                    archive_bytes = f.read()
                
                # Encrypt the entire archive's bytes.
                encrypted_data = aes_encrypt(archive_bytes, self.key, self.iv)
                
                # Write the encrypted bytes to the final file.
                with open(file_path, 'wb') as f:
                    f.write(encrypted_data)

                os.remove(temp_archive_path)
                print("Model encrypted and saved successfully.")

        except Exception as e:
            print(f"An error occurred while saving the model: {e}")

# ==============================================================================
# --- Example Usage ---
# ==============================================================================

if __name__ == "__main__":
    # Create some dummy model data with the new structure.
    dummy_model_data = {
        "head": {"texture": "face.png", "parts": ["eyes", "hair"]},
        "torso": {"texture": "torso.png", "parts": ["chest", "stomach"]},
        "left_arm": {"texture": "arm.png"},
        "right_arm": {"texture": "arm.png"},
        "left_legs": {"texture": "legs.png"},
        "right_legs": {"texture": "legs.png"},
        "nsfw": {"texture": "nsfw.png", "parts": ["private_parts"]},
    }

    # Initialize the OpenLive2D handler.
    handler = OpenLive2D()

    ol2d_file = 'dummy_model.ol2d'
    ml2d_file = 'dummy_model.ml2d'

    # 1. Save the model as .ol2d.
    handler.save_model(dummy_model_data, ol2d_file)
    print("-" * 30)

    # 2. Save the same model as .ml2d (encrypted).
    handler.save_model(dummy_model_data, ml2d_file)
    print("-" * 30)
    
    # 3. Load the .ol2d model.
    loaded_ol2d_data = handler.load_model(ol2d_file)
    if loaded_ol2d_data:
        print("Loaded .ol2d model data:", loaded_ol2d_data)
    print("-" * 30)

    # 4. Load the .ml2d model.
    loaded_ml2d_data = handler.load_model(ml2d_file)
    if loaded_ml2d_data:
        print("Loaded .ml2d model data:", loaded_ml2d_data)
    print("-" * 30)

    # Clean up the generated files for demonstration.
    os.remove(ol2d_file)
    os.remove(ml2d_file)
    print("Example files have been cleaned up.")

