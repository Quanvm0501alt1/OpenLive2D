from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import json
import py7zr
import io
import shutil
from direct.showbase.ShowBase import ShowBase
import os
class FileHandler:
    """
    Handles file operations for OpenLive2D models, including decryption and unzipping.
    """
    
    def __init__(self):
        self.key = os.urandom(32)  # Generate a random key for AES encryption
        self.iv = os.urandom(16)   # Generate a random IV for AES encryption
    
    def encrypt_file(self, file_path):
        """
        Encrypts a .ml2d file using AES encryption.
        """
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

    def decrypt_file(self, file_path):
        """
        Decrypts a .ml2d file using AES encryption.
        """
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
        
        return decrypted_data

    def unzip_file(self, file_path):
        """
        Unzips a .ol2d or .ml2d file and returns the contents.
        """
        with py7zr.SevenZipFile(file_path, mode='r') as archive:
            archive.extractall(path=os.path.dirname(file_path))
        
        return os.path.dirname(file_path)
    def zip_file(self, directory, output_path):
        """
        Zips the contents of a directory into a .ol2d file.
        """
        with py7zr.SevenZipFile(output_path, mode='w') as archive:
            archive.writeall(directory, arcname=os.path.basename(directory))
    def generate_model_from_pictures(self, parts_map, output_dir="."):
        """
        Generates a Live2D model structure from a dictionary of parts and pictures.

        This function creates a main `model.json` file that references individual
        JSON files for each part. Each part's JSON file contains properties
        like texture path, position, scale, etc.

        :param parts_map: A dictionary mapping part names to their picture paths.
                          e.g., {'head': 'path/to/head.png', 'torso': 'path/to/torso.png'}
        :param output_dir: The directory where the model files will be saved.
                           Defaults to the current directory.
        :return: The path to the generated model.json file, or None on failure.
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"Created output directory: {output_dir}")

        model_definition = {}
        print(f"Generating model structure in '{output_dir}'...")

        for part_name, picture_path in parts_map.items():
            # Create data for the individual part JSON with placeholder properties
            part_data = {
                "texture": os.path.abspath(picture_path),
                "position": [0.0, 0.0, 0.0],
                "rotation": [0.0, 0.0, 0.0],
                "scale": [1.0, 1.0, 1.0],
                "anchor": [0.5, 0.5],
                "opacity": 1.0,
            }

            # Define and write the part's JSON file
            part_json_filename = f"{part_name}.json"
            part_json_path = os.path.join(output_dir, part_json_filename)
            with open(part_json_path, 'w') as f:
                json.dump(part_data, f, indent=4)

            # Add the part reference to the main model definition
            model_definition[part_name] = part_json_filename

        # Define and write the main model.json file
        model_json_path = os.path.join(output_dir, "model.json")
        with open(model_json_path, 'w') as f:
            json.dump(model_definition, f, indent=4)
        print(f"Successfully created model definition: {model_json_path}")
        return model_json_path

    def load_live2d_model(self, file_path):
        """
        Loads a Live2D model from a file, handling decryption and unzipping if necessary.
        """
        if file_path.endswith('.ol2d'):
            print(f"Loading Live2D model from: {file_path}")
            return self.unzip_file(file_path)
        elif file_path.endswith('.ml2d'):
            print(f"Decrypting and loading Live2D model from: {file_path}")
            try:
                decrypted_data = self.decrypt_file(file_path)
                with open('decrypted_model.json', 'wb') as f:
                    f.write(decrypted_data)
                return json.loads(decrypted_data.decode('utf-8'))
            except Exception as e:
                print(f"Decryption failed: {e}")
                return None
        elif file_path.endswith('.json'):
            print(f"Loading JSON model data from: {file_path}")
            try:
                with open(file_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Failed to load JSON model data: {e}")
                return None
        else:
            print(f"Unsupported file type: {file_path}")
            return None

class OpenLive2D(ShowBase):
    """
    The main class for handling OpenLive2D operations.
    """
    
    def __init__(self):
        ShowBase.__init__(self)
        self.file_handler = FileHandler()

        # Example usage:
        # self.load_live2d_model('path/to/your/model.ol2d')