# build from scratch
import sys, os, shutil, tempfile, traceback, json, subprocess
from direct.showbase import ShowBase
from direct.task import Task
from direct.gui.DirectGui import DirectButton, DirectLabel
from direct.showbase.PythonUtil import Functor
from direct.showbase import PythonUtil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Union

class AES256:
    def __init__(self, key: bytes, iv: bytes):
        self.key = key
        self.iv = iv

    def encrypt(self, plaintext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        return unpadder.update(padded_data) + unpadder.finalize()

class FileHandler:
    def __init__(self, key: bytes = None, iv: bytes = None, *args, **kwargs):
        if key is None:
            self.key = os.urandom(32)  # AES-256 key
        else:
            self.key = key
        if iv is None:
            self.iv = os.urandom(16)   # AES block size is 16
        else:
            self.iv = iv
        self.aes = AES256(self.key, self.iv)

    def model_json_generator(self, filename: str, color: str = '#FFFFFF', size: Union[int, float] = 1.0, width: Union[int, float] = 1.0, height: Union[int, float] = 2.0) -> dict:
        """
        Generates the structure for a model.json file.

        Args:
            filename (str): Base name for the model. Not used in this implementation
                            but kept for signature consistency.
            color (str): Hex color string for the humanoid.
            size (int): Overall size of the humanoid.
            width (int): Width of the humanoid.
            height (int): Height of the humanoid.

        Returns:
            dict: A dictionary representing the model structure.
        """
        model_structure = {
            "humanoid": {
                "color": color,
                "size": float(size),
                "width": float(width),
                "height": float(height)
            },
            "head": "head.json",
            "torso": "torso.json",
            "left_arm": "left_arm.json",
            "right_arm": "right_arm.json",
            "left_leg": "left_leg.json",
            "right_leg": "right_leg.json",
            "nsfw": "nsfw.json",
            "animations": {
                "idle": "idle.json",
                "walk": "walk.json",
                "run": "run.json",
                "jump": "jump.json",
                "attack": "attack.json"
            }
        }
        return model_structure

    def part_json_generator(self, part_name: str) -> dict:
        """
        Generates the structure for a model part JSON file (e.g., head.json).

        Args:
            part_name (str): The name of the part (e.g., 'head', 'torso').

        Returns:
            dict: A dictionary representing the part structure.
        """
        part_structure = {
            "kra_file": f"{part_name}.kra",
            "logo": f"{part_name}.png",
            "animations": {
                "turn_left": "turn_left.json",
                "turn_right": "turn_right.json",
                "turn_up": "turn_up.json",
                "turn_down": "turn_down.json"
            }
        }
        return part_structure

    def animation_json_generator(self, duration: float = 5.0, fps: float = 30.0, loop: bool = True, curves: list = None, user_data: list = None) -> dict:
        """
        Generates the structure for a Live2D animation file (motion3.json).

        Args:
            duration (float): Duration of the animation in seconds.
            fps (float): Frames per second.
            loop (bool): Whether the animation should loop.
            curves (list, optional): A list of curve dictionaries. Defaults to None.
            user_data (list, optional): A list of user data dictionaries. Defaults to None.

        Returns:
            dict: A dictionary representing the animation data.
        """
        if curves is None:
            curves = []
        if user_data is None:
            user_data = []

        total_segment_count = 0
        total_point_count = 0
        for curve in curves:
            segments = curve.get("Segments", [])
            num_values = len(segments)
            if num_values > 0:
                total_point_count += 1  # Initial point
                i = 2
                while i < num_values:
                    total_segment_count += 1
                    segment_type = segments[i]
                    i += 1
                    if segment_type == 1:  # Bezier
                        i += 6
                        total_point_count += 3
                    else:  # Linear, Stepped, Inverse Stepped
                        i += 2
                        total_point_count += 1

        total_user_data_size = 0
        for data in user_data:
            total_user_data_size += len(data.get("Value", ""))

        animation_structure = {
            "Version": 3,
            "Meta": {
                "Duration": float(duration),
                "Fps": float(fps),
                "Loop": loop,
                "AreBeziersRestricted": True,
                "CurveCount": len(curves),
                "TotalSegmentCount": total_segment_count,
                "TotalPointCount": total_point_count,
                "UserDataCount": len(user_data),
                "TotalUserDataSize": total_user_data_size
            },
            "Curves": curves,
            "UserData": user_data
        }
        return animation_structure

    def convert_psd_to_kra(self, psd_path: str, kra_path: str = None):
        """
        Converts a .psd file to a .kra file using Krita's command-line interface.
        This requires Krita to be installed and accessible in the system's PATH.

        Args:
            psd_path (str): The path to the input Photoshop (.psd) file.
            kra_path (str, optional): The path for the output Krita (.kra) file.
                                      If None, it will be the same as the psd_path but with a .kra extension.
        """
        if not shutil.which("krita"):
            print("\nWarning: 'krita' executable not found in PATH. Cannot convert .psd file.")
            print("         Please install Krita and ensure its command-line tools are in your system's PATH.\n")
            return

        if not os.path.exists(psd_path):
            print(f"Error: Input file not found at '{psd_path}'")
            return

        if kra_path is None:
            kra_path = os.path.splitext(psd_path)[0] + ".kra"

        print(f"Converting '{psd_path}' to '{kra_path}' using Krita...")
        try:
            # Krita's command line for conversion
            command = [
                "krita",
                psd_path,
                "--export",
                "--export-filename",
                kra_path
            ]
            # On some systems, Krita might need to run in the background and without a GUI
            if sys.platform != "win32":
                command.insert(1, "--no-gui")

            # Using subprocess.run for simplicity and better error handling
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)

            print(f"Successfully converted to {kra_path}")
            if result.stdout:
                print(f"Krita output:\n{result.stdout}")

        except FileNotFoundError:
            print("\nError: 'krita' command not found. Is Krita installed and in your PATH?")
        except subprocess.CalledProcessError as e:
            print(f"An error occurred while running Krita (return code {e.returncode}):")
            print(f"Command: {' '.join(e.cmd)}")
            print(f"STDOUT:\n{e.stdout}")
            print(f"STDERR:\n{e.stderr}")
        except subprocess.TimeoutExpired:
            print("Krita conversion timed out. The process may be stuck.")
        except Exception as e:
            print(f"An unexpected error occurred during PSD to KRA conversion: {e}")

    def create_part_from_kra(self, part_name: str, kra_path: str, logo_layer_name: str = "logo"):
        """
        Generates a part JSON file and efficiently extracts a logo from the corresponding .kra file.

        Args:
            part_name (str): The name of the part (e.g., 'head').
            kra_path (str): The path to the Krita (.kra) file.
            logo_layer_name (str, optional): The name of the layer to extract as the logo. Defaults to "logo".
        """
        # Generate the part JSON structure and save it
        part_structure = self.part_json_generator(part_name)
        part_json_path = os.path.join(f"{part_name}.json")
        with open(part_json_path, 'w') as f:
            json.dump(part_structure, f, indent=2)
        print(f"Successfully created part definition: {part_json_path}")

        # Extract the logo from the .kra file using kritapy
        try:
            from kritapy import Krita

            print(f"Opening Krita file: {kra_path}")
            kra_file = Krita(kra_path)
            logo_layer = kra_file.get_layer_by_name(logo_layer_name)

            if logo_layer:
                print(f"Found layer '{logo_layer_name}', extracting as logo...")
                pillow_image = logo_layer.get_image()
                logo_path = part_structure["logo"]
                pillow_image.save(logo_path)
                print(f"Successfully extracted logo to {logo_path}")
            else:
                print(f"Warning: Layer '{logo_layer_name}' not found in {kra_path}. Logo not extracted.")

        except ImportError:
            print("\nWarning: 'kritapy' and 'Pillow' are required for Krita file processing. Skipping logo extraction.")
            print("         Install with: pip install kritapy Pillow\n")
        except FileNotFoundError:
            print(f"Warning: Krita file not found at '{kra_path}'. Logo not extracted.")
        except Exception as e:
            print(f"An error occurred during logo extraction from {kra_path}: {e}")

    def convert_live2d_animation_to_json(self, json_path: str) -> dict | None:
        """
        Loads a Live2D animation file (.motion3.json) and returns it as a
        dictionary, ensuring metadata counts are correct.

        This is useful for loading an animation file, potentially modifying it,
        and then resaving it with consistent metadata.

        Args:
            json_path (str): The path to the animation JSON file.

        Returns:
            A dictionary representing the full animation structure, or None if an error occurs.
        """
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            meta = data.get("Meta")
            curves = data.get("Curves")
            user_data = data.get("UserData")  # Can be None

            if meta is None or curves is None:
                print(f"Error: Invalid .motion3.json format in '{json_path}'. Missing 'Meta' or 'Curves' key.")
                return None

            print(f"Successfully loaded and parsed animation from {json_path}")

            # Reconstruct the full animation dictionary using the generator to ensure
            # all counts in the metadata are correct.
            animation_data = self.animation_json_generator(
                duration=meta.get("Duration", 0.0),
                fps=meta.get("Fps", 30.0),
                loop=meta.get("Loop", False),
                curves=curves,
                user_data=user_data
            )
            return animation_data
        except FileNotFoundError:
            print(f"Error: Animation file not found at '{json_path}'")
            return None
        except json.JSONDecodeError as e:
            print(f"Error: Failed to parse JSON from '{json_path}': {e}")
            return None
        except Exception as e:
            print(f"An unexpected error occurred while loading {json_path}: {e}")
            return None

    def load_live2d_animation(self, json_path: str) -> tuple[dict | None, list | None]:
        """
        Loads and parses a Live2D animation file (.motion3.json).
        This allows for reading existing animations, modifying their data,
        and then using animation_json_generator to save a new version.

        Args:
            json_path (str): The path to the animation JSON file.

        Returns:
            A tuple containing (meta_data, curves_data) or (None, None) if an error occurs.
        """
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            meta = data.get("Meta")
            curves = data.get("Curves")

            if meta is None or curves is None:
                print(f"Error: Invalid .motion3.json format in '{json_path}'. Missing 'Meta' or 'Curves' key.")
                return None, None

            print(f"Successfully loaded and parsed animation from {json_path}")
            return meta, curves
        except FileNotFoundError:
            print(f"Error: Animation file not found at '{json_path}'")
            return None, None
        except json.JSONDecodeError as e:
            print(f"Error: Failed to parse JSON from '{json_path}': {e}")
            return None, None
        except Exception as e:
            print(f"An unexpected error occurred while loading {json_path}: {e}")
            return None, None

    def save_file(self, filename: str, data: bytes) -> None:
        """
        Saves data to a file, encrypting it if the extension is .ml2d.

        Args:
            filename (str): The name of the file to save.
            data (bytes): The data to write to the file.
        """
        _root, ext = os.path.splitext(filename)

        try:
            if os.path.dirname(filename):
                os.makedirs(os.path.dirname(filename), exist_ok=True)

            if ext == '.ml2d':
                encrypted_data = self.aes.encrypt(data)
                with open(filename, 'wb') as f:
                    f.write(encrypted_data)
                print(f"Successfully saved encrypted file: {filename}")
            else:
                with open(filename, 'wb') as f:
                    f.write(data)
                if ext == '.ol2d':
                    print(f"Successfully saved file: {filename}")
                elif ext == '.json':
                    print(f"Successfully saved JSON file: {filename}")
                else:
                    print(f"Successfully saved file: {filename}")
        except IOError as e:
            print(f"Error saving file {filename}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while saving {filename}: {e}")

def _example():
    # Example Usage
    handler = FileHandler()

    # 1. Create model.json and other definition files
    model_dir = "model.json"
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
    print(f"Created output directory: {model_dir}")

    model_structure = handler.model_json_generator(filename="model")
    model_json_path = os.path.join(model_dir, "model.json")
    print(f"Generating model structure in '{model_json_path}'...")
    with open(model_json_path, 'w') as f:
        json.dump(model_structure, f, indent=2)
    print(f"Successfully created model definition: {model_json_path}")

    # 2. Save dummy model data
    dummy_data = b"This is some model data that will be saved."
    handler.save_file("model.ol2d", dummy_data)
    handler.save_file("model.ml2d", dummy_data)

    # 3. Decrypt and verify
    print(f"Loading Live2D model from: model.ol2d")
    with open("model.ol2d", "rb") as f:
        ol2d_data = f.read()
        assert ol2d_data == dummy_data

    print(f"Decrypting and loading Live2D model from: model.ml2d")
    try:
        with open("model.ml2d", "rb") as f:
            encrypted_data = f.read()
        decrypted_data = handler.aes.decrypt(encrypted_data)
        assert decrypted_data == dummy_data
        print("Decryption successful!")
    except Exception as e:
        print(f"Decryption failed: {e}")
        traceback.print_exc()

    # 4. Create part definitions and extract assets from KRA files
    #    (This is a demonstration and requires a dummy .kra file to exist)
    print("\n--- Generating Part Assets ---")
    # Note: For this to work, you would need Krita files (e.g. 'head.kra')
    # with a layer named 'logo'. Since we can't create one here, this will
    # likely show a FileNotFoundError or an ImportError if kra-py is not installed.
    parts_to_generate = ["head", "torso"]
    for part in parts_to_generate:
        # The KRA file should be in the same directory or you should provide a full path.
        kra_file_path = f"{part}.kra"
        handler.create_part_from_kra(part, kra_file_path)

    # 5. Convert a dummy PSD to KRA
    print("\n--- Converting PSD to KRA ---")
    # Create a dummy PSD file for demonstration since we can't create a real one
    dummy_psd_path = "dummy.psd"
    if not os.path.exists(dummy_psd_path):
        with open(dummy_psd_path, "w") as f:
            f.write("This is not a real PSD file.")
    handler.convert_psd_to_kra(dummy_psd_path)

    # 6. Convert a Live2D animation, modify its curves, and save it back
    print("\n--- Converting, Modifying, and Resaving Animation ---")
    # First, create a sample animation to load
    sample_curves = [{
        "Target": "Parameter", "Id": "ParamAngleX",
        "Segments": [0, -30, 1, 1, -30, 2, 30, 3, 30]
    }]
    sample_anim_data = handler.animation_json_generator(duration=3.0, loop=True, curves=sample_curves)
    sample_anim_path = "sample_anim.motion3.json"
    handler.save_file(sample_anim_path, json.dumps(sample_anim_data, indent=2).encode('utf-8'))

    # Now, convert the animation to a normalized JSON dictionary
    loaded_anim = handler.convert_live2d_animation_to_json(sample_anim_path)
    if loaded_anim:
        print("Loaded animation with duration:", loaded_anim["Meta"]["Duration"])
        # Example modification: Add a new curve
        new_curve = {"Target": "Parameter", "Id": "ParamEyeLOpen", "Segments": [0, 1, 0, 3, 0]}
        loaded_anim["Curves"].append(new_curve)
        # Re-generate the animation data to update the counts in Meta
        modified_anim_data = handler.animation_json_generator(
            duration=loaded_anim["Meta"]["Duration"],
            fps=loaded_anim["Meta"]["Fps"],
            loop=loaded_anim["Meta"]["Loop"],
            curves=loaded_anim["Curves"],
            user_data=loaded_anim.get("UserData")
        )
        # Save it as a new file
        modified_anim_path = "modified_anim.motion3.json"
        handler.save_file(modified_anim_path, json.dumps(modified_anim_data, indent=2).encode('utf-8'))

if __name__ == '__main__':
    _example()