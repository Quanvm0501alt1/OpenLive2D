# ==============================================================================
# --- Panda3D Dummy Model Renderer ---
# This script creates a basic desktop application to render a dummy model
# based on the multi-file JSON structure.
#
# To run this, you must have Panda3D installed:
# pip install panda3d
# ==============================================================================
import os
import json
from direct.showbase.ShowBase import ShowBase
from panda3d.core import NodePath, CardMaker, TransparencyAttrib, TextNode
from direct.gui.DirectGui import *
from direct.task import Task
from io import BytesIO
import zipfile
import py7zr

# --- Constants for Rendering ---
# Mapping of part names to their colors for visualization.
PART_COLORS = {
    "head": (179/255, 229/255, 252/255, 1),      # Light blue
    "torso": (200/255, 230/255, 201/255, 1),     # Light green
    "left_arm": (255/255, 236/255, 179/255, 1),  # Light yellow
    "right_arm": (255/255, 205/255, 210/255, 1), # Light pink
    "left_legs": (225/255, 190/255, 231/255, 1), # Light purple
    "right_legs": (178/255, 235/255, 242/255, 1), # Light cyan
    "nsfw": (248/255, 187/255, 208/255, 1),     # Lighter pink
}

# --- Placeholder Functions ---
# In a real application, you would handle decryption and file extraction here.
# For this example, we assume success and return dummy data.
def decrypt_and_unzip_ml2d(file_path):
    """
    Simulates the decryption and decompression of a .ml2d file.
    In a real app, this would use the `cryptography` and `py7zr` libraries.
    """
    print(f"Simulating decryption of {file_path}...")
    # This is dummy data that a successful decryption and decompression would yield.
    # The actual data would be loaded from the unzipped files.
    dummy_model_data = {
        "humanoid": {
            "head": "head.json",
            "torso": "torso.json",
            "left_arm": "left_arm.json",
            "right_arm": "right_arm.json",
            "left_legs": "left_legs.json",
            "right_legs": "right_legs.json",
            "nsfw": "nsfw.json",
        },
        "parts": {
            "head": {"type": "head"},
            "torso": {"type": "torso"},
            "left_arm": {"type": "left_arm"},
            "right_arm": {"type": "right_arm"},
            "left_legs": {"type": "left_legs"},
            "right_legs": {"type": "right_legs"},
            "nsfw": {"type": "nsfw"},
        }
    }
    return dummy_model_data

def unzip_ol2d(file_path):
    """
    Unzips an .ol2d file and loads the model data from its parts.
    """
    print(f"Unzipping and loading {file_path}...")
    try:
        # Use a temporary directory for extraction.
        temp_dir = 'temp_ol2d_extract'
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
        
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        # Load the main humanoid.json file
        humanoid_path = os.path.join(temp_dir, 'model', 'humanoid.json')
        if not os.path.exists(humanoid_path):
            raise FileNotFoundError("humanoid.json not found in archive.")

        with open(humanoid_path, 'r') as f:
            humanoid_data = json.load(f)

        # Load each part
        parts_data = {}
        for key, filename in humanoid_data.items():
            part_path = os.path.join(temp_dir, 'model', filename)
            with open(part_path, 'r') as f:
                parts_data[key] = json.load(f)

        return {"humanoid": humanoid_data, "parts": parts_data}
    finally:
        # Clean up the temporary directory
        if os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir)


# ==============================================================================
# --- Panda3D Application Class ---
# ==============================================================================
class ModelRenderer(ShowBase):
    """
    The main application class for our renderer.
    """
    def __init__(self):
        ShowBase.__init__(self)

        # Disable the default camera control.
        self.disableMouse()
        
        # Set up a 2D camera for our scene.
        # This is the standard way to set up a 2D viewport in Panda3D.
        self.camera.setPos(0, -20, 0)
        
        # Main container for the model parts.
        self.model_root = NodePath("model_root")
        self.model_root.reparentTo(self.render)
        
        self.model_info_text = None

        # Create a GUI for file selection.
        self.create_gui()
        
    def create_gui(self):
        """
        Creates the UI elements for the application.
        """
        self.status_label = OnscreenText(
            text="Please select a model file (.ol2d or .ml2d).",
            pos=(0, 0.9),
            scale=0.07,
            fg=(1, 1, 1, 1),
            bg=(0, 0, 0, 0.5),
            align=TextNode.ACenter,
            mayChange=True
        )

        self.file_button = DirectButton(
            text=("Select File", "Loading...", "Select File", "disabled"),
            scale=0.1,
            pos=(-0.7, 0, -0.8),
            command=self.open_file_dialog
        )
        
    def open_file_dialog(self):
        """
        Opens a native file dialog for the user to select a model file.
        """
        from tkinter import Tk, filedialog
        root = Tk()
        root.withdraw()
        
        # Open a file dialog to get the path
        file_path = filedialog.askopenfilename(
            filetypes=[("Live2D Models", "*.ol2d *.ml2d")]
        )
        
        root.destroy()
        
        if file_path:
            self.load_model(file_path)

    def load_model(self, file_path):
        """
        Loads the selected model file and triggers rendering.
        """
        self.file_button['state'] = DGG.DISABLED
        self.status_label.setText("Loading model...")
        
        file_extension = os.path.splitext(file_path)[1].lower()
        
        try:
            if file_extension == '.ol2d':
                model_data = unzip_ol2d(file_path)
            elif file_extension == '.ml2d':
                model_data = decrypt_and_unzip_ml2d(file_path)
            else:
                self.status_label.setText("Error: Unsupported file type.")
                self.file_button['state'] = DGG.NORMAL
                return
            
            self.render_model(model_data)
            self.status_label.setText(f"Successfully loaded {os.path.basename(file_path)}!")
        except Exception as e:
            self.status_label.setText(f"Error loading model: {e}")
            print(f"Error: {e}")
        finally:
            self.file_button['state'] = DGG.NORMAL

    def render_model(self, model_data):
        """
        Clears the old model and renders the new one on the scene.
        """
        # Remove any previously rendered model.
        self.model_root.getChildren().detach()

        # Create a CardMaker to create textured quads for our parts.
        cm = CardMaker('model_part')
        
        # Positions for each part relative to the model root.
        positions = {
            'head': (0, 0, 1.5),
            'torso': (0, 0, 0),
            'left_arm': (-1, 0, 0),
            'right_arm': (1, 0, 0),
            'left_legs': (-0.5, 0, -1.5),
            'right_legs': (0.5, 0, -1.5),
            'nsfw': (0, 0, -0.5),
        }
        
        # Render each part.
        for part_key, part_info in model_data['parts'].items():
            if part_key in positions:
                cm.setFrame(-0.5, 0.5, -0.5, 0.5)
                part_node = NodePath(cm.generate())
                part_node.reparentTo(self.model_root)
                part_node.setPos(positions[part_key])
                
                # Apply a solid color and make it a little transparent.
                color = PART_COLORS.get(part_key, (0.5, 0.5, 0.5, 1))
                part_node.setColor(color)
                part_node.setTransparency(TransparencyAttrib.MAlpha)
                
                # Add a label to the part.
                label = OnscreenText(
                    text=part_key.replace('_', ' ').title(),
                    pos=(positions[part_key][0], positions[part_key][2]),
                    scale=0.1,
                    fg=(0, 0, 0, 1),
                    align=TextNode.ACenter,
                    mayChange=True
                )
                label.reparentTo(self.model_root)

# ==============================================================================
# --- Main Application Loop ---
# ==============================================================================
if __name__ == "__main__":
    app = ModelRenderer()
    app.run()
