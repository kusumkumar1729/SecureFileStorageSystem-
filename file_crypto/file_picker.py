import tkinter as tk
from tkinter import filedialog

def select_file():
    """Opens a Tkinter file picker and returns the selected file path."""
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    file_path = filedialog.askopenfilename(title="Select a file")
    
    if file_path:
        print(file_path)  # Output the file path
    else:
        print("")  # Empty output if no file is selected

if __name__ == "__main__":
    select_file()
