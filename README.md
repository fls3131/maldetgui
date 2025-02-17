<h1>Maldet Scanner GUI Version 1.0</h1> Developed by Fabio Schmit
<h2>Contact: hostmaster@bithostel.com.br</h2>
<h2>Website: https://bithostel.com.br</h2>
<h1></h1>This tool provides a graphical interface for Maldet, allowing users to scan directories easily.</h1>
<img src="https://github.com/fls3131/maldetgui/blob/main/mainwindow.png"/>




Python Version

- Ensure you have Python 3.x installed (preferably 3.6 or higher) as tkinter support may vary.

Dependencies

The main dependencies for this script are standard libraries that come with Python, so you may not need to install extra packages. Here are the specific libraries and modules used:

1. tkinter: This is the standard GUI toolkit for Python. It is included with most Python installations.

- Submodules being used:

- tkinter.scrolledtext

- tkinter.filedialog

- tkinter.simpledialog

- tkinter.ttk

- tkinter.Menu

2. subprocess: This module is part of the Python standard library and is used to spawn new processes, connect to their input/output/error pipes, and obtain their return codes.

3. threading: This module is also part of the Python standard library and is used to create and manage threads.

4. queue: A standard library module that provides a thread-safe queue.

5. os: A standard library module that provides functions for interacting with the operating system.

6. signal: A standard library module that allows your program to handle signals received from the operating system (used here to stop processes).

Additional Tools

- Maldet: This script seems to invoke the Maldet scanner (located at /usr/local/sbin/maldet) and requires it to be installed and accessible on the system. You will need the appropriate permissions to run the Maldet command via sudo. Make sure you have Maldet installed correctly on your system.

Setup Instructions

To ensure everything works correctly:

1. Install Python: Make sure Python 3.x is installed on your system.

2. Verify Tkinter: Although Tkinter usually comes with Python, you can verify it by running:

python

   import tkinter as tk
   



If there are no import errors, it is installed.

3. Install Maldet (if not installed): You will need to install Maldet if it's not already. You can typically download and install It from Rfx Networks’ Maldet page.

4. Running the Script: To run this script, save it as a .py file and execute it with:

bash

   python your_script.py
   



5. Permissions: Make sure you have the necessary permissions and that the Maldet executable is in the specified path. You may need to change the code based on your Maldet installation path.

Note

Make sure to test the GUI thoroughly to ensure that all functionalities such as scanning, stopping scans, and saving output work as expected. If you encounter issues with tkinter, consider checking your Python installation or environment setup.
