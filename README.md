SmartGuard: File Corruption Detection & Recovery System:
  SmartGuard is a powerful desktop computer security software developed using Python and PyQt5. SmartGuard performs real-time file corruption scanning and raw deleted file recovery using low-level disk scanning.   With the new, interactive graphical user interface and enhanced integrity checking, SmartGuard preserves data integrity and facilitates quick file restoration from accidental deletion.

Features:

➣ The continuous tracking of the assigned folders.
➣ Manual Integrity Check using SHA-256 + format checking
➣ File corruption detection for .jpg, .png, .pdf, .docx, and .zip files.
➣ Low-level deletion of files can be recovered using raw disk access.
➣ Provision of a Custom Recovery Directory.
➣ Dark Mode & New Neon UI
➣ Process Scheduling: Runs with the Highest Priority (REALTIME)
➣ Administrative Access Prompt at Startup

Workflow & Architecture:

➣ GUI Interface: Developed using PyQt5 and custom CSS styled

➣ Monitoring System:
  → Uses watchdog to monitor for file changes (create/delete)
  → Triggers corruption check on new files

➣ Manual Integrity Test:
  → Uses hashlib, PIL.Image.verify(), PDF/DOCX signature verification

➣ Raw Recovery Engine:
  → Reads raw disk bytes (\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\.\\\\\\\\\\\\\\\\C: style access)
  → Headers/footers detection in files (e.g., JPG: FFD8.FFD9)
  → Erases removed files from free space.

➣ Multithreading:
  → Maintains UI responsiveness during heavy recovery or scans

➣ Supported Formats
  → .jpg, .png (imagenes)
  → .pdf. (documents).
  → .docx (Word files)
  → .zip (compressed archives)
  → Other formats can be implemented using the signature definitions available in recovery.py.

How to Run:

➣ Requirements
  → Python 3.8+
  → Admin rights (for raw disc access)

➣ Dependencies:
  → bash
  → Copy
  → Edit
  → pip install -r requirements.txt
  → Start the Application
  → bash
  → Copy
  → Rephrase
  → python app.py
  → Upon launch, the app will:
    • Request for administrative rights (Windows)
    • Set process priority to REALTIM
    • Start default monitoring of the Downloads folder.

Main Modules:

  ➣ Module\tResponsibility
  ➣ app.py
  ➣ Main GUI + logic binding
  ➣ monitor.py
  ➣ Watchdog-based live folder monitor
  ➣ recovery.py
  ➣ File carving engine (header-footer scanning)

Example Use Case
  
  ➣ Open SmartGuard in admin.
  ➣ Choose a folder to look at (Downloads, Documents, etc.)
  ➣ Upload or remove a file.
  ➣ App will record modifications & flag if corruption is detected.
  ➣ Click on "Recover Raw Files" and select drive & output path.
  ➣ Deleted files (images/docs) will be carved & restored!

★ Notes:
   ➣ Recovery success depends on whether deleted data has been overwritten.
   ➣ Scanning whole drives is time-consuming; use demo on external drives/USBs. 
   ➣ Run as Admin to have full functionality.

★ Author
   ➣ Developed by Shiv Swaroop Sabharwal
   ➣ Contact: shivswaroopsabharwal@gmail.com

