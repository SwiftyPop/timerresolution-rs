# SetTimerResolution - RS edition

This is a modern Rust fork of the original [C++ `SetTimerResolution` utility](https://github.com/valleyofdoom/TimerResolution).
This version are fully rewritten in Rust & provide QoL fixes  over the original. More info [here](https://github.com/valleyofdoom/TimerResolution).

---

## Usage: Run at Startup

To run the program in the background and have it start automatically with Windows, you can use one of the methods below.

### Method 1: Startup Folder (Easiest)

This method automatically runs the program when you log in.

1.  Place `SetTimerResolution.exe` in a permanent location (e.g., `C:\Tools\`).
2.  Right-click `SetTimerResolution.exe` and select **Create shortcut**.
3.  Right-click the new shortcut and choose **Properties**.
4.  In the **Target** field, add your command-line arguments after the executable path.
    * **Example:**
    ```
    C:\Tools\SetTimerResolution.exe --resolution 5000 --no-console
    ```
5.  Press **Win** + **R** to open the Run box.
6.  Type `shell:startup` and press $\text{Enter}$. This will open your user's Startup folder.
7.  Move the modified shortcut into this "Startup" folder.

The program will now run with your chosen settings every time you log in.

### Method 2: Task Scheduler (Advanced)

If you prefer more control (e.g., running with elevated privileges), you can use the Task Scheduler:

1.  Place the `SetTimerResolution.exe` binary in a permanent location (e.g., `C:\Tools\`).
2.  Create a Scheduled Task (set to trigger "At log on").
3.  Set the action to "Start a program" using the following command:

```bash
C:\Tools\SetTimerResolution.exe --resolution 5000 --no-console
