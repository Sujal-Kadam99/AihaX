import subprocess

proc = subprocess.run([r"bin\tools\katana.exe", "-h"], capture_output=True, text=True)
with open("katana_help.txt", "w") as f:
    f.write(proc.stdout + "\n" + proc.stderr)
print("Wrote katana_help.txt")
