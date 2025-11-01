import os
import shutil
import subprocess
from pathlib import Path

def get_dll_dependencies(pyd_file):
    """
    Get DLL dependencies from a .pyd file using objdump or dumpbin.
    """
    dependencies = []
    pyd_path = Path(pyd_file)
    
    if not pyd_path.exists():
        print(f"Error: {pyd_file} not found!")
        return dependencies
    
    # Try using objdump (MinGW)
    try:
        result = subprocess.run(
            ['objdump', '-p', str(pyd_path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse objdump output for DLL dependencies
        for line in result.stdout.split('\n'):
            if 'DLL Name:' in line:
                dll_name = line.split('DLL Name:')[1].strip()
                dependencies.append(dll_name)
        
        return dependencies
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Try using dumpbin (MSVC)
    try:
        result = subprocess.run(
            ['dumpbin', '/dependents', str(pyd_path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse dumpbin output for DLL dependencies
        in_deps_section = False
        for line in result.stdout.split('\n'):
            if 'dependencies' in line.lower():
                in_deps_section = True
                continue
            if in_deps_section:
                line = line.strip()
                if line.endswith('.dll'):
                    dependencies.append(line)
                elif 'Summary' in line:
                    break
        
        return dependencies
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    print("Warning: Neither objdump nor dumpbin found. Install MinGW or MSVC tools.")
    return dependencies

def search_dll_in_system(dll_name):
    """
    Search for a DLL in common system locations.
    Returns the path if found, None otherwise.
    """
    # Common search paths
    search_paths = [
        r'C:\msys64\mingw64\bin',
        r'C:\msys64\usr\bin',
        r'C:\msys2\mingw64\bin',
        r'C:\msys2\usr\bin',
        r'C:\Program Files\Git\mingw64\bin',
        r'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE',
        r'C:\Windows\System32\downlevel',
        r'C:\MinGW\bin',
        r'C:\Windows\System32',
    ]
    
    # Add PATH directories
    path_dirs = os.environ.get('PATH', '').split(os.pathsep)
    search_paths.extend(path_dirs)
    
    # Search in each path
    for search_dir in search_paths:
        if not search_dir or not os.path.isdir(search_dir):
            continue
        
        dll_path = Path(search_dir) / dll_name
        if dll_path.exists():
            return dll_path
    
    return None

def is_system_dll(dll_name):
    """Check if a DLL is a Windows system DLL."""
    dll_lower = dll_name.lower()
    
    # Known system DLLs
    system_dlls = {
        'kernel32.dll', 'user32.dll', 'advapi32.dll', 'ws2_32.dll',
        'msvcrt.dll', 'shell32.dll', 'ole32.dll', 'oleaut32.dll',
        'gdi32.dll', 'comdlg32.dll', 'version.dll', 'winmm.dll',
        'imm32.dll', 'comctl32.dll', 'setupapi.dll', 'winspool.drv',
        'bcrypt.dll', 'crypt32.dll', 'secur32.dll', 'rpcrt4.dll',
        'ntdll.dll', 'kernelbase.dll', 'ucrtbase.dll'
    }
    
    # Check exact matches
    if dll_lower in system_dlls:
        return True
    
    # Check for API Set DLLs (api-ms-win-*, ext-ms-win-*)
    if dll_lower.startswith(('api-ms-win-', 'ext-ms-win-')):
        return True
    
    return False

def copy_required_dlls(pyd_file='discord_py.pyd', primary_source=r'C:\msys64\mingw64\bin'):
    """
    Copy required DLL files to local lib folder, searching system if not found in primary source.
    """
    primary_source_path = Path(primary_source)
    dest_dir = Path.cwd() / "lib"
    
    # Create lib directory if it doesn't exist
    dest_dir.mkdir(exist_ok=True)
    
    print(f"Analyzing dependencies for: {pyd_file}\n")
    
    # Get DLL dependencies
    dll_dependencies = get_dll_dependencies(pyd_file)
    
    if not dll_dependencies:
        print("No dependencies found or unable to read dependencies.")
        return [], []
    
    print(f"Found {len(dll_dependencies)} DLL dependencies:")
    for dll in dll_dependencies:
        print(f"  - {dll}")
    print()
    
    dlls_to_copy = [dll for dll in dll_dependencies 
                    if not is_system_dll(dll)]
    
    if len(dlls_to_copy) < len(dll_dependencies):
        skipped = len(dll_dependencies) - len(dlls_to_copy)
        print(f"Skipping {skipped} system DLL(s) (not needed)\n")
    
    # Copy each DLL from source to destination
    copied = []
    not_found = []
    already_copied = set()
    
    def copy_dll_recursive(dll_name, indent=0):
        """Recursively copy DLL and its dependencies."""
        if dll_name.lower() in already_copied or is_system_dll(dll_name.lower()):
            return
        
        already_copied.add(dll_name.lower())
        prefix = "  " * indent
        
        dest_file = dest_dir / dll_name
        
        # First, try primary source
        source_file = primary_source_path / dll_name
        
        # If not in primary source, search system
        if not source_file.exists():
            print(f"{prefix}⚠ Not in {primary_source}, searching system...")
            found_path = search_dll_in_system(dll_name)
            if found_path:
                source_file = found_path
                print(f"{prefix}  Found at: {source_file.parent}")
            else:
                not_found.append(dll_name)
                print(f"{prefix}✗ Not found anywhere: {dll_name}")
                return
        
        # Copy the DLL
        try:
            shutil.copy2(source_file, dest_file)
            copied.append(dll_name)
            print(f"{prefix}✓ Copied: {dll_name}")
            
            # Check if this DLL has dependencies too
            try:
                sub_deps = get_dll_dependencies(dest_file)
                for sub_dll in sub_deps:
                    if sub_dll.lower() not in system_dlls:
                        copy_dll_recursive(sub_dll, indent + 1)
            except Exception as e:
                # If we can't read sub-dependencies, that's okay
                pass
                    
        except Exception as e:
            print(f"{prefix}✗ Error copying {dll_name}: {e}")
    
    print("Copying DLLs and their dependencies...\n")
    for dll_name in dlls_to_copy:
        copy_dll_recursive(dll_name)
    
    # Summary
    print(f"\n{'='*60}")
    print(f"Summary:")
    print(f"  Successfully copied: {len(copied)} DLL(s)")
    print(f"  Not found anywhere: {len(not_found)} DLL(s)")
    print(f"  Destination: {dest_dir.absolute()}")
    
    if not_found:
        print(f"\nMissing DLLs (could not locate on system):")
        for dll in not_found:
            print(f"  - {dll}")
        print(f"\nThese may need to be installed or built separately.")
    
    return copied, not_found

if __name__ == "__main__":
    print("Extracting and copying DLL dependencies...\n")
    
    # Check if discord_py.pyd exists
    pyd_files = [f for f in os.listdir('.') if f.endswith('.pyd')]
    
    if not pyd_files:
        print("Error: No .pyd files found in current directory!")
        exit(1)
    
    if 'discord_py.pyd' in pyd_files:
        pyd_file = 'discord_py.pyd'
    else:
        pyd_file = pyd_files[0]
        print(f"Using: {pyd_file}\n")
    
    copied, not_found = copy_required_dlls(pyd_file)
    
    if copied:
        print("\n✓ Done! Add 'lib' directory to your PATH:")
        print("  set PATH=%PATH%;%CD%\\lib")
        print("\nOr use in Python:")
        print("  import os")
        print("  os.add_dll_directory(os.path.join(os.getcwd(), 'lib'))")
    else:
        print("\n⚠ No DLLs were copied.")