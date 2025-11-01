#!/usr/bin/env python3
"""
Setup script for building Discord Python bindings using Cython.

Usage:
    python setup.py build_ext --inplace
    
Or to install:
    pip install .
"""

from setuptools import setup, Extension
from Cython.Build import cythonize
import sys
import os

# Platform-specific compilation settings
extra_compile_args = []
extra_link_args = []
libraries = ['curl', 'cJSON', 'websockets']

if sys.platform == 'win32':
    # Windows-specific settings
    libraries.append('ws2_32')
    
    # Try to detect MSYS2/MinGW or vcpkg
    msys2_path = r"C:\msys64\mingw64"
    vcpkg_path = r"C:\vcpkg\installed\x64-windows"
    
    if os.path.exists(msys2_path):
        # Using MSYS2/MinGW
        print(f"Found MSYS2 at {msys2_path}")
        extra_compile_args = ['-O3', '-Wall']
        extra_compile_args.extend([
            f'-I{msys2_path}\\include',
        ])
        extra_link_args.extend([
            f'-L{msys2_path}\\lib',
        ])
    elif os.path.exists(vcpkg_path):
        # Using vcpkg
        print(f"Found vcpkg at {vcpkg_path}")
        extra_compile_args = ['/O2'] if 'MSC' in sys.version else ['-O3', '-Wall']
        extra_compile_args.extend([
            f'-I{vcpkg_path}\\include',
        ])
        extra_link_args.extend([
            f'/LIBPATH:{vcpkg_path}\\lib',
        ])
    else:
        # Default Windows paths
        extra_compile_args = ['/O2'] if 'MSC' in sys.version else ['-O3', '-Wall']
        print("Warning: Could not find MSYS2 or vcpkg. You may need to specify library paths manually.")
else:
    # Unix-like systems (Linux, macOS)
    libraries.append('pthread')
    extra_compile_args = ['-O3', '-Wall']
    
    # macOS might need specific paths
    if sys.platform == 'darwin':
        # Common Homebrew paths
        extra_compile_args.extend([
            '-I/usr/local/include',
            '-I/opt/homebrew/include'
        ])
        extra_link_args.extend([
            '-L/usr/local/lib',
            '-L/opt/homebrew/lib'
        ])

# Define the extension module
extensions = [
    Extension(
        name="discord_py",
        sources=["discord_py.pyx"],
        libraries=libraries,
        include_dirs=[".", "./include"],
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
        define_macros=[('DISCORD_IMPLEMENTATION', None)],
        language="c"
    )
]

setup(
    name="discord-py-bindings",
    version="1.0.0",
    description="Python bindings for discord.h C library",
    author="Philip R. Simonson",
    author_email="psimonson1988@gmail.com",
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            'language_level': "3",
            'embedsignature': True,
            'binding': True
        }
    ),
    install_requires=[
        'cython>=0.29.0',
    ],
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Cython',
        'Topic :: Communications :: Chat',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)