import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='padding_oracle',
    version='0.1.4',
    author='Yuankui Lee',
    author_email='toregnerate@gmail.com',
    description='Threaded padding oracle automation.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/djosix/padding_oracle.py',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security :: Cryptography'
    ],
    python_requires='>=3.5',
)
