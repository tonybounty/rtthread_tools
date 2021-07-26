from distutils.core import setup
from setuptools import find_packages 


setup(
    name='rtthread-tools',
    version='0.0.1',
    description='Python tools for RT-Thread real-time operating system',
    author='Tanski Mikael',
    url='https://github.com/tonybounty/rtthread',
    license='MIT License',
    classifiers = [
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development :: Embedded Systems',
    ],
    packages=find_packages(),
    install_requires=["pycrypto"],
)