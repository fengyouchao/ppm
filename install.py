#!/usr/bin/env python
import os
import sys
import platform


if __name__ == '__main__':
    support_os = ('Darwin', 'Linux')
    current_os = platform.system()
    if not support_os.__contains__(current_os):
        print '%s not support' % current_os
        sys.exit(-1)
    # if os.geteuid():
    #     args = [sys.executable] + sys.argv
    #     os.execlp('su', 'su', '-c', ' '.join(args))
    os.chdir(os.path.dirname(sys.argv[0]))
    path = os.path.abspath('ppm.py')
    os.system('ln -sf %s /usr/bin/ppm' % path)
    os.system('wget https://bootstrap.pypa.io/get-pip.py')
    os.system('python get-pip.py')
    os.remove('get-pip.py')
    os.system('pip install pycrypto')
    os.system('pip install prompt-toolkit')
    os.system('pip install prettytable')
    print 'Install ppm successfully!'
