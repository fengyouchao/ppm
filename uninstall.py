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
    if os.geteuid():
        args = [sys.executable] + sys.argv
        os.execlp('su', 'su', '-c', ' '.join(args))
    os.chdir(os.path.dirname(sys.argv[0]))
    os.remove('/usr/bin/ppm')
    print 'Uninstall ppm successfully!'
