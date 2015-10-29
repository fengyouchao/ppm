#!/usr/bin/env python
import hashlib
import random
import string
import getpass
from Crypto.Cipher import AES
import sys
import pickle
import os

default_chars = 'abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()'
default_path = os.path.expanduser('~/.ppm.store')
BS = AES.block_size


def pad(s):
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)


def unpad(s):
    return s[0:-ord(s[-1])]


def hash_pwd(password):
    return hashlib.md5(hashlib.md5(hashlib.md5(password).hexdigest()).hexdigest()).hexdigest()


def random_pwd(length=12, charsets=default_chars):
    """
    :param length:  length of password
    :param charsets: set of characters
    :return: password
    """
    password_array = random.sample(charsets, length)
    return string.join(password_array, '')


def show_usage():
    print """Usage: command [options]

  Command:
    list [account_name]    List accounts
    find [account_name]    Find an account by name
    create [name:username:password:remark[]
                           Create new account
    remove [account_name]  Remove an account by name
    update [account_name]  Update an account
    passwd [new_password]  Change store password
    genpass                Generate a random string
    reset                  Reset ppm, delete store file. If you forget password for store
                           This command will reset ppm but it will delete all data
    upgrade                Upgrade PPM
    help/-h/--help         show help

  Options:
    -s <store_path>        Store path, default "~/.ppm.store"
    -p <password>          password for store
    --new <name:username:password:remark>
                           Specify a new account in command [create]
    --name <new_name>      set a new name for an account in command [update]
    --username <username>  set a new username for an account in command [update]
    --password <password>  set a new password for an account in command [update]
    --remark   <remark>    set a new remark for an account in command [update]
    -f                     Force to do some dangerous commands with no warning

More: https://github.com/fengyouchao/ppm
    """


def load(password, path=default_path, default=None):
    data_protector = DataProtector(password)
    if os.path.exists(path):
        with open(path, 'rb') as pm_file:
            encrypt_text = pm_file.read()
            text = data_protector.decrypt(encrypt_text)
        return pickle.loads(text)
    else:
        return default


def dump(data, password, path=default_path):
    text = pickle.dumps(data)
    data_protector = DataProtector(password)
    encrypted_text = data_protector.encrypt(text)
    with open(path, 'wb') as pm_file:
        pm_file.write(encrypted_text)


def require_pwd(args=sys.argv, msg='Password: '):
    _password = value_of_arg('-p', args)
    if _password:
        return _password
    else:
        return getpass.getpass(msg)


def value_of_arg(arg, args=sys.argv, default=None):
    for i in range(len(args)):
        if args[i] == arg and len(args) > i + 1:
            return args[i + 1]
    return default


def has_arg(arg, args=sys.argv):
    return args.__contains__(arg)


def require_keyword(args=sys.argv):
    _keyword = get_command_value(args)
    if _keyword:
        return _keyword
    else:
        return raw_input("Search keyword: ")


def get_command_value(args=sys.argv):
    if len(args) > 2 and not args[2].startswith('-'):
        return args[2]


def require_name(args=sys.argv):
    _name = get_command_value(args)
    if _name:
        return _name
    else:
        return raw_input("Account name: ")


def confirm(msg):
    _answer = raw_input(msg)
    if _answer == 'y' or _answer == 'Y':
        return True
    else:
        return False


def get_all_accounts(password, store_path=default_path):
    return load(password, path=store_path, default=[])


def get_store():
    return value_of_arg('-s', default=default_path)


def new_account_manager(password):
    try:
        return AccountManager(password, get_store())
    except Exception, e:
        print "Wrong password"
        sys.exit(-1)


def upgrade():
    os.chdir(os.path.dirname(sys.argv[0]))
    os.system('git checkout .')
    os.system('git pull origin master')


class Account(object):
    def __init__(self, name, username, password, remark=''):
        self.name = name
        self.username = username
        self.password = password
        self.remark = remark

    def set_name(self, name):
        self.name = name

    def set_username(self, username):
        self.username = username

    def set_password(self, password):
        self.password = password

    def set_remark(self, remark):
        self.remark = remark

    def __repr__(self):
        return "{\"name\":\"%s\", \"username\":\"%s\", \"password\":\"%s\", \"remark\":\"%s\"}" % (
            self.name, self.username, self.password, self.remark)


class AccountManager(object):
    def __init__(self, password, store_path=default_path):
        self.password = password
        self.store_path = store_path
        self.accounts = get_all_accounts(password, self.store_path)

    def get_all(self):
        return self.accounts

    def find(self, name):
        for _account in self.accounts:
            if _account.name == name:
                return _account

    def exist(self, name):
        if self.find(name):
            return True
        else:
            return False

    def search(self, keyword):
        result = []
        for _account in self.accounts:
            if _account.name.__contains__(keyword) or _account.remark.__contains__(keyword):
                result.append(_account)
        return result

    def remove(self, remove_account):
        self.accounts.remove(remove_account)
        self.persist(self.password)

    def add_account(self, new_account):
        self.accounts.append(new_account)
        self.persist(self.password)

    def change_pwd(self, new_password):
        self.persist(new_password)

    def persist(self, password):
        dump(self.accounts, password, path=self.store_path)


class DataProtector(object):
    def __init__(self, password):
        self.__aes__ = AES.new(hash_pwd(password))

    def encrypt(self, plaintext):
        return self.__aes__.encrypt(pad(plaintext))

    def decrypt(self, ciphertext):
        return unpad(self.__aes__.decrypt(ciphertext))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        show_usage()
        sys.exit(0)
    command = sys.argv[1]

    if command == 'list':
        store_password = require_pwd()
        value = get_command_value()
        manager = new_account_manager(store_password)
        if value:
            account = manager.find(value)
            if account:
                print account
        else:
            accounts = manager.get_all()
            for account in accounts:
                print account

    elif command == 'create':
        store_password = require_pwd()
        manager = new_account_manager(store_password)
        create_value = get_command_value()
        if create_value:
            value = create_value.split(':')
            if len(value) == 4:
                ac_name, ac_username, ac_password, ac_remark = value
                if manager.exist(ac_name):
                    print "[%s] already exists" % ac_name
                    sys.exit(-1)
                else:
                    manager.add_account(Account(ac_name, ac_username, ac_password, ac_remark))
                    print "Create record success!"
            else:
                print '[--new] value should be <name:username:password:remark>'
        else:
            ac_name = raw_input("Name for new account: ")
            while manager.exist(ac_name):
                ac_name = raw_input("[%s] already exists, change new name: " % ac_name)
            ac_username = raw_input("Username: ")
            ac_password = getpass.getpass('Password for [%s]: ' % ac_username)
            ac_remark = raw_input("Remark: ")
            manager.add_account(Account(ac_name, ac_username, ac_password, ac_remark))
            print "Create new account successfully!"

    elif command == 'find':
        store_password = require_pwd()
        account_name = require_name()
        manager = new_account_manager(store_password)
        account = manager.find(account_name)
        if account:
            print account
        else:
            print "No account named [%s]" % account_name

    elif command == 'search':
        store_password = require_pwd()
        search_keyword = require_keyword()
        manager = new_account_manager(store_password)
        accounts = manager.search(search_keyword)
        for account in accounts:
            print account

    elif command == 'update':
        store_password = require_pwd()
        manager = new_account_manager(store_password)
        account_name = require_name()
        account = manager.find(account_name)
        if account:
            update_name = value_of_arg('--name')
            print update_name
            if update_name and update_name != account_name:
                if manager.exist(update_name):
                    print "Account name [%s] already exists" % update_name
                    sys.exit(-1)
                account.set_name(update_name)
            update_username = value_of_arg('--username')
            if update_username:
                account.set_username(update_username)
            update_password = value_of_arg('--password')
            if update_password:
                account.set_password(update_password)
            update_remark = value_of_arg('--remark')
            if update_remark:
                account.set_remark(update_remark)
            if has_arg('-f'):
                manager.persist(store_password)
                print 'Account updated successfully'
            else:
                print account
                if confirm('Are you sure to update?[Y/N]: '):
                    manager.persist(store_password)
                    print 'Account updated successfully'
                else:
                    print 'Account unchanged'
        else:
            print 'No account named [%s]' % account_name

    elif command == 'remove':
        store_password = require_pwd()
        account_name = require_name()
        manager = new_account_manager(store_password)
        account = manager.find(account_name)
        if account:
            if has_arg('-f'):
                manager.remove(account)
            else:
                print account
                if confirm("Are you sure to remove this account?[Y/N]: "):
                    manager.remove(account)

    elif command == 'passwd':
        print "Changing password for store [%s]" % get_store()
        store_password = require_pwd(msg="(current) password: ")
        manager = new_account_manager(store_password)
        new_password = get_command_value()
        if not new_password:
            new_password1 = getpass.getpass("New password: ")
            new_password2 = getpass.getpass("Retype new password:")
            if new_password1 == new_password2:
                new_password = new_password1
            else:
                print "Sorry, password do not match"
                sys.exit(-1)
        manager.change_pwd(new_password)
        print 'Password updated successfully'
    elif command == 'genpass':
        print random_pwd()
    elif command == 'reset':
        store_path = get_store()
        if has_arg('-f') or confirm("Are you sure to reset store [%s]? [Y/N]: " % store_path):
            os.remove(store_path)
    elif command == 'upgrade':
        upgrade()
    elif command == 'help' or command == '-h' or command == '--help':
        show_usage()
    else:
        print 'Account updated successfully'
        print "Unknown command[%s]" % command
        sys.exit(-1)
