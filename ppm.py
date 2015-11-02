#!/usr/bin/env python
from __future__ import unicode_literals
from Crypto.Cipher import AES
from prompt_toolkit.history import FileHistory
from prompt_toolkit.contrib.completers import WordCompleter
from prompt_toolkit.contrib.completers import PathCompleter
from prompt_toolkit.key_binding.manager import KeyBindingManager
from prompt_toolkit.keys import Keys
from prompt_toolkit.filters import Condition
from prompt_toolkit.contrib.regular_languages.compiler import compile
from prompt_toolkit.contrib.regular_languages.completion import GrammarCompleter
from prompt_toolkit.contrib.regular_languages.lexer import GrammarLexer
from prompt_toolkit.layout.lexers import SimpleLexer
from pygments.token import Token
from prompt_toolkit.styles import DefaultStyle, PygmentsStyle
from prompt_toolkit.validation import Validator, ValidationError
from prompt_toolkit import prompt, AbortAction
from prettytable import PrettyTable
import hashlib
import random
import string
import getpass
import sys
import pickle
import os

update_options = ['name', 'username', 'password', 'remark']

shell_commands = [
    'list',
    'create',
    'search',
    'update',
    'remove',
    'password',
    'switch',
    'where',
    'exit',
    'help'
]

default_chars = 'abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()'
default_store_path = os.path.expanduser('~/.ppm.store')
ppm_shell_history = os.path.expanduser('~/.ppm.history')
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
    create [name:username:password:remark]
                           Create new account
    remove [account_name]  Remove an account by name
    update [account_name]  Update an account
    passwd [new_password]  Change store password
    genpass                Generate a random string
    shell                  Run an interactive shell
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


def load(password, path=default_store_path, default=None):
    data_protector = DataProtector(password)
    if os.path.exists(path):
        with open(path, 'rb') as pm_file:
            encrypt_text = pm_file.read()
            text = data_protector.decrypt(encrypt_text)
        return pickle.loads(text)
    else:
        return default


def dump(data, password, path=default_store_path):
    text = pickle.dumps(data)
    data_protector = DataProtector(password)
    encrypted_text = data_protector.encrypt(text)
    with open(path, 'wb') as pm_file:
        pm_file.write(encrypted_text)


def input_pwd(msg='Password:'):
    hidden = [True]
    pwd_key_bindings_manager = KeyBindingManager()

    @pwd_key_bindings_manager.registry.add_binding(Keys.ControlT)
    def _(event):
        hidden[0] = not hidden[0]

    return prompt(msg, is_password=Condition(lambda cli: hidden[0]),
                  key_bindings_registry=pwd_key_bindings_manager.registry)


def require_pwd(args=sys.argv, msg='Password: '):
    _password = find_arg_value('-p', args)
    if _password:
        return _password
    else:
        return input_pwd()


def find_arg_value(arg, args=sys.argv, default=None):
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


def get_all_accounts(password, store_path=default_store_path):
    return load(password, path=store_path, default=[])


def get_store():
    return find_arg_value('-s', default=default_store_path)


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

    def copy(self):
        return Account(self.name, self.username, self.password, self.remark)

    def copy_from(self, source):
        self.name = source.name
        self.username = source.username
        self.password = source.password
        self.remark = source.remark

    def __repr__(self):
        return "{\"name\":\"%s\", \"username\":\"%s\", \"password\":\"%s\", \"remark\":\"%s\"}" % (
            self.name, self.username, self.password, self.remark)


class AccountManager(object):
    def __init__(self, password, store_path=default_store_path):
        self.password = password
        self.store_path = store_path
        self.accounts = get_all_accounts(password, self.store_path)

    def get_store_path(self):
        return self.store_path

    def get_password(self):
        return self.password

    def get_all(self):
        return self.accounts

    def update(self, name, updated_account):
        account = self.find(name)
        account.copy_from(updated_account)
        self.persist(self.password)

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

    def get_all_name(self):
        all_accounts = self.get_all()
        all_names = []
        for ac in all_accounts:
            all_names.append(ac.name)
        return all_names

    def change_pwd(self, new_pwd):
        self.password = new_pwd
        self.persist(new_pwd)

    def persist(self, password):
        dump(self.accounts, password, path=self.store_path)


class DataProtector(object):
    def __init__(self, password):
        self.__aes__ = AES.new(hash_pwd(password))

    def encrypt(self, plaintext):
        return self.__aes__.encrypt(pad(plaintext))

    def decrypt(self, ciphertext):
        return unpad(self.__aes__.decrypt(ciphertext))


class AccountNameExistValidator(Validator):
    def __init__(self, account_manager):
        self.manager = account_manager

    def validate(self, document):
        name = document.text
        if self.manager.exist(name):
            raise ValidationError(message='Account name [%s] already exists' % name,
                                  cursor_position=len(document.text))  # Move cursor to end of input.


def show_accounts(accounts):
    x = PrettyTable(['No', 'Name', 'Username', 'Password', 'Remark'])
    x.align['No'] = 1
    x.padding_width = 1
    if not isinstance(accounts, list):
        accounts = [accounts]
    no = 1
    for account in accounts:
        x.add_row([no, account.name, account.username, account.password, account.remark])
        no += 1
    if len(accounts) > 0:
        print x


def do_list(account_manager, target=None):
    if target:
        ac = account_manager.find(target)
        if ac:
            show_accounts(ac)
    else:
        all_accounts = account_manager.get_all()
        show_accounts(all_accounts)


def do_create(account_manager):
    try:
        name = prompt('Enter name for new account: ', validator=AccountNameExistValidator(account_manager))
        username = prompt("Enter username for [%s]: " % name)
        password = input_pwd("Enter password for [%s]: " % name)
        retype_password = input_pwd("Retype password: ")
        while password != retype_password:
            print "Password do not match, try again"
            password = input_pwd("Enter password for [%s]: " % name)
            retype_password = input_pwd("Retype password: ")
        remark = prompt("Enter remark: ")
        account_manager.add_account(Account(name, username, password, remark))
        print "Create new account successfully!"

    except KeyboardInterrupt, e:
        print 'Command [create] canceled!'
        return


def do_search(account_manager, keyword):
    accounts = account_manager.search(keyword)
    show_accounts(accounts)


def do_remove(account_manager, target, force=False):
    account = account_manager.find(target)
    if force:
        account_manager.remove(account)
    else:
        show_accounts(account)
        if confirm("Are you sure to remove this account? [Y/N]: "):
            account_manager.remove(account)


def do_password(account_manager, store_path=default_store_path):
    old = input_pwd('Enter current password for store [%s]: ' % store_path)
    try:
        manager = AccountManager(old, store_path=store_path)
        new = input_pwd('Enter new password for store [%s]: ' % store_path)
        retype = input_pwd("Retype password: ")
        i = 0
        while new != retype and i < 2:
            print "Sorry, password not match!"
            new = input_pwd('Enter new password for store [%s]: ' % store_path)
            retype = input_pwd("Retype password: ")
            i += 1
        if new == retype:
            manager.change_pwd(new)
            if manager.get_store_path() == account_manager.get_store_path():
                return manager
            else:
                return account_manager
        else:
            print "Change password failed!"
        return account_manager

    except Exception, e:
        print "ERROR: Wrong password!"
        return account_manager


def do_switch(store_path):
    password = input_pwd("Enter password for store [%s]: " % store_path)
    return AccountManager(password, store_path)


def do_update(account_manager, target, field, force=False):
    account = account_manager.find(target)
    if account:
        try:
            updated_account = account.copy()
            if field == 'username':
                new_username = prompt("Enter new username: ")
                updated_account.username = new_username
            elif field == 'password':
                new_password = input_pwd('Enter new password for account [%s]: ' % target)
                updated_account.password = new_password
            elif field == 'remark':
                new_remark = prompt('Enter new remark: ')
                updated_account.remark = new_remark
            elif field == 'name':
                new_name = prompt('Enter new name: ', validator=AccountNameExistValidator(account_manager))
                updated_account.name = new_name
            show_accounts(updated_account)
            if force or confirm('Are you sure to update this account? [Y/N]: '):
                account_manager.update(target, updated_account)
                print 'Update successfully!'
        except KeyboardInterrupt, e:
            print "Command [update] canceled!"
    else:
        print 'No such account named [%s]' % target


def do_help():
    print """Usage: Command <values> [Options]
Command:
    list [accountName]             List all accounts or a specified account.
    create                         Create an account.
    update <accountName> <name|username|password|remark> [-f]
                                   Update a exist account.
    remove <accountName] [-f]      Remove a specified account. Using [-f] to remove account with no warning.
    search <keyword>               Search accounts by a keyword.
    password [storePath]           Change current store's password or change a specified  store's password.
    switch <storePath>             Switch to a specified store.
    where                          Show current store path.
    exit                           Exit.
    help                           Show help.

Options:
    -f                           Do some commands with no warning.

Shortcut Key:
    ls = list
    ct = create
    ud = update
    rm = remove
    sh = search
    pw = password
    st = switch
    we = where
    et = exit
    hp = help
    """


def create_grammar():
    return compile("""
        (\s*(?P<command>list)   (\s+ (?P<accountName>[\w0-9]+))?  \s*)  |
        (\s*(?P<command>remove)   \s+ (?P<accountName>[\w0-9]+) (\s+(?P<force>-f))?  \s*) |
        (\s*(?P<command>update)  \s+ (?P<accountName>[\w0-9\.]+)
             \s+ (?P<updateOption>name|username|password|remark) (\s+(?P<force>-f))? \s*) |
        (\s*(?P<command>search)  \s+ (?P<keyword>[\w0-9]+) \s*) |
        (\s*(?P<command>password)  (\s+ (?P<path>~?[\w0-9\./_-]+))? \s*) |
        (\s*(?P<command>switch)  \s+ (?P<path>~?[\w0-9\./_-]+) \s*) |
        (\s*(?P<command>where) \s*) |
        (\s*(?P<command>exit) \s*) |
        (\s*(?P<command>create) \s*) |
        (\s*(?P<command>help) \s*)
    """)


class CommandStyle(DefaultStyle):
    styles = {}
    styles.update(DefaultStyle.styles)
    styles.update({
        Token.Command: '#33aa33 bold',
        Token.Value: '#aa3333 bold',
        Token.Option: '#aa1333 bold',
        Token.OptionValue: '#aa8383 bold',
        Token.TrailingInput: 'bg:#662222 #ffffff',
    })


def run_shell():
    ppm_password = require_pwd()
    account_manager = new_account_manager(ppm_password)
    shell_history = FileHistory(ppm_shell_history)
    key_bindings_manager = KeyBindingManager.for_prompt()

    g = create_grammar()
    lexer = GrammarLexer(g, lexers={
        'command': SimpleLexer(Token.Command),
        'value': SimpleLexer(Token.Value),
        'accountName': SimpleLexer(Token.Value),
        'force': SimpleLexer(Token.Option),
        'option': SimpleLexer(Token.Option),
        'updateOption': SimpleLexer(Token.Option),
        'updateValue': SimpleLexer(Token.OptionValue),
        'keyword': SimpleLexer(Token.Value),
        'path': SimpleLexer(Token.Value),
    })

    @key_bindings_manager.registry.add_binding('c', 't')
    def _(event):
        if len(event.cli.current_buffer.text) == 0:
            event.cli.current_buffer.insert_text('create')

    @key_bindings_manager.registry.add_binding('l', 's')
    def _(event):
        if len(event.cli.current_buffer.text) == 0:
            event.cli.current_buffer.insert_text('list')

    @key_bindings_manager.registry.add_binding('e', 't')
    def _(event):
        if len(event.cli.current_buffer.text) == 0:
            event.cli.current_buffer.insert_text('exit')

    @key_bindings_manager.registry.add_binding('r', 'm')
    def _(event):
        if len(event.cli.current_buffer.text) == 0:
            event.cli.current_buffer.insert_text('remove')

    @key_bindings_manager.registry.add_binding('p', 'w')
    def _(event):
        if len(event.cli.current_buffer.text) == 0:
            event.cli.current_buffer.insert_text('password')

    @key_bindings_manager.registry.add_binding('s', 't')
    def _(event):
        if len(event.cli.current_buffer.text) == 0:
            event.cli.current_buffer.insert_text('switch')

    @key_bindings_manager.registry.add_binding('w', 'e')
    def _(event):
        if len(event.cli.current_buffer.text) == 0:
            event.cli.current_buffer.insert_text('where')

    @key_bindings_manager.registry.add_binding('u', 'd')
    def _(event):
        if len(event.cli.current_buffer.text) == 0:
            event.cli.current_buffer.insert_text('update')

    @key_bindings_manager.registry.add_binding('s', 'h')
    def _(event):
        if len(event.cli.current_buffer.text) == 0:
            event.cli.current_buffer.insert_text('search')

    @key_bindings_manager.registry.add_binding('h', 'p')
    def _(event):
        if len(event.cli.current_buffer.text) == 0:
            event.cli.current_buffer.insert_text('help')

    while True:

        completer = GrammarCompleter(g, {
            'command': WordCompleter(shell_commands),
            'accountName': WordCompleter(account_manager.get_all_name()),
            'force': WordCompleter(['-f']),
            'updateOption': WordCompleter(update_options),
            'path': PathCompleter(),
        })
        text = prompt(">> ", history=shell_history,
                      key_bindings_registry=key_bindings_manager.registry, lexer=lexer, completer=completer,
                      style=PygmentsStyle(CommandStyle), on_abort=AbortAction.RETRY)
        m = g.match(text)
        if m:
            _vars = m.variables()
            command = _vars.get('command')
            if command == 'list':
                target = _vars.get('accountName')
                do_list(account_manager, target=target)
            elif command == 'create':
                do_create(account_manager)
            elif command == 'remove':
                target = _vars.get('accountName')
                force_option = _vars.get('force')
                do_remove(account_manager, target=target, force=force_option)
            elif command == 'update':
                target = _vars.get('accountName')
                update_option = _vars.get('updateOption')
                force_option = _vars.get('force')
                do_update(account_manager, target=target, field=update_option, force=force_option)
            elif command == 'search':
                keyword = _vars.get('keyword')
                do_search(account_manager, keyword=keyword)
            elif command == 'password':
                store_path = _vars.get('path')
                if not store_path:
                    store_path = default_store_path
                account_manager = do_password(account_manager, store_path=store_path)
            elif command == 'switch':
                store_path = _vars.get('path')
                try:
                    account_manager = do_switch(store_path)
                except Exception, e:
                    print "ERROR: Wrong password!"
            elif command == 'where':
                print account_manager.get_store_path()
            elif command == 'exit':
                sys.exit(0)
            elif command == 'help':
                do_help()
        else:
            print 'ERROR: Command error!'


def main():
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
                show_accounts([account])
        else:
            accounts = manager.get_all()
            show_accounts(accounts)

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
            update_name = find_arg_value('--name')
            print update_name
            if update_name and update_name != account_name:
                if manager.exist(update_name):
                    print "Account name [%s] already exists" % update_name
                    sys.exit(-1)
                account.set_name(update_name)
            update_username = find_arg_value('--username')
            if update_username:
                account.set_username(update_username)
            update_password = find_arg_value('--password')
            if update_password:
                account.set_password(update_password)
            update_remark = find_arg_value('--remark')
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
    elif command == 'shell':
        run_shell()
    else:
        print 'Account updated successfully'
        print "Unknown command[%s]" % command
        sys.exit(-1)


if __name__ == '__main__':
    main()
