
import collections
import os
import random
import re
import sys
import tempfile
import traceback
import warnings
from contextlib import contextmanager
from textwrap import dedent

_VersionInfo = collections.namedtuple(
    "VersionInfo", ("major", "minor", "micro", "releasesuffix"))

class VersionInfo(_VersionInfo):
    def __str__(self):
        res = ".".join( ( str(elt) for elt in self[:3] ) )
        if self.releasesuffix:
            res += self.releasesuffix
        return res

    def __repr__(self):
        return "{0}.{1}".format(__name__, _VersionInfo.__repr__(self))


version_info = VersionInfo(3, 5, 3, None)
__version__ = str(version_info)

try:
    from shlex import quote as _shell_quote
except ImportError:
    def _shell_quote(s):
        return "'%s'" % s.replace("'", "'\"'\"'")

class error(Exception):
    def __init__(self, message=None):
        self.message = message

    def __str__(self):
        return self.complete_message()

    def __repr__(self):
        return "{0}.{1}({2!r})".format(__name__, self.__class__.__name__,
                                       self.message)

    def complete_message(self):
        if self.message:
            return "{0}: {1}".format(self.ExceptionShortDescription,
                                     self.message)
        else:
            return self.ExceptionShortDescription

    ExceptionShortDescription = "{0} generic exception".format("pythondialog")


PythonDialogException = error

class ExecutableNotFound(error):
    ExceptionShortDescription = "Executable not found"

class PythonDialogBug(error):
    ExceptionShortDescription = "Bug in pythondialog"

class ProbablyPythonBug(error):
    ExceptionShortDescription = "Bug in python, probably"

class BadPythonDialogUsage(error):
    ExceptionShortDescription = "Invalid use of pythondialog"

class PythonDialogSystemError(error):
    ExceptionShortDescription = "System error"

class PythonDialogOSError(PythonDialogSystemError):
    ExceptionShortDescription = "OS error"

class PythonDialogIOError(PythonDialogOSError):
    ExceptionShortDescription = "IO error"

class PythonDialogErrorBeforeExecInChildProcess(PythonDialogSystemError):
    ExceptionShortDescription = "Error in a child process before the exec " \
                                "system call"

class PythonDialogReModuleError(PythonDialogSystemError):
    ExceptionShortDescription = "'re' module error"

class UnexpectedDialogOutput(error):
    ExceptionShortDescription = "Unexpected dialog output"

class DialogTerminatedBySignal(error):
    ExceptionShortDescription = "dialog-like terminated by a signal"

class DialogError(error):
    ExceptionShortDescription = "dialog-like terminated due to an error"

class UnableToRetrieveBackendVersion(error):
    ExceptionShortDescription = "Unable to retrieve the version of the \
dialog-like backend"

class UnableToParseBackendVersion(error):
    ExceptionShortDescription = "Unable to parse as a dialog-like backend \
version string"

class UnableToParseDialogBackendVersion(UnableToParseBackendVersion):
    ExceptionShortDescription = "Unable to parse as a dialog version string"

class InadequateBackendVersion(error):
    ExceptionShortDescription = "Inadequate backend version"


@contextmanager
def _OSErrorHandling():
    try:
        yield
    except OSError as e:
        raise PythonDialogOSError(str(e)) from e
    except IOError as e:
        raise PythonDialogIOError(str(e)) from e


try:
    _on_cre = re.compile(r"on$", re.IGNORECASE)
    _off_cre = re.compile(r"off$", re.IGNORECASE)

    _calendar_date_cre = re.compile(
        r"(?P<day>\d\d)/(?P<month>\d\d)/(?P<year>\d\d\d\d)$")
    _timebox_time_cre = re.compile(
        r"(?P<hour>\d\d):(?P<minute>\d\d):(?P<second>\d\d)$")
except re.error as e:
    raise PythonDialogReModuleError(str(e)) from e


def _dash_escape(args):
    res = []

    for arg in args:
        if arg.startswith("--"):
            res.extend(("--", arg))
        else:
            res.append(arg)

    return res

def _dash_escape_nf(args):
    if not args:
        raise PythonDialogBug("not a non-empty sequence: {0!r}".format(args))
    l = _dash_escape(args[1:])
    l.insert(0, args[0])
    return l

def _simple_option(option, enable):
    if enable:
        return (option,)
    else:
        return ()

_common_args_syntax = {
    "ascii_lines": lambda enable: _simple_option("--ascii-lines", enable),
    "aspect": lambda ratio: _dash_escape_nf(("--aspect", str(ratio))),
    "backtitle": lambda backtitle: _dash_escape_nf(("--backtitle", backtitle)),
    "beep": lambda enable: _simple_option("--beep", enable),
    "beep_after": lambda enable: _simple_option("--beep-after", enable),
    "begin": lambda coords: _dash_escape_nf(
        ("--begin", str(coords[0]), str(coords[1]))),
    "cancel_label": lambda s: _dash_escape_nf(("--cancel-label", s)),
    "cancel": lambda s: _dash_escape_nf(("--cancel-label", s)),
    "clear": lambda enable: _simple_option("--clear", enable),
    "colors": lambda enable: _simple_option("--colors", enable),
    "column_separator": lambda s: _dash_escape_nf(("--column-separator", s)),
    "cr_wrap": lambda enable: _simple_option("--cr-wrap", enable),
    "create_rc": lambda filename: _dash_escape_nf(("--create-rc", filename)),
    "date_format": lambda s: _dash_escape_nf(("--date-format", s)),
    "defaultno": lambda enable: _simple_option("--defaultno", enable),
    "default_button": lambda s: _dash_escape_nf(("--default-button", s)),
    "default_item": lambda s: _dash_escape_nf(("--default-item", s)),
    "exit_label": lambda s: _dash_escape_nf(("--exit-label", s)),
    "extra_button": lambda enable: _simple_option("--extra-button", enable),
    "extra_label": lambda s: _dash_escape_nf(("--extra-label", s)),
    "help": lambda enable: _simple_option("--help", enable),
    "help_button": lambda enable: _simple_option("--help-button", enable),
    "help_label": lambda s: _dash_escape_nf(("--help-label", s)),
    "help_status": lambda enable: _simple_option("--help-status", enable),
    "help_tags": lambda enable: _simple_option("--help-tags", enable),
    "hfile": lambda filename: _dash_escape_nf(("--hfile", filename)),
    "hline": lambda s: _dash_escape_nf(("--hline", s)),
    "ignore": lambda enable: _simple_option("--ignore", enable),
    "insecure": lambda enable: _simple_option("--insecure", enable),
    "item_help": lambda enable: _simple_option("--item-help", enable),
    "keep_tite": lambda enable: _simple_option("--keep-tite", enable),
    "keep_window": lambda enable: _simple_option("--keep-window", enable),
    "max_input": lambda size: _dash_escape_nf(("--max-input", str(size))),
    "no_cancel": lambda enable: _simple_option("--no-cancel", enable),
    "nocancel": lambda enable: _simple_option("--nocancel", enable),
    "no_collapse": lambda enable: _simple_option("--no-collapse", enable),
    "no_kill": lambda enable: _simple_option("--no-kill", enable),
    "no_label": lambda s: _dash_escape_nf(("--no-label", s)),
    "no_lines": lambda enable: _simple_option("--no-lines", enable),
    "no_mouse": lambda enable: _simple_option("--no-mouse", enable),
    "no_nl_expand": lambda enable: _simple_option("--no-nl-expand", enable),
    "no_ok": lambda enable: _simple_option("--no-ok", enable),
    "no_shadow": lambda enable: _simple_option("--no-shadow", enable),
    "no_tags": lambda enable: _simple_option("--no-tags", enable),
    "ok_label": lambda s: _dash_escape_nf(("--ok-label", s)),
    "print_maxsize": lambda enable: _simple_option("--print-maxsize",
                                                   enable),
    "print_size": lambda enable: _simple_option("--print-size", enable),
    "print_version": lambda enable: _simple_option("--print-version",
                                                   enable),
    "scrollbar": lambda enable: _simple_option("--scrollbar", enable),
    "separate_output": lambda enable: _simple_option("--separate-output",
                                                     enable),
    "separate_widget": lambda s: _dash_escape_nf(("--separate-widget", s)),
    "shadow": lambda enable: _simple_option("--shadow", enable),
    "size_err": lambda enable: _simple_option("--size-err", enable),
    "sleep": lambda secs: _dash_escape_nf(("--sleep", str(secs))),
    "stderr": lambda enable: _simple_option("--stderr", enable),
    "stdout": lambda enable: _simple_option("--stdout", enable),
    "tab_correct": lambda enable: _simple_option("--tab-correct", enable),
    "tab_len": lambda n: _dash_escape_nf(("--tab-len", str(n))),
    "time_format": lambda s: _dash_escape_nf(("--time-format", s)),
    "timeout": lambda secs: _dash_escape_nf(("--timeout", str(secs))),
    "title": lambda title: _dash_escape_nf(("--title", title)),
    "trace": lambda filename: _dash_escape_nf(("--trace", filename)),
    "trim": lambda enable: _simple_option("--trim", enable),
    "version": lambda enable: _simple_option("--version", enable),
    "visit_items": lambda enable: _simple_option("--visit-items", enable),
    "week_start": lambda start: _dash_escape_nf(
        ("--week-start", str(start) if isinstance(start, int) else start)),
    "yes_label": lambda s: _dash_escape_nf(("--yes-label", s)) }


def _find_in_path(prog_name):
    with _OSErrorHandling():
        PATH = os.getenv("PATH", "/bin:/usr/bin")
        for d in PATH.split(os.pathsep):
            file_path = os.path.join(d, prog_name)
            if os.path.isfile(file_path) \
               and os.access(file_path, os.R_OK | os.X_OK):
                return file_path
        return None


def _path_to_executable(f):
    with _OSErrorHandling():
        if '/' in f:
            if os.path.isfile(f) and os.access(f, os.R_OK | os.X_OK):
                res = f
            else:
                raise ExecutableNotFound("%s cannot be read and executed" % f)
        else:
            res = _find_in_path(f)
            if res is None:
                raise ExecutableNotFound(
                    "can't find the executable for the dialog-like "
                    "program")

    return os.path.realpath(res)


def _to_onoff(val):
    if isinstance(val, (bool, int)):
        return "on" if val else "off"
    elif isinstance(val, str):
        try:
            if _on_cre.match(val):
                return "on"
            elif _off_cre.match(val):
                return "off"
        except re.error as e:
            raise PythonDialogReModuleError(str(e)) from e

    raise BadPythonDialogUsage("invalid boolean value: {0!r}".format(val))


def _compute_common_args(mapping):
    args = []
    for option, value in mapping.items():
        args.extend(_common_args_syntax[option](value))
    return args


if sys.hexversion >= 0x030200F0:
    import abc
    class BackendVersion(metaclass=abc.ABCMeta):
        @abc.abstractmethod
        def __str__(self):
            raise NotImplementedError()

        if sys.hexversion >= 0x030300F0:
            @classmethod
            @abc.abstractmethod
            def fromstring(cls, s):
                raise NotImplementedError()
        else:
            @abc.abstractclassmethod
            def fromstring(cls, s):
                raise NotImplementedError()

        @abc.abstractmethod
        def __lt__(self, other):
            raise NotImplementedError()

        @abc.abstractmethod
        def __le__(self, other):
            raise NotImplementedError()

        @abc.abstractmethod
        def __eq__(self, other):
            raise NotImplementedError()

        @abc.abstractmethod
        def __ne__(self, other):
            raise NotImplementedError()

        @abc.abstractmethod
        def __gt__(self, other):
            raise NotImplementedError()

        @abc.abstractmethod
        def __ge__(self, other):
            raise NotImplementedError()
else:
    class BackendVersion:
        pass


class DialogBackendVersion(BackendVersion):
    try:
        _backend_version_cre = re.compile(r"""(?P<dotted> (\d+) (\.\d+)* )
                                              (?P<rest>.*)$""", re.VERBOSE)
    except re.error as e:
        raise PythonDialogReModuleError(str(e)) from e

    def __init__(self, dotted_part_or_str, rest=""):
        if isinstance(dotted_part_or_str, str):
            if rest:
                raise BadPythonDialogUsage(
                    "non-empty 'rest' with 'dotted_part_or_str' as string: "
                    "{0!r}".format(rest))
            else:
                tmp = self.__class__.fromstring(dotted_part_or_str)
                dotted_part_or_str, rest = tmp.dotted_part, tmp.rest

        for elt in dotted_part_or_str:
            if not isinstance(elt, int):
                raise BadPythonDialogUsage(
                    "when 'dotted_part_or_str' is not a string, it must "
                    "be a sequence (or iterable) of integers; however, "
                    "{0!r} is not an integer.".format(elt))

        self.dotted_part = list(dotted_part_or_str)
        self.rest = rest

    def __repr__(self):
        return "{0}.{1}({2!r}, rest={3!r})".format(
            __name__, self.__class__.__name__, self.dotted_part, self.rest)

    def __str__(self):
        return '.'.join(map(str, self.dotted_part)) + self.rest

    @classmethod
    def fromstring(cls, s):
        try:
            mo = cls._backend_version_cre.match(s)
            if not mo:
                raise UnableToParseDialogBackendVersion(s)
            dotted_part = [ int(x) for x in mo.group("dotted").split(".") ]
            rest = mo.group("rest")
        except re.error as e:
            raise PythonDialogReModuleError(str(e)) from e

        return cls(dotted_part, rest)

    def __lt__(self, other):
        return (self.dotted_part, self.rest) < (other.dotted_part, other.rest)

    def __le__(self, other):
        return (self.dotted_part, self.rest) <= (other.dotted_part, other.rest)

    def __eq__(self, other):
        return (self.dotted_part, self.rest) == (other.dotted_part, other.rest)

    def __ne__(self, other):
        return not (self == other)

    def __gt__(self, other):
        return not (self <= other)

    def __ge__(self, other):
        return not (self < other)


def widget(func):
    func.is_widget = True
    return func


def retval_is_code(func):
    func.retval_is_code = True
    return func


def _obsolete_property(name, replacement=None):
    if replacement is None:
        replacement = name

    def getter(self):
        warnings.warn("the DIALOG_{name} attribute of Dialog instances is "
                      "obsolete; use the Dialog.{repl} class attribute "
                      "instead.".format(name=name, repl=replacement),
                      DeprecationWarning)
        return getattr(self, replacement)

    return getter


class Dialog:
    try:
        _print_maxsize_cre = re.compile(r"""^MaxSize:[ \t]+
                                            (?P<rows>\d+),[ \t]*
                                            (?P<columns>\d+)[ \t]*$""",
                                        re.VERBOSE)
        _print_version_cre = re.compile(
            r"^Version:[ \t]+(?P<version>.+?)[ \t]*$", re.MULTILINE)
    except re.error as e:
        raise PythonDialogReModuleError(str(e)) from e

    _DIALOG_OK        = 0
    _DIALOG_CANCEL    = 1
    _DIALOG_ESC       = 2
    _DIALOG_ERROR     = 3
    _DIALOG_EXTRA     = 4
    _DIALOG_HELP      = 5
    _DIALOG_ITEM_HELP = 6
    _DIALOG_TIMEOUT   = 7
    _lowlevel_exit_code_varnames = frozenset(
        ("OK", "CANCEL", "ESC", "ERROR", "EXTRA", "HELP", "ITEM_HELP",
         "TIMEOUT"))

    OK     = "ok"
    CANCEL = "cancel"
    ESC    = "esc"
    EXTRA  = "extra"
    HELP   = "help"
    TIMEOUT = "timeout"
    DIALOG_OK        = property(_obsolete_property("OK"),
                         doc="Obsolete property superseded by Dialog.OK")
    DIALOG_CANCEL    = property(_obsolete_property("CANCEL"),
                         doc="Obsolete property superseded by Dialog.CANCEL")
    DIALOG_ESC       = property(_obsolete_property("ESC"),
                         doc="Obsolete property superseded by Dialog.ESC")
    DIALOG_EXTRA     = property(_obsolete_property("EXTRA"),
                         doc="Obsolete property superseded by Dialog.EXTRA")
    DIALOG_HELP      = property(_obsolete_property("HELP"),
                         doc="Obsolete property superseded by Dialog.HELP")
    DIALOG_ITEM_HELP = property(_obsolete_property("ITEM_HELP",
                                                   replacement="HELP"),
                         doc="Obsolete property superseded by Dialog.HELP")

    @property
    def DIALOG_ERROR(self):
        warnings.warn("the DIALOG_ERROR attribute of Dialog instances is "
                      "obsolete. Since the corresponding exit status is "
                      "automatically translated into a DialogError exception, "
                      "users should not see nor need this attribute. If you "
                      "think you have a good reason to use it, please expose "
                      "your situation on the pythondialog mailing-list.",
                      DeprecationWarning)
        return self._DIALOG_ERROR

    def __init__(self, dialog="dialog", DIALOGRC=None,
                 compat="dialog", use_stdout=None, *, autowidgetsize=False,
                 pass_args_via_file=None):
        if DIALOGRC is not None:
            self.DIALOGRC = DIALOGRC

        self._lowlevel_exit_codes = {
            name: getattr(self, "_DIALOG_" + name)
            for name in self._lowlevel_exit_code_varnames }

        self._dialog_exit_code_ll_to_hl = {}
        for name in self._lowlevel_exit_code_varnames:
            intcode = self._lowlevel_exit_codes[name]

            if name == "ITEM_HELP":
                self._dialog_exit_code_ll_to_hl[intcode] = self.HELP
            elif name == "ERROR":
                continue
            else:
                self._dialog_exit_code_ll_to_hl[intcode] = getattr(self, name)

        self._dialog_prg = _path_to_executable(dialog)
        self.compat = compat
        self.autowidgetsize = autowidgetsize
        self.dialog_persistent_arglist = []

        if self.compat == "Xdialog":
            self.use_stdout = True
        else:
            self.use_stdout = False
        if use_stdout is not None:
            self.use_stdout = use_stdout
        if self.use_stdout:
            self.add_persistent_args(["--stdout"])

        self.setup_debug(False)

        if compat == "dialog":
            self.pass_args_via_file = False
            self.cached_backend_version = DialogBackendVersion.fromstring(
                self.backend_version())
        else:
            self.cached_backend_version = None

        if pass_args_via_file is not None:
            self.pass_args_via_file = pass_args_via_file
        elif self.cached_backend_version is not None:
            self.pass_args_via_file = self.cached_backend_version >= \
                                      DialogBackendVersion("1.2-20150513")
        else:
            self.pass_args_via_file = False

    @classmethod
    def dash_escape(cls, args):
        return _dash_escape(args)

    @classmethod
    def dash_escape_nf(cls, args):
        return _dash_escape_nf(args)

    def add_persistent_args(self, args):
        self.dialog_persistent_arglist.extend(args)

    def set_background_title(self, text):
        self.add_persistent_args(self.dash_escape_nf(("--backtitle", text)))

    def setBackgroundTitle(self, text):

        warnings.warn("Dialog.setBackgroundTitle() has been obsolete for "
                      "many years; use Dialog.set_background_title() instead",
                      DeprecationWarning)
        self.set_background_title(text)

    def setup_debug(self, enable, file=None, always_flush=False, *,
                    expand_file_opt=False):
        self._debug_enabled = enable

        if not hasattr(self, "_debug_logfile"):
            self._debug_logfile = None
        if file is not None:
            self._debug_logfile = file

        if enable and self._debug_logfile is None:
            raise BadPythonDialogUsage(
                "you must specify a file object when turning debugging on")

        self._debug_always_flush = always_flush
        self._expand_file_opt = expand_file_opt
        self._debug_first_output = True

    def _write_command_to_file(self, env, arglist):
        envvar_settings_list = []

        if "DIALOGRC" in env:
            envvar_settings_list.append(
                "DIALOGRC={0}".format(_shell_quote(env["DIALOGRC"])))

        for var in self._lowlevel_exit_code_varnames:
            varname = "DIALOG_" + var
            envvar_settings_list.append(
                "{0}={1}".format(varname, _shell_quote(env[varname])))

        command_str = ' '.join(envvar_settings_list +
                               list(map(_shell_quote, arglist)))
        s = "{separator}{cmd}\n\nArgs: {args!r}\n".format(
            separator="" if self._debug_first_output else ("-" * 79) + "\n",
            cmd=command_str, args=arglist)

        self._debug_logfile.write(s)
        if self._debug_always_flush:
            self._debug_logfile.flush()

        self._debug_first_output = False

    def _quote_arg_for_file_opt(self, argument):
        l = ['"']

        for c in argument:
            if c in ('"', '\\'):
                l.append("\\" + c)
            else:
                l.append(c)

        return ''.join(l + ['"'])

    def _call_program(self, cmdargs, *, dash_escape="non-first",
                      use_persistent_args=True,
                      redir_child_stdin_from_fd=None, close_fds=(), **kwargs):
        new_environ = {}
        new_environ.update(os.environ)
        for var, value in self._lowlevel_exit_codes.items():
            varname = "DIALOG_" + var
            new_environ[varname] = str(value)
        if hasattr(self, "DIALOGRC"):
            new_environ["DIALOGRC"] = self.DIALOGRC

        if dash_escape == "non-first":
            cmdargs = self.dash_escape_nf(cmdargs)
        elif dash_escape != "none":
            raise PythonDialogBug("invalid value for 'dash_escape' parameter: "
                                  "{0!r}".format(dash_escape))

        arglist = [ self._dialog_prg ]

        if use_persistent_args:
            arglist.extend(self.dialog_persistent_arglist)

        arglist.extend(_compute_common_args(kwargs) + cmdargs)
        orig_args = arglist[:]

        if self.pass_args_via_file:
            tmpfile = tempfile.NamedTemporaryFile(
                mode="w", prefix="pythondialog.tmp", delete=False)
            with tmpfile as f:
                f.write(' '.join( ( self._quote_arg_for_file_opt(arg)
                                    for arg in arglist[1:] ) ))
            args_file = tmpfile.name
            arglist[1:] = ["--file", args_file]
        else:
            args_file = None

        if self._debug_enabled:
            self._write_command_to_file(
                new_environ, orig_args if self._expand_file_opt else arglist)

        with _OSErrorHandling():
            (child_output_rfd, child_output_wfd) = os.pipe()

        child_pid = os.fork()
        if child_pid == 0:
            try:
                for fd in close_fds + (child_output_rfd,):
                    os.close(fd)
                father_stderr = os.fdopen(os.dup(2), mode="w", buffering=1)
                os.dup2(child_output_wfd, 1 if self.use_stdout else 2)
                if redir_child_stdin_from_fd is not None:
                    os.dup2(redir_child_stdin_from_fd, 0)

                os.execve(self._dialog_prg, arglist, new_environ)
            except:
                print(traceback.format_exc(), file=father_stderr)
                father_stderr.close()
                os._exit(127)

            os._exit(126)

        with _OSErrorHandling():
            os.close(child_output_wfd)
        return (child_pid, child_output_rfd, args_file)

    def _wait_for_program_termination(self, child_pid, child_output_rfd):

        with _OSErrorHandling():
            with os.fdopen(child_output_rfd, "r") as f:
                child_output = f.read()

        exit_info = os.waitpid(child_pid, 0)[1]
        if os.WIFEXITED(exit_info):
            ll_exit_code = os.WEXITSTATUS(exit_info)
        elif os.WIFSIGNALED(exit_info):
            raise DialogTerminatedBySignal("the dialog-like program was "
                                           "terminated by signal %d" %
                                           os.WTERMSIG(exit_info))
        else:
            raise PythonDialogBug("please report this bug to the "
                                  "pythondialog maintainer(s)")

        if ll_exit_code == self._DIALOG_ERROR:
            raise DialogError(
                "the dialog-like program exited with status {0} (which was "
                "passed to it as the DIALOG_ERROR environment variable). "
                "Sometimes, the reason is simply that dialog was given a "
                "height or width parameter that is too big for the terminal "
                "in use. Its output, with leading and trailing whitespace "
                "stripped, was:\n\n{1}".format(ll_exit_code,
                                               child_output.strip()))
        elif ll_exit_code == 127:
            raise PythonDialogErrorBeforeExecInChildProcess(dedent("""\
            possible reasons include:
              - the dialog-like program could not be executed (this can happen
                for instance if the Python program is trying to call the
                dialog-like program with arguments that cannot be represented
                in the user's locale [LC_CTYPE]);
              - the system is out of memory;
              - the maximum number of open file descriptors has been reached;
              - a cosmic ray hit the system memory and flipped nasty bits.
            There ought to be a traceback above this message that describes
            more precisely what happened."""))
        elif ll_exit_code == 126:
            raise ProbablyPythonBug(
                "a child process returned with exit status 126; this might "
                "be the exit status of the dialog-like program, for some "
                "unknown reason (-> probably a bug in the dialog-like "
                "program); otherwise, we have probably found a python bug")

        try:
            hl_exit_code = self._dialog_exit_code_ll_to_hl[ll_exit_code]
        except KeyError:
            raise PythonDialogBug(
                "unexpected low-level exit status (new code?): {0!r}".format(
                    ll_exit_code))

        return (hl_exit_code, child_output)

    def _handle_program_exit(self, child_pid, child_output_rfd, args_file):
        try:
            exit_code, output = \
                    self._wait_for_program_termination(child_pid,
                                                       child_output_rfd)
        finally:
            with _OSErrorHandling():
                if args_file is not None and os.path.exists(args_file):
                    os.unlink(args_file)

        return (exit_code, output)

    def _perform(self, cmdargs, *, dash_escape="non-first",
                 use_persistent_args=True, **kwargs):
        child_pid, child_output_rfd, args_file = \
                    self._call_program(cmdargs, dash_escape=dash_escape,
                                       use_persistent_args=use_persistent_args,
                                       **kwargs)
        exit_code, output = self._handle_program_exit(child_pid,
                                                      child_output_rfd,
                                                      args_file)
        if exit_code == self.TIMEOUT:
            output = ""

        return (exit_code, output)

    def _strip_xdialog_newline(self, output):
        if self.compat == "Xdialog" and output.endswith("\n"):
            output = output[:-1]
        return output

    def _perform_no_options(self, cmd):

        warnings.warn("Dialog._perform_no_options() has been obsolete for "
                      "many years", DeprecationWarning)
        return os.system(self._dialog_prg + ' ' + cmd)

    def clear(self):
        warnings.warn("Dialog.clear() has been obsolete for many years.\n"
                      "You may use the clear(1) program to clear the screen.\n"
                      "cf. clear_screen() in examples/demo.py for an example",
                      DeprecationWarning)
        self._perform_no_options('--clear')

    def _help_status_on(self, kwargs):
        return ("--help-status" in self.dialog_persistent_arglist
                or kwargs.get("help_status", False))

    def _parse_quoted_string(self, s, start=0):
        if start >= len(s) or s[start] != '"':
            raise PythonDialogBug("quoted string does not start with a double "
                                  "quote: {0!r}".format(s))

        l = []
        i = start + 1

        while i < len(s) and s[i] != '"':
            if s[i] == "\\":
                i += 1
                if i >= len(s):
                    raise PythonDialogBug(
                        "quoted string ends with a backslash: {0!r}".format(s))
            l.append(s[i])
            i += 1

        if s[i] != '"':
            raise PythonDialogBug("quoted string does not and with a double "
                                  "quote: {0!r}".format(s))

        return (''.join(l), i+1)

    def _split_shellstyle_arglist(self, s):
        s = s.rstrip()
        l = []
        i = 0

        while i < len(s):
            if s[i] == '"':
                arg, i = self._parse_quoted_string(s, start=i)
                if i < len(s) and s[i] != ' ':
                    raise PythonDialogBug(
                        "expected a space or end-of-string after quoted "
                        "string in {0!r}, but found {1!r}".format(s, s[i]))
                i += 1
                l.append(arg)
            else:
                try:
                    end = s.index(' ', i)
                except ValueError:
                    end = len(s)

                l.append(s[i:end])
                i = end + 1

        return l

    def _parse_help(self, output, kwargs, *, multival=False,
                    multival_on_single_line=False, raw_format=False):
        l = output.splitlines()

        if raw_format:
            if len(l) > 1:
                raise PythonDialogBug("raw help feedback unexpected as "
                                      "multiline: {0!r}".format(output))
            elif len(l) == 0:
                return ""
            else:
                return l[0]

        if not l:
            return None

        if not l[0].startswith("HELP "):
            raise PythonDialogBug(
                "unexpected help output that does not start with 'HELP ': "
                "{0!r}".format(output))

        s = l[0][5:]

        if not self._help_status_on(kwargs):
            return s

        if multival:
            if multival_on_single_line:
                args = self._split_shellstyle_arglist(s)
                if not args:
                    raise PythonDialogBug(
                        "expected a non-empty space-separated list of "
                        "possibly-quoted strings in this help output: {0!r}"
                        .format(output))
                return (args[0], args[1:])
            else:
                return (s, l[1:])
        else:
            if not s:
                raise PythonDialogBug(
                    "unexpected help output whose first line is 'HELP '")
            elif s[0] != '"':
                l2 = s.split(' ', 1)
                if len(l2) == 1:
                    raise PythonDialogBug(
                        "expected 'HELP <id> <status>' in the help output, "
                        "but couldn't find any space after 'HELP '")
                else:
                    return tuple(l2)
            else:
                help_id, after_index = self._parse_quoted_string(s)
                if not s[after_index:].startswith(" "):
                    raise PythonDialogBug(
                        "expected 'HELP <quoted_id> <status>' in the help "
                        "output, but couldn't find any space after "
                        "'HELP <quoted_id>'")
                return (help_id, s[after_index+1:])

    def _widget_with_string_output(self, args, kwargs,
                                   strip_xdialog_newline=False,
                                   raw_help=False):
        code, output = self._perform(args, **kwargs)

        if strip_xdialog_newline:
            output = self._strip_xdialog_newline(output)

        if code == self.HELP:
            help_data = self._parse_help(output, kwargs, raw_format=raw_help)
            return (code, help_data)
        else:
            return (code, output)

    def _widget_with_no_output(self, widget_name, args, kwargs):
        code, output = self._perform(args, **kwargs)

        if output:
            raise PythonDialogBug(
                "expected an empty output from {0!r}, but got: {1!r}".format(
                    widget_name, output))

        return code

    def _dialog_version_check(self, version_string, feature):
        if self.compat == "dialog":
            minimum_version = DialogBackendVersion.fromstring(version_string)

            if self.cached_backend_version < minimum_version:
                raise InadequateBackendVersion(
                    "{0} requires dialog {1} or later, "
                    "but you seem to be using version {2}".format(
                        feature, minimum_version, self.cached_backend_version))

    def backend_version(self):
        code, output = self._perform(["--print-version"],
                                     use_persistent_args=False)

        if code == self.OK and not (output.strip() or self.use_stdout):
            self.use_stdout = True
            code, output = self._perform(["--stdout", "--print-version"],
                                         use_persistent_args=False,
                                         dash_escape="none")
            self.use_stdout = False

        if code == self.OK:
            try:
                mo = self._print_version_cre.match(output)
                if mo:
                    return mo.group("version")
                else:
                    raise UnableToRetrieveBackendVersion(
                        "unable to parse the output of '{0} --print-version': "
                        "{1!r}".format(self._dialog_prg, output))
            except re.error as e:
                raise PythonDialogReModuleError(str(e)) from e
        else:
            raise UnableToRetrieveBackendVersion(
                "exit code {0!r} from the backend".format(code))

    def maxsize(self, **kwargs):
        code, output = self._perform(["--print-maxsize"], **kwargs)
        if code == self.OK:
            try:
                mo = self._print_maxsize_cre.match(output)
                if mo:
                    return tuple(map(int, mo.group("rows", "columns")))
                else:
                    raise PythonDialogBug(
                        "Unable to parse the output of '{0} --print-maxsize': "
                        "{1!r}".format(self._dialog_prg, output))
            except re.error as e:
                raise PythonDialogReModuleError(str(e)) from e
        else:
            return None

    def _default_size(self, values, defaults):
        if self.autowidgetsize:
            defaults = (0,) * len(defaults)

        return [ v if v is not None else defaults[i]
                 for i, v in enumerate(values) ]

    @widget
    def buildlist(self, text, height=0, width=0, list_height=0, items=[],
                  **kwargs):
        self._dialog_version_check("1.2-20121230", "the buildlist widget")

        cmd = ["--buildlist", text, str(height), str(width), str(list_height)]
        for t in items:
            cmd.extend([ t[0], t[1], _to_onoff(t[2]) ] + list(t[3:]))

        code, output = self._perform(cmd, **kwargs)

        if code == self.HELP:
            help_data = self._parse_help(output, kwargs, multival=True,
                                         multival_on_single_line=True)
            if self._help_status_on(kwargs):
                help_id, selected_tags = help_data
                items = [ [ tag, item, tag in selected_tags ] + rest
                            for (tag, item, status, *rest) in items ]
                return (code, (help_id, selected_tags, items))
            else:
                return (code, help_data)
        elif code in (self.OK, self.EXTRA):
            return (code, self._split_shellstyle_arglist(output))
        else:
            return (code, None)

    def _calendar_parse_date(self, date_str):
        try:
            mo = _calendar_date_cre.match(date_str)
        except re.error as e:
            raise PythonDialogReModuleError(str(e)) from e

        if not mo:
            raise UnexpectedDialogOutput(
                "the dialog-like program returned the following "
                "unexpected output (a date string was expected) from the "
                "calendar box: {0!r}".format(date_str))

        return [ int(s) for s in mo.group("day", "month", "year") ]

    @widget
    def calendar(self, text, height=None, width=0, day=-1, month=-1, year=-1,
                 **kwargs):
        (height,) = self._default_size((height, ), (6,))
        (code, output) = self._perform(
            ["--calendar", text, str(height), str(width), str(day),
               str(month), str(year)],
            **kwargs)

        if code == self.HELP:
            help_data = self._parse_help(output, kwargs, raw_format=True)
            return (code, self._calendar_parse_date(help_data))
        elif code in (self.OK, self.EXTRA):
            return (code, self._calendar_parse_date(output))
        else:
            return (code, None)

    @widget
    def checklist(self, text, height=None, width=None, list_height=None,
                  choices=[], **kwargs):
        height, width, list_height = self._default_size(
            (height, width, list_height), (15, 54, 7))
        cmd = ["--checklist", text, str(height), str(width), str(list_height)]
        for t in choices:
            t = [ t[0], t[1], _to_onoff(t[2]) ] + list(t[3:])
            cmd.extend(t)

        kwargs["separate_output"] = True

        (code, output) = self._perform(cmd, **kwargs)

        if code == self.HELP:
            help_data = self._parse_help(output, kwargs, multival=True)
            if self._help_status_on(kwargs):
                help_id, selected_tags = help_data
                choices = [ [ tag, item, tag in selected_tags ] + rest
                            for (tag, item, status, *rest) in choices ]
                return (code, (help_id, selected_tags, choices))
            else:
                return (code, help_data)
        else:
            return (code, output.split('\n')[:-1])

    def _form_updated_items(self, status, elements):

        res = []
        for i, (label, yl, xl, item, yi, xi, field_length, *rest) \
                in enumerate(elements):
            res.append(status[i] if field_length > 0 else item)

        return res

    def _generic_form(self, widget_name, method_name, text, elements, height=0,
                      width=0, form_height=0, **kwargs):
        cmd = ["--%s" % widget_name, text, str(height), str(width),
               str(form_height)]

        if not elements:
            raise BadPythonDialogUsage(
                "{0}.{1}.{2}: empty ELEMENTS sequence: {3!r}".format(
                    __name__, type(self).__name__, method_name, elements))

        elt_len = len(elements[0])
        for i, elt in enumerate(elements):
            if len(elt) != elt_len:
                raise BadPythonDialogUsage(
                    "{0}.{1}.{2}: ELEMENTS[0] has length {3}, whereas "
                    "ELEMENTS[{4}] has length {5}".format(
                        __name__, type(self).__name__, method_name,
                        elt_len, i, len(elt)))
            if widget_name in ("form", "passwordform"):
                label, yl, xl, item, yi, xi, field_length, input_length = \
                    elt[:8]
                rest = elt[8:]
            elif widget_name == "mixedform":
                label, yl, xl, item, yi, xi, field_length, input_length, \
                    attributes = elt[:9]
                rest = elt[9:]
            else:
                raise PythonDialogBug(
                    "unexpected widget name in {0}.{1}._generic_form(): "
                    "{2!r}".format(__name__, type(self).__name__, widget_name))

            for name, value in (("label", label), ("item", item)):
                if not isinstance(value, str):
                    raise BadPythonDialogUsage(
                        "{0}.{1}.{2}: {3!r} element not a string: {4!r}".format(
                            __name__, type(self).__name__,
                            method_name, name, value))

            cmd.extend((label, str(yl), str(xl), item, str(yi), str(xi),
                        str(field_length), str(input_length)))
            if widget_name == "mixedform":
                cmd.append(str(attributes))

            cmd.extend(rest)

        (code, output) = self._perform(cmd, **kwargs)

        if code == self.HELP:
            help_data = self._parse_help(output, kwargs, multival=True)
            if self._help_status_on(kwargs):
                help_id, status = help_data
                updated_items = self._form_updated_items(status, elements)
                elements = [ [ label, yl, xl, updated_item ] + rest for
                             ((label, yl, xl, item, *rest), updated_item) in
                             zip(elements, updated_items) ]
                return (code, (help_id, status, elements))
            else:
                return (code, help_data)
        else:
            return (code, output.split('\n')[:-1])

    @widget
    def form(self, text, elements, height=0, width=0, form_height=0, **kwargs):
        return self._generic_form("form", "form", text, elements,
                                  height, width, form_height, **kwargs)

    @widget
    def passwordform(self, text, elements, height=0, width=0, form_height=0,
                     **kwargs):

        return self._generic_form("passwordform", "passwordform", text,
                                  elements, height, width, form_height,
                                  **kwargs)

    @widget
    def mixedform(self, text, elements, height=0, width=0, form_height=0,
                  **kwargs):
        return self._generic_form("mixedform", "mixedform", text, elements,
                                  height, width, form_height, **kwargs)

    @widget
    def dselect(self, filepath, height=0, width=0, **kwargs):
        return self._widget_with_string_output(
            ["--dselect", filepath, str(height), str(width)],
            kwargs, raw_help=True)

    @widget
    def editbox(self, filepath, height=0, width=0, **kwargs):
        return self._widget_with_string_output(
            ["--editbox", filepath, str(height), str(width)],
            kwargs)

    def editbox_str(self, init_contents, *args, **kwargs):

        if not init_contents.endswith('\n'):
            init_contents += '\n'

        with _OSErrorHandling():
            tmpfile = tempfile.NamedTemporaryFile(
                mode="w", prefix="pythondialog.tmp", delete=False)
            try:
                with tmpfile as f:
                    f.write(init_contents)
                res = self.editbox(tmpfile.name, *args, **kwargs)
            finally:
                if os.path.exists(tmpfile.name):
                    os.unlink(tmpfile.name)

        return res

    @widget
    def fselect(self, filepath, height=0, width=0, **kwargs):
        return self._widget_with_string_output(
            ["--fselect", filepath, str(height), str(width)],
            kwargs, strip_xdialog_newline=True, raw_help=True)

    def gauge_start(self, text="", height=None, width=None, percent=0,
                    **kwargs):
        height, width = self._default_size((height, width), (8, 54))
        with _OSErrorHandling():
            (child_stdin_rfd, child_stdin_wfd)  = os.pipe()

            child_pid, child_output_rfd, args_file = self._call_program(
                ["--gauge", text, str(height), str(width), str(percent)],
                redir_child_stdin_from_fd=child_stdin_rfd,
                close_fds=(child_stdin_wfd,), **kwargs)

            os.close(child_stdin_rfd)

            self._gauge_process = {
                "pid": child_pid,
                "stdin": os.fdopen(child_stdin_wfd, "w"),
                "child_output_rfd": child_output_rfd,
                "args_file": args_file
                }

    def gauge_update(self, percent, text="", update_text=False):
        if not isinstance(percent, int):
            raise BadPythonDialogUsage(
                "the 'percent' argument of gauge_update() must be an integer, "
                "but {0!r} is not".format(percent))

        if update_text:
            gauge_data = "XXX\n{0}\n{1}\nXXX\n".format(percent, text)
        else:
            gauge_data = "{0}\n".format(percent)
        with _OSErrorHandling():
            self._gauge_process["stdin"].write(gauge_data)
            self._gauge_process["stdin"].flush()

    def gauge_iterate(*args, **kwargs):

        warnings.warn("Dialog.gauge_iterate() has been obsolete for "
                      "many years", DeprecationWarning)
        gauge_update(*args, **kwargs)

    @widget
    @retval_is_code
    def gauge_stop(self):

        p = self._gauge_process
        with _OSErrorHandling():
            p["stdin"].close()
        exit_code = self._handle_program_exit(p["pid"],
                                              p["child_output_rfd"],
                                              p["args_file"])[0]
        return exit_code

    @widget
    @retval_is_code
    def infobox(self, text, height=None, width=None, **kwargs):
        height, width = self._default_size((height, width), (10, 30))
        return self._widget_with_no_output(
            "infobox",
            ["--infobox", text, str(height), str(width)],
            kwargs)

    @widget
    def inputbox(self, text, height=None, width=None, init='', **kwargs):
        height, width = self._default_size((height, width), (10, 30))
        return self._widget_with_string_output(
            ["--inputbox", text, str(height), str(width), init],
            kwargs, strip_xdialog_newline=True, raw_help=True)

    @widget
    def inputmenu(self, text, height=0, width=None, menu_height=None,
                  choices=[], **kwargs):
        width, menu_height = self._default_size((width, menu_height), (60, 7))
        cmd = ["--inputmenu", text, str(height), str(width), str(menu_height)]
        for t in choices:
            cmd.extend(t)
        (code, output) = self._perform(cmd, **kwargs)

        if code == self.HELP:
            help_id = self._parse_help(output, kwargs)
            return (code, help_id, None)
        elif code == self.OK:
            return ("accepted", output, None)
        elif code == self.EXTRA:
            if not output.startswith("RENAMED "):
                raise PythonDialogBug(
                    "'output' does not start with 'RENAMED ': {0!r}".format(
                        output))
            t = output.split(' ', 2)
            return ("renamed", t[1], t[2])
        else:
            return (code, None, None)

    @widget
    def menu(self, text, height=None, width=None, menu_height=None, choices=[],
             **kwargs):
        height, width, menu_height = self._default_size(
            (height, width, menu_height), (15, 54, 7))
        cmd = ["--menu", text, str(height), str(width), str(menu_height)]
        for t in choices:
            cmd.extend(t)

        return self._widget_with_string_output(
            cmd, kwargs, strip_xdialog_newline=True)

    @widget
    @retval_is_code
    def mixedgauge(self, text, height=0, width=0, percent=0, elements=[],
             **kwargs):
        cmd = ["--mixedgauge", text, str(height), str(width), str(percent)]
        for t in elements:
            cmd.extend( (t[0], str(t[1])) )
        return self._widget_with_no_output("mixedgauge", cmd, kwargs)

    @widget
    @retval_is_code
    def msgbox(self, text, height=None, width=None, **kwargs):
        height, width = self._default_size((height, width), (10, 30))
        return self._widget_with_no_output(
            "msgbox",
            ["--msgbox", text, str(height), str(width)],
            kwargs)

    @widget
    @retval_is_code
    def pause(self, text, height=None, width=None, seconds=5, **kwargs):
        height, width = self._default_size((height, width), (15, 60))
        return self._widget_with_no_output(
            "pause",
            ["--pause", text, str(height), str(width), str(seconds)],
            kwargs)

    @widget
    def passwordbox(self, text, height=None, width=None, init='', **kwargs):
        height, width = self._default_size((height, width), (10, 60))
        return self._widget_with_string_output(
            ["--passwordbox", text, str(height), str(width), init],
            kwargs, strip_xdialog_newline=True, raw_help=True)

    def _progressboxoid(self, widget, file_path=None, file_flags=os.O_RDONLY,
                        fd=None, text=None, height=20, width=78, **kwargs):
        if (file_path is None and fd is None) or \
                (file_path is not None and fd is not None):
            raise BadPythonDialogUsage(
                "{0}.{1}.{2}: either 'file_path' or 'fd' must be provided, and "
                "not both at the same time".format(
                    __name__, self.__class__.__name__, widget))

        with _OSErrorHandling():
            if file_path is not None:
                if fd is not None:
                    raise PythonDialogBug(
                        "unexpected non-None value for 'fd': {0!r}".format(fd))
                fd = os.open(file_path, file_flags)

            try:
                args = [ "--{0}".format(widget) ]
                if text is not None:
                    args.append(text)
                args.extend([str(height), str(width)])

                kwargs["redir_child_stdin_from_fd"] = fd
                code = self._widget_with_no_output(widget, args, kwargs)
            finally:
                with _OSErrorHandling():
                    if file_path is not None:
                        os.close(fd)

        return code

    @widget
    @retval_is_code
    def progressbox(self, file_path=None, file_flags=os.O_RDONLY,
                    fd=None, text=None, height=None, width=None, **kwargs):
        height, width = self._default_size((height, width), (20, 78))
        return self._progressboxoid(
            "progressbox", file_path=file_path, file_flags=file_flags,
            fd=fd, text=text, height=height, width=width, **kwargs)

    @widget
    @retval_is_code
    def programbox(self, file_path=None, file_flags=os.O_RDONLY,
                   fd=None, text=None, height=None, width=None, **kwargs):
        self._dialog_version_check("1.1-20110302", "the programbox widget")

        height, width = self._default_size((height, width), (20, 78))
        return self._progressboxoid(
            "programbox", file_path=file_path, file_flags=file_flags,
            fd=fd, text=text, height=height, width=width, **kwargs)

    @widget
    def radiolist(self, text, height=None, width=None, list_height=None,
                  choices=[], **kwargs):
        height, width, list_height = self._default_size(
            (height, width, list_height), (15, 54, 7))

        cmd = ["--radiolist", text, str(height), str(width), str(list_height)]
        for t in choices:
            cmd.extend([ t[0], t[1], _to_onoff(t[2]) ] + list(t[3:]))
        (code, output) = self._perform(cmd, **kwargs)

        output = self._strip_xdialog_newline(output)

        if code == self.HELP:
            help_data = self._parse_help(output, kwargs)
            if self._help_status_on(kwargs):
                help_id, selected_tag = help_data
                choices = [ [ tag, item, tag == selected_tag ] + rest for
                            (tag, item, status, *rest) in choices ]
                return (code, (help_id, selected_tag, choices))
            else:
                return (code, help_data)
        else:
            return (code, output)

    @widget
    def rangebox(self, text, height=0, width=0, min=None, max=None, init=None,
                 **kwargs):
        self._dialog_version_check("1.2-20121230", "the rangebox widget")

        for name in ("min", "max", "init"):
            if not isinstance(locals()[name], int):
                raise BadPythonDialogUsage(
                    "{0!r} argument not an int: {1!r}".format(name,
                                                              locals()[name]))
        (code, output) = self._perform(
            ["--rangebox", text] + [ str(i) for i in
                                     (height, width, min, max, init) ],
            **kwargs)

        if code == self.HELP:
            help_data = self._parse_help(output, kwargs, raw_format=True)
            return (code, int(help_data))
        elif code in (self.OK, self.EXTRA):
            return (code, int(output))
        else:
            return (code, None)

    @widget
    @retval_is_code
    def scrollbox(self, text, height=None, width=None, **kwargs):
        height, width = self._default_size((height, width), (20, 78))

        with _OSErrorHandling():
            tmpfile = tempfile.NamedTemporaryFile(
                mode="w", prefix="pythondialog.tmp", delete=False)
            try:
                with tmpfile as f:
                    f.write(text)
                if kwargs.get("title", None) is None:
                    kwargs["title"] = ""

                return self._widget_with_no_output(
                    "textbox",
                    ["--textbox", tmpfile.name, str(height), str(width)],
                    kwargs)
            finally:
                if os.path.exists(tmpfile.name):
                    os.unlink(tmpfile.name)

    @widget
    @retval_is_code
    def tailbox(self, filepath, height=None, width=None, **kwargs):
        height, width = self._default_size((height, width), (20, 60))
        return self._widget_with_no_output(
            "tailbox",
            ["--tailbox", filepath, str(height), str(width)],
            kwargs)

    @widget
    @retval_is_code
    def textbox(self, filepath, height=None, width=None, **kwargs):
        height, width = self._default_size((height, width), (20, 60))
        if kwargs.get("title", None) is None:
            kwargs["title"] = filepath

        return self._widget_with_no_output(
            "textbox",
            ["--textbox", filepath, str(height), str(width)],
            kwargs)

    def _timebox_parse_time(self, time_str):
        try:
            mo = _timebox_time_cre.match(time_str)
        except re.error as e:
            raise PythonDialogReModuleError(str(e)) from e

        if not mo:
            raise UnexpectedDialogOutput(
                "the dialog-like program returned the following "
                "unexpected output (a time string was expected) with the "
                "--timebox option: {0!r}".format(time_str))

        return [ int(s) for s in mo.group("hour", "minute", "second") ]

    @widget
    def timebox(self, text, height=None, width=None, hour=-1, minute=-1,
                second=-1, **kwargs):
        height, width = self._default_size((height, width), (3, 30))
        (code, output) = self._perform(
            ["--timebox", text, str(height), str(width),
               str(hour), str(minute), str(second)],
            **kwargs)

        if code == self.HELP:
            help_data = self._parse_help(output, kwargs, raw_format=True)
            return (code, self._timebox_parse_time(help_data))
        elif code in (self.OK, self.EXTRA):
            return (code, self._timebox_parse_time(output))
        else:
            return (code, None)

    @widget
    def treeview(self, text, height=0, width=0, list_height=0,
                 nodes=[], **kwargs):
        self._dialog_version_check("1.2-20121230", "the treeview widget")
        cmd = ["--treeview", text, str(height), str(width), str(list_height)]

        nselected = 0
        for i, t in enumerate(nodes):
            if not isinstance(t[3], int):
                raise BadPythonDialogUsage(
                    "fourth element of node {0} not an int: {1!r}".format(
                        i, t[3]))

            status = _to_onoff(t[2])
            if status == "on":
                nselected += 1

            cmd.extend([ t[0], t[1], status, str(t[3]) ] + list(t[4:]))

        if nselected != 1:
            raise BadPythonDialogUsage(
                "exactly one node must be selected, not {0}".format(nselected))

        (code, output) = self._perform(cmd, **kwargs)

        if code == self.HELP:
            help_data = self._parse_help(output, kwargs)
            if self._help_status_on(kwargs):
                help_id, selected_tag = help_data
                nodes = [ [ tag, item, tag == selected_tag ] + rest for
                          (tag, item, status, *rest) in nodes ]
                return (code, (help_id, selected_tag, nodes))
            else:
                return (code, help_data)
        elif code in (self.OK, self.EXTRA):
            return (code, output)
        else:
            return (code, None)

    @widget
    @retval_is_code
    def yesno(self, text, height=None, width=None, **kwargs):

        height, width = self._default_size((height, width), (10, 30))
        return self._widget_with_no_output(
            "yesno",
            ["--yesno", text, str(height), str(width)],
            kwargs)
