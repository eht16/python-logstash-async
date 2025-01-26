# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

import sys
import traceback
from copy import deepcopy
from datetime import datetime, UTC
from importlib import import_module
from itertools import chain, islice


# ----------------------------------------------------------------------
def ichunked(seq, chunksize):
    """Yields items from an iterator in iterable chunks.
       https://stackoverflow.com/a/8998040
    """
    iterable = iter(seq)
    while True:
        chunk_iterable = islice(iterable, chunksize)
        try:
            element = next(chunk_iterable)
        except StopIteration:
            return
        yield list(chain((element,), chunk_iterable))


# ----------------------------------------------------------------------
def safe_log_via_print(log_level, message, *args, **kwargs):
    timestamp = datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M:%S')
    log_message = f'{timestamp}: {log_level}: {message}'
    print(log_message % args, file=sys.stderr)  # noqa: T201
    # print stack trace if available
    exc_info = kwargs.get('exc_info')
    if exc_info or log_level == 'exception':
        if not isinstance(exc_info, tuple):
            exc_info = sys.exc_info()
            stack_trace = ''.join(traceback.format_exception(*exc_info))
            print(stack_trace, file=sys.stderr)  # noqa: T201


# ----------------------------------------------------------------------
def import_string(dotted_path):
    """
    Import a dotted module path and return the attribute/class designated by the
    last name in the path. Raise ImportError if the import failed.

    (stolen from Django)
    """
    try:
        module_path, class_name = dotted_path.rsplit('.', 1)
    except ValueError as exc:
        error_message = f'{dotted_path} does not look like a module path'
        raise ImportError(error_message) from exc

    module = import_module(module_path)
    try:
        return getattr(module, class_name)
    except AttributeError as exc:
        error_message = f'Module "{module_path}" does not define a "{class_name}" attribute/class'
        raise ImportError(error_message) from exc


# ----------------------------------------------------------------------
# pylint: disable-next=invalid-name
class normalize_ecs_dict:  # noqa: N801
    """
    Convert dotted ecs fields into nested objects.
    """

    def __new__(cls, ecs_dict):
        new_dict = deepcopy(ecs_dict)
        cls.normalize_dict(new_dict)
        return new_dict

    @classmethod
    def normalize_dict(cls, ecs_dict):
        for key in list(ecs_dict):
            if '.' in key:
                cls.merge_dicts(ecs_dict, cls.de_dot_record(key, ecs_dict.pop(key)))
        for val in ecs_dict.values():
            cls.normalize_value(val)

    @classmethod
    def normalize_sequence(cls, ecs_sequence):
        for val in ecs_sequence:
            cls.normalize_value(val)

    @classmethod
    def normalize_value(cls, ecs_value):
        if isinstance(ecs_value, dict):
            cls.normalize_dict(ecs_value)
        if isinstance(ecs_value, (list, tuple, set)):
            cls.normalize_sequence(ecs_value)

    @classmethod
    def merge_dicts(cls, target, src):
        """
        Merge dicts recursively.
        Mutates `target`.
        Uses references from `src` which may lead to `src` mutation.
        """
        for key, src_value in src.items():
            if key in target:
                target_value = target[key]
                if isinstance(target_value, dict) and isinstance(src_value, dict):
                    cls.merge_dicts(target_value, src_value)
                else:
                    target[key] = src_value
            else:
                target[key] = src_value

    @classmethod
    def de_dot_record(cls, key, value):
        keys = key.split('.')
        res = {keys.pop(): value}
        for k in reversed(keys):
            res = {k: res}
        return res
