# -*- coding: utf-8 -*-
#
# This software may be modified and distributed under the terms
# of the MIT license.  See the LICENSE file for details.

from __future__ import print_function

from datetime import datetime
from importlib import import_module
from itertools import chain, islice
import sys
import traceback

import six


# ----------------------------------------------------------------------
def ichunked(seq, chunksize):
    """Yields items from an iterator in iterable chunks.
       http://stackoverflow.com/a/1335572
    """
    iterable = iter(seq)
    while True:
        yield list(chain([next(iterable)], islice(iterable, chunksize - 1)))


# ----------------------------------------------------------------------
def safe_log_via_print(log_level, message, *args, **kwargs):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = u'{}: {}: {}'.format(timestamp, log_level, message)
    print(log_message % args, file=sys.stderr)
    # print stack trace if available
    exc_info = kwargs.get('exc_info', None)
    if exc_info or log_level == 'exception':
        if not isinstance(exc_info, tuple):
            exc_info = sys.exc_info()
            stack_trace = ''.join(traceback.format_exception(*exc_info))
            print(stack_trace, file=sys.stderr)


# ----------------------------------------------------------------------
def import_string(dotted_path):
    """
    Import a dotted module path and return the attribute/class designated by the
    last name in the path. Raise ImportError if the import failed.

    (stolen from Django)
    """
    try:
        module_path, class_name = dotted_path.rsplit('.', 1)
    except ValueError:
        msg = "{} doesn't look like a module path".format(dotted_path)
        six.reraise(ImportError, ImportError(msg), sys.exc_info()[2])

    module = import_module(module_path)
    try:
        return getattr(module, class_name)
    except AttributeError:
        msg = 'Module "{}" does not define a "{}" attribute/class'.format(module_path, class_name)
        six.reraise(ImportError, ImportError(msg), sys.exc_info()[2])
