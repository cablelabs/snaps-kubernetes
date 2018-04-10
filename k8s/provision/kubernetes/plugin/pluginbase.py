
import abc

import six


@six.add_metaclass(abc.ABCMeta)
class PluginBase(object):
    """Base class for example plugin .
    """

    @abc.abstractmethod
    def execute(self, data):
        """iExecute would be implemented differently for each of the given plugin.

        :param data: A dictionary with string keys and simple types as
                     values.
        :type data: dict(str:?)
        :returns: boolean.

       """
